// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// defaultCRLRefresh is how often sources are reloaded unless a
	// CRL's lifetime calls for sooner.
	defaultCRLRefresh = time.Hour

	// minCRLRefresh bounds how fast a short CRL lifetime can make us poll.
	minCRLRefresh = time.Second

	// a CRL is refetched after crlRefreshAfter/crlRefreshOf of its lifetime
	crlRefreshAfter = 3
	crlRefreshOf    = 5

	// waits over a minute are shortened by 1/crlHeadroomDivisor so a
	// reload lands before the deadline it was timed to
	crlHeadroomDivisor = 10
)

// crlRetryOnFailure is how soon to retry after a source fails, and the
// floor on how often anything is refetched. A var so tests can shorten it.
var crlRetryOnFailure = 5 * time.Minute

// loop reloads the sources until the module's context is canceled.
func (v *CRLVerifier) loop(next time.Duration) {
	defer v.wg.Done()
	timer := time.NewTimer(next)
	defer timer.Stop()
	for {
		select {
		case <-v.reloadCtx.Done():
			return
		case <-timer.C:
			var wait time.Duration
			var err error
			// a panic must not end the loop, or the module would serve
			// an ever-staler CRL while appearing to work
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						v.logger.Error("recovered from a panic while reloading CRLs",
							zap.Any("panic", rec),
							zap.Stack("stack"),
						)
						wait = boundedRefresh(crlRetryOnFailure)
					}
				}()
				wait, err = v.reload(false)
			}()
			if err != nil {
				v.logger.Error("every configured CRL source reported a problem during this refresh",
					zap.Error(err),
					zap.Strings("still_loaded", v.current().issuerNames()))
			}
			timer.Reset(wait)
		}
	}
}

// reload loads every source, atomically replaces the loaded set, and
// returns how long to wait before the next reload. A source that fails
// keeps the CRLs it last served. The error means every source reported a
// problem, not that nothing is loaded. With provision set, any failing
// source is a config error.
func (v *CRLVerifier) reload(provision bool) (time.Duration, error) {
	next := defaultCRLRefresh

	// fetch concurrently and outside the lock; this is on the critical
	// path of a config load
	results := make([]sourceResult, len(v.sources))
	var wg sync.WaitGroup
	for i, src := range v.sources {
		wg.Go(func() {
			crls, refused, err := src.load(v.reloadCtx, v.client)
			results[i] = sourceResult{crls: crls, refused: refused, err: err}
		})
	}
	wg.Wait()

	if v.reloadCtx.Err() != nil {
		// torn down; don't log failures of a config being replaced
		return minCRLRefresh, nil
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	var loaded []*parsedCRL
	// one entry per failing source, in source order
	var failures []sourceFailure

	// the same failures as errors, for the joined report
	var causes []error

	for i, res := range results {
		v.logRefused(v.sources[i], res.refused)

		crls := res.crls
		if res.err != nil {
			source := v.sources[i]
			failures = append(failures, sourceFailure{location: source.key(), detail: res.err.Error()})
			causes = append(causes, fmt.Errorf("%s: %w", source.display(), res.err))
			loaded = append(loaded, v.lastGood[source.key()]...)
			continue
		}

		// a CRL whose cRLNumber went backwards is refused and this
		// source's earlier copy stands in for it
		fresh, behind := v.regressed(v.sources[i].key(), crls)
		if len(behind) > 0 {
			kept := append(fresh, superseded(v.lastGood[v.sources[i].key()], behind)...)
			crls = distinctLists(kept)
			names, uncovered := regressedNames(behind, crls)
			message := fmt.Sprintf("a CRL for %s is older than one this source served before, so using it could undo revocations published since; refusing it (restarting Caddy starts from scratch, if rolling a CRL back is intended)", strings.Join(names, ", "))
			if len(uncovered) > 0 {
				message += fmt.Sprintf("; no earlier list from this source covers %s, so unless another source does their certificates are refused until this one serves a list at or above the highest number it has accepted for them, or one which carries no number at all", strings.Join(uncovered, ", "))
			}
			failures = append(failures, sourceFailure{location: v.sources[i].key(), kind: message})
			causes = append(causes, fmt.Errorf("%s: %w", v.sources[i].display(), errors.New(message)))
		}
		v.lastGood[v.sources[i].key()] = crls
		loaded = append(loaded, crls...)
		now := v.now()
		for _, crl := range crls {
			if wait := crl.refreshDelay(now, next); wait < next {
				next = wait
			}
		}
	}
	if !provision {
		// at provision the returned error is the report
		v.logFailures(failures)
	}

	if len(failures) > 0 {
		next = min(next, crlRetryOnFailure)
	}

	if provision && len(failures) > 0 {
		// refuse the config rather than run on a subset of the sources,
		// which would look exactly like a working deployment
		return boundedRefresh(next), fmt.Errorf("could not load %d of the %d configured CRL source(s): %w",
			len(failures), len(v.sources), errors.Join(causes...))
	}

	set := buildCRLSet(loaded)
	if set == nil && provision {
		return boundedRefresh(next), errors.New("no CRL source could be loaded")
	}
	if set == nil {
		// every source was refused with nothing to fall back on; an
		// empty set refuses every certificate as uncovered, whereas
		// keeping the old snapshot would admit on stale data
		set = &crlSet{byIssuer: make(map[string][]*parsedCRL)}
	}
	summary := set.summary()
	changed := summary != v.summary
	v.summary = summary
	previous := v.snapshot.Swap(set)

	// info only when something changed, so hourly reloads stay quiet
	level := zap.DebugLevel
	if previous == nil || changed {
		level = zap.InfoLevel
	}
	if len(set.byIssuer) == 0 {
		// logged on the transition into this state; the first set
		// installed is never empty, so previous is always set
		if previous != nil && len(previous.byIssuer) > 0 {
			v.logger.Error("no CRL is in service",
				zap.String("note", "every certificate whose issuer needs a CRL is refused as uncovered until a source contributes one"))
		}
	} else if level == zap.InfoLevel {
		for _, crls := range set.newest() {
			fields := []zap.Field{
				zap.String("issuer", crls[0].issuerName),
				zap.Int("crls", len(crls)),
				zap.Int("revoked", len(crls[0].revoked)),
				zap.String("crl_number", crls[0].numberText()),
				zap.Time("this_update", crls[0].thisUpdate),
			}
			if !crls[0].nextUpdate.IsZero() {
				fields = append(fields, zap.Time("next_update", crls[0].nextUpdate))
			}
			v.logger.Info("loaded CRLs", fields...)
		}
	}

	if len(failures) == len(v.sources) {
		return boundedRefresh(next), fmt.Errorf("every configured CRL source reported a problem this time: %w",
			errors.Join(causes...))
	}
	return boundedRefresh(next), nil
}

// sourceResult is what one source produced during a reload.
type sourceResult struct {
	crls []*parsedCRL

	// CRLs this source holds which the module will not read; not a
	// failure, but whatever only they covered is now uncovered
	refused []string
	err     error
}

// logFailures logs the sources failing this cycle, but only when the set
// of failing sources or their kind changed, so a source that stays down
// is reported once. Reason text is not compared because it may contain
// ephemeral detail such as a port number. The caller must hold v.mu.
func (v *CRLVerifier) logFailures(failures []sourceFailure) {
	if slices.EqualFunc(failures, v.failing, sourceFailure.sameCondition) {
		return
	}
	v.failing = failures
	if len(failures) == 0 {
		v.logger.Info("all CRL sources are loading again")
		return
	}

	for _, failure := range failures {
		v.logger.Error("a CRL source reported a problem",
			zap.String("source", redactURL(failure.location)),
			zap.String("reason", failure.reason()),
			zap.String("note", "this is logged again when a source starts or stops failing, or starts failing in a new way"),
		)
	}
}

// sourceFailure is one problem one source reported this cycle.
type sourceFailure struct {
	location string // the configured source, as key() names it
	kind     string // a diagnosis made by this module, if any
	detail   string // the source's own error text; not compared
}

// sameCondition reports whether two failures are the same news.
func (f sourceFailure) sameCondition(other sourceFailure) bool {
	return f.location == other.location && f.kind == other.kind
}

// reason is the text an operator reads.
func (f sourceFailure) reason() string {
	if f.kind != "" {
		return f.kind
	}
	return f.detail
}

// logRefused reports, once per distinct answer, the CRLs a source holds
// which this module will not read.
func (v *CRLVerifier) logRefused(src crlSource, refused []string) {
	if len(refused) == 0 {
		return
	}
	// same refusals in another order are the same condition
	slices.Sort(refused)
	level, ok := v.logOnceLevel(logKey{kind: logRefusedSource, who: src.key(), detail: strings.Join(refused, ", ")}, zap.ErrorLevel)
	if !ok {
		return
	}
	v.logger.Log(level, "a configured CRL source holds lists this module will not read",
		zap.String("source", src.display()),
		zap.Strings("refused", refused),
		zap.String("note", "the other lists from that source are loaded; certificates which only a refused list covered are refused as uncovered"),
	)
}

// regressed splits freshly loaded CRLs into those that may be used and
// those whose cRLNumber is lower than one this source already served for
// the same issuer and signing key, which would undo revocations published
// since. Marks are per source because two distribution points of one CA
// may legitimately hold different partitions, and per signing key because
// a re-keyed CA restarts its numbering. A CRL without a cRLNumber is kept
// without comparison. The signature check still stands between any CRL
// and an admission, so a forged high number can only cause refusals.
//
// A CRL this source already served is exempt from the comparison when
// the same batch also carries a higher CRL for that issuer which is at
// or above the marks. This keeps an overlap survivable: a publisher whose
// clock runs ahead leaves the older CRL beside a newer one that is not
// yet valid, and the older one must keep answering until it is. If the
// batch's own top is behind the marks, the batch went backwards as a
// whole and all of it is refused.
//
// A refused CRL is not remembered as served, so the refusal is reported
// for as long as the source keeps serving it. The caller must hold v.mu.
func (v *CRLVerifier) regressed(location string, fresh []*parsedCRL) (keep, behind []*parsedCRL) {
	served := make(map[[sha256.Size]byte]bool, len(v.lastGood[location]))
	for _, prev := range v.lastGood[location] {
		served[prev.contentDigest()] = true
	}

	for _, crl := range fresh {
		if crl.number == nil {
			keep = append(keep, crl)
			continue
		}
		key := sourceIssuer{location: location, issuerKey: crl.issuerKey}
		aki := crl.akiKey()
		marks := v.maxNumber[key]
		if marks.behind(aki, crl.number) {
			top := batchTop(fresh, crl.issuerKey, aki)
			if !served[crl.contentDigest()] || marks.behind(top.akiKey(), top.number) {
				behind = append(behind, crl)
				continue
			}
		}
		keep = append(keep, crl)
	}
	for _, crl := range keep {
		if crl.number == nil {
			continue
		}
		key := sourceIssuer{location: location, issuerKey: crl.issuerKey}
		v.maxNumber[key] = v.maxNumber[key].raised(crl.akiKey(), crl.number)
	}
	return keep, behind
}

// crlNumberMark is the highest cRLNumber one source has served for one
// issuer under one signing key. An empty aki means the CRL did not say
// which key signed it.
type crlNumberMark struct {
	aki    string
	number *big.Int
}

// sourceIssuer is one issuer at one configured source.
type sourceIssuer struct {
	location  string // the source, as key() names it
	issuerKey string // the issuer's RawSubject bytes
}

// crlNumberMarks are the marks of one issuer at one source, one per
// signing key seen.
type crlNumberMarks []crlNumberMark

// behind reports whether number is lower than a mark for a comparable
// signing key. A missing key id on either side is unknown, not different,
// so a CA that starts or stops publishing its key id cannot slip a
// rollback through.
func (m crlNumberMarks) behind(aki string, number *big.Int) bool {
	for _, mark := range m {
		if aki != "" && mark.aki != "" && aki != mark.aki {
			continue
		}
		if compareNumbers(number, mark.number) < 0 {
			return true
		}
	}
	return false
}

// batchTop returns the highest-numbered CRL for issuerKey in fresh whose
// signing key is comparable with aki. It may be the CRL being examined,
// so a numbered CRL never gets nil back.
func batchTop(fresh []*parsedCRL, issuerKey, aki string) *parsedCRL {
	var top *parsedCRL
	for _, other := range fresh {
		if other.number == nil || other.issuerKey != issuerKey {
			continue
		}
		if otherAKI := other.akiKey(); aki != "" && otherAKI != "" && aki != otherAKI {
			continue
		}
		if top == nil || compareNumbers(other.number, top.number) > 0 {
			top = other
		}
	}
	return top
}

// raised returns the marks with aki's mark moved up to number. A mark
// only ever moves up.
func (m crlNumberMarks) raised(aki string, number *big.Int) crlNumberMarks {
	for i, mark := range m {
		if mark.aki == aki {
			if compareNumbers(number, mark.number) > 0 {
				m[i].number = number
			}
			return m
		}
	}
	return append(m, crlNumberMark{aki: aki, number: number})
}

// superseded returns the previously loaded CRLs which stand in for the
// ones just refused as regressed: same issuer, a higher number, and the
// same signing key where both say which one they carry.
func superseded(previous, behind []*parsedCRL) []*parsedCRL {
	var out []*parsedCRL
	for _, old := range previous {
		for _, refused := range behind {
			if old.issuerKey != refused.issuerKey || compareNumbers(old.number, refused.number) <= 0 {
				continue
			}
			if oldAKI, refusedAKI := old.akiKey(), refused.akiKey(); oldAKI != "" && refusedAKI != "" && oldAKI != refusedAKI {
				continue
			}
			out = append(out, old)
			break
		}
	}
	return out
}

// regressedNames returns the issuers with a refused CRL, and the subset
// left with no CRL at all from this source.
func regressedNames(behind, kept []*parsedCRL) (names, uncovered []string) {
	covered := make(map[string]bool, len(kept))
	for _, crl := range kept {
		covered[crl.issuerKey] = true
	}
	seen := make(map[string]bool, len(behind))
	for _, crl := range behind {
		if seen[crl.issuerKey] {
			continue
		}
		seen[crl.issuerKey] = true
		names = append(names, crl.issuerName)
		if !covered[crl.issuerKey] {
			uncovered = append(uncovered, crl.issuerName)
		}
	}
	slices.Sort(names)
	slices.Sort(uncovered)
	return names, uncovered
}

// boundedRefresh clamps a wait to [minCRLRefresh, defaultCRLRefresh] and
// takes some headroom off anything over a minute.
func boundedRefresh(d time.Duration) time.Duration {
	d = max(min(d, defaultCRLRefresh), minCRLRefresh)
	if d <= time.Minute {
		return d
	}
	return d - d/crlHeadroomDivisor
}

// refreshDelay returns how long this CRL may be left before it is fetched
// again, measured from now and bounded above by bound.
func (c *parsedCRL) refreshDelay(now time.Time, bound time.Duration) time.Duration {
	if c.nextUpdate.IsZero() || c.thisUpdate.IsZero() {
		return bound
	}
	lifetime := c.nextUpdate.Sub(c.thisUpdate)
	if lifetime <= 0 {
		// a CRL that expires no later than it starts has no usable lifetime
		return min(crlRetryOnFailure, bound)
	}
	due := c.thisUpdate.Add(time.Duration(float64(lifetime) * crlRefreshAfter / crlRefreshOf))
	// past due, the publisher is behind; polling faster won't help
	wait := max(due.Sub(now), crlRetryOnFailure)
	return min(wait, bound)
}
