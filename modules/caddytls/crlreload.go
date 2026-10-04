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
	// defaultCRLRefresh is how often every source is fetched when no CRL asks to be refetched
	// sooner. A list whose own lifetime is shorter than this pulls the next reload forward; nothing
	// pushes it later than here except a source which has to be tried again sooner (see below).
	defaultCRLRefresh = time.Hour

	// minCRLRefresh bounds how aggressively a short CRL lifetime can make us poll.
	minCRLRefresh = time.Second
)

// crlRetryOnFailure is how soon to try again when a source could not be used, so that a
// distribution point which was briefly unreachable does not have to wait out a whole refresh
// interval to be believed again. It is also the floor on how often any one source is fetched,
// whatever its stated lifetime says. A var only so a test can watch the reload loop come back
// without waiting five minutes for it; nothing configures it.
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
			// A panic during a reload must not end the loop: a verifier which stops refreshing
			// serves an ever more stale CRL while appearing to work, which is the very failure
			// this module exists to prevent. The loaded set is left as it is.
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
				// Every source reported a problem this cycle and the error names each one with its
				// reason. What could be used was loaded and what could not keeps whatever this
				// source served before; where nothing at all could be used, the set was emptied
				// rather than left standing (see reload). Whether anything is still answering for an
				// issuer is the difference between a distribution point being briefly unreachable
				// and revocation checking having gone away, and this is the line printed on every
				// retry — so it names what is still loaded, which is nothing when the set is empty.
				// A list which is loaded and past its nextUpdate is named here and still refuses
				// every client under it; the per-certificate line above is what says that. Keep trying
				// sooner than the normal schedule.
				v.logger.Error("every configured CRL source reported a problem during this refresh",
					zap.Error(err),
					zap.Strings("still_loaded", v.current().issuerNames()))
			}
			timer.Reset(wait)
		}
	}
}

// reload reloads every source and atomically replaces the loaded set, returning how long to wait
// before doing it again. While running, it fails when every source reported a problem this pass —
// it did not answer, or what it answered was refused. That is not the same as nothing being
// loaded: a source whose list was refused beside others it kept has both reported a problem and
// been used. A source which cannot be used keeps whatever was last obtained from it, so that a
// distribution point being down cannot open the door by discarding the revocations which are
// already known; the set is emptied only when no source contributes anything at all. When
// provision is true this is the load done for a config load, where any source which cannot be used
// is a configuration error rather than a condition to keep running under.
func (v *CRLVerifier) reload(provision bool) (time.Duration, error) {
	// The default ceiling on how long to go without refetching; a CRL whose own lifetime is
	// shorter pulls the next reload forward (see refreshDelay).
	next := defaultCRLRefresh

	// The sources are fetched concurrently and outside the lock: a configuration with several
	// distribution points should not pay the sum of their latencies on every reload, since this is
	// on the critical path of a config load. Each fetch is bounded by the module's context and by
	// the per-URL timeout, so the wait here is bounded too.
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
		// The module is being torn down, so this reload is not happening. Reporting the fetches
		// that cancellation interrupted would put failures in the log of a config which is about
		// to be replaced.
		return minCRLRefresh, nil
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	var loaded []*parsedCRL
	// Keyed by position in results rather than by location: two configured sources may name one
	// file, and a count of problems which silently collapsed the two into one entry would leave the
	// count short of the number of sources — so a cycle in which every source failed would report
	// none of them as having failed.
	failures := make(map[int]string)
	kinds := make(map[int]string)
	for i, res := range results {
		v.logRefused(v.sources[i], res.refused)

		crls := res.crls
		if res.err != nil {
			failures[i] = res.err.Error()
			loaded = append(loaded, v.lastGood[v.sources[i].location]...)
			continue
		}

		// A list whose cRLNumber went backwards is refused on its own, and only the copy this same
		// source loaded before takes its place: a bundle covering two CAs must not lose one of
		// them because the other regressed, and another source's list for that issuer is a
		// different distribution point's word about its own scope.
		fresh, behind := v.regressed(v.sources[i].location, crls)
		if len(behind) > 0 {
			// What this source speaks with afterwards: the lists it may keep plus whatever stands in
			// for the ones it lost. The report is written about that set, because whether an issuer is
			// left uncovered is a question about what remains rather than about what was refused.
			kept := append(fresh, superseded(v.lastGood[v.sources[i].location], behind)...)
			crls = distinctLists(kept)
			// The issuers named in the report, each once however many lists were refused for it, and
			// separately those left with nothing at all from this source: a bundle covering two CAs can
			// regress one while an earlier copy stands in for it and leave the other uncovered, which is
			// worth saying out loud — it is the difference between a rollback being visible and it
			// looking like a problem with the trust pool.
			names, uncovered := regressedNames(behind, crls)
			// "a CRL for X, Y" rather than "the CRL for X, Y": several issuers may each have one of
			// their own lists refused, and a definite article would imply a single shared document.
			message := fmt.Sprintf("a CRL for %s is older than one this source served before, so using it could undo revocations published since; refusing it (restarting Caddy starts from scratch, if rolling a CRL back is intended)", strings.Join(names, ", "))
			if len(uncovered) > 0 {
				// Another source may still cover them; if none does, their certificates are refused as
				// uncovered from here. A list with no number ends it too, since there is nothing to
				// compare it against (see regressed).
				message += fmt.Sprintf("; no earlier list from this source covers %s, so unless another source does their certificates are refused until this one serves a list at or above the highest number it has accepted for them, or one which carries no number at all", strings.Join(uncovered, ", "))
			}
			failures[i] = message
			// The wording is what makes this a different condition from the last one logged for this
			// source: the same distribution point which was unreachable and now serves a rollback has
			// something new to report (see logFailures).
			kinds[i] = message
		}
		v.lastGood[v.sources[i].location] = crls
		loaded = append(loaded, crls...)
		now := v.now()
		for _, crl := range crls {
			if wait := crl.refreshDelay(now, next); wait < next {
				next = wait
			}
		}
	}
	if !provision {
		// At provision the returned error below is the report, and there is nothing previously
		// loaded to speak of keeping.
		v.logFailures(failures, kinds)
	}

	if len(failures) > 0 {
		// Retry well before the normal interval so that a distribution point which was briefly
		// unreachable does not have to wait out a whole refresh cycle to be believed again.
		next = min(next, crlRetryOnFailure)
	}

	reports := make([]string, 0, len(failures))
	for i := range results {
		if reason, ok := failures[i]; ok {
			reports = append(reports, fmt.Sprintf("%s: %s", v.sources[i].display(), reason))
		}
	}

	if provision && len(failures) > 0 {
		// A config load is the one moment an operator is certainly listening, and it is the moment
		// a mistake in the configuration is cheapest to report. Running on a subset of the sources
		// would look exactly like a deployment whose revocation checking works, which is the
		// failure this module exists to prevent; so a mistyped path or a distribution point which
		// moved is refused here rather than discovered months later. Once running, a source which
		// fails keeps whatever was last obtained from it (see above), because dropping known
		// revocations because a server is briefly down opens the door instead of closing it.
		return boundedRefresh(next), fmt.Errorf("could not load %d of the %d configured CRL source(s): %s",
			len(failures), len(v.sources), strings.Join(reports, "; "))
	}

	set := buildCRLSet(loaded)
	if set == nil && provision {
		return boundedRefresh(next), errors.New("no CRL source could be loaded")
	}
	if set == nil {
		// Running, and every source was refused outright with nothing of its own to fall back on:
		// the lists which were serving these issuers are gone, so the set in service is emptied
		// rather than left holding certificates nobody fetched this time. A certificate whose
		// revocation status cannot be established is refused, which is what the refusal above
		// promised an operator; leaving the last snapshot standing would admit on it instead.
		set = &crlSet{byIssuer: make(map[string][]*parsedCRL)}
	}
	summary := set.summary()
	changed := summary != v.summary
	v.summary = summary
	previous := v.snapshot.Swap(set)

	// Log at info only when something actually changed, so that a deployment which reloads
	// every hour does not fill the log with identical lines.
	level := zap.DebugLevel
	if previous == nil || changed {
		level = zap.InfoLevel
	}
	if len(set.byIssuer) == 0 {
		// No "loaded CRLs" line can describe this state because there is no list to name, and the
		// per-source errors above do not read as it either. Say plainly that nothing answers for any
		// issuer now: from here every certificate whose issuer needs a list is refused as uncovered,
		// which the handshakes will otherwise be left to imply one warning at a time. This is said on
		// the change into the state rather than once per process, because leaving it and falling back
		// into it again are two different incidents. The first set ever installed cannot be an empty
		// one — a config load refuses that outright above — so there is always a previous snapshot to
		// have come from; the read is written nil-safe only so that this line cannot panic if that
		// changes, not because anything here waits for it.
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
		// Every source reported a problem this cycle: it did not answer, or what it served was
		// refused. Some of what they served may still be in the set — one list refused beside
		// others kept is a problem and a load at once — which is why this says that each source
		// reported something rather than claiming none could be used. The reasons are repeated here
		// because the line above which names them is said once per change, while this one is
		// reported again on every retry.
		return boundedRefresh(next), fmt.Errorf("every configured CRL source reported a problem this time: %s",
			strings.Join(reports, "; "))
	}
	return boundedRefresh(next), nil
}

// sourceResult is what one source produced during a reload pass.
type sourceResult struct {
	crls []*parsedCRL

	// refused names, in the module's own words, the lists this source holds which will never be
	// read. They are not a failure of the source — the rest of it loaded — but they do mean that
	// whatever only those lists covered is now uncovered, so they are worth a line of their own.
	refused []string
	err     error
}

// logFailures records which sources reported a problem this cycle and logs the change, so that a
// source which stays down for hours is reported once rather than on every poll. What happens to
// coverage differs by problem, and only the regression reason says so: it names which issuers were
// refused and which of them are left with nothing standing in for them, though not the lists which do
// stand in — those are in the "loaded CRLs" lines. For a source which did not answer, this line says
// nothing about coverage — its previous lists are kept, silently, because that is the ordinary
// running case rather than a change worth a line of its own. The caller must hold v.mu.
//
// kinds says which of these failures are worth re-reporting in the same place: a refusal to go
// backwards names the issuers it covers in its wording, so the same source serving a rollback for a
// different CA is a new condition rather than the old one repeated. The reason text cannot be part of
// the comparison for every kind of failure — Go's DNS timeout carries an ephemeral port which differs
// on every attempt, which would write a line per poll — so only that refusal adds anything here.
func (v *CRLVerifier) logFailures(failures, kinds map[int]string) {
	locations := make([]string, 0, len(failures))
	reasons := make([]string, 0, len(failures))
	keys := make([]string, 0, len(failures))
	for i, src := range v.sources {
		if reason, ok := failures[i]; ok {
			locations = append(locations, src.location)
			reasons = append(reasons, reason)
			keys = append(keys, src.location+"\x00"+kinds[i])
		}
	}

	// The raw locations identify the configured source for the comparison above; what is written
	// out has any credentials hidden.
	current := strings.Join(keys, ",")
	if current == v.failing {
		return
	}
	v.failing = current
	if current == "" {
		v.logger.Info("all CRL sources are loading again")
		return
	}

	for i, location := range locations {
		v.logger.Error("a CRL source reported a problem",
			zap.String("source", redactURL(location)),
			zap.String("reason", reasons[i]),
			zap.String("note", "this is logged again when a source starts or stops failing, or starts failing in a new way"),
		)
	}
}

// logRefused reports the lists a source holds which this module will not read. It is said once per
// distinct answer about a source rather than on every refresh, in the same shape as the other
// standing conditions here: what is true now will be true until somebody changes the file or the CA
// publishes something else. The consequence is spelled out because "loaded 3 CRLs" and "loaded 3 of
// the 4 you configured" look the same in a log which does not say otherwise.
func (v *CRLVerifier) logRefused(src crlSource, refused []string) {
	if len(refused) == 0 {
		return
	}
	// Sorted before it is remembered as much as before it is written out: the same set of refusals
	// reported in a different order is the same condition, and should not be logged twice.
	slices.Sort(refused)
	level, ok := v.logOnceLevel("refused\x00"+src.location+"\x00"+strings.Join(refused, "|"), zap.ErrorLevel)
	if !ok {
		return
	}
	v.logger.Log(level, "a configured CRL source holds lists this module will not read",
		zap.String("source", src.display()),
		zap.Strings("refused", refused),
		zap.String("note", "the other lists from that source are loaded; certificates which only a refused list covered are refused as uncovered"),
	)
}

// regressed splits a freshly loaded set into the lists which may be used and those whose
// cRLNumber is lower than what this same source has already served for the same issuer and
// signing key, which would undo the revocations published since. Only lists carrying a number can
// be compared, since that is what makes their order meaningful; the high-water marks are raised
// for whatever is kept. A list with no cRLNumber at all is kept without comparison — such a CA
// (EJBCA's issuing CRL being the one in hand) cannot be shown by its own numbering to have gone
// backwards, and refusing every un-numbered list would refuse that deployment outright. What still
// stands between it and an admission is the signature check, as everywhere else.
//
// The marks are per source because this is a guard against one distribution point serving an
// older object than it served before, and two distribution points of one CA may hold different
// partitions of its revocations, each counting on its own. They are per signing key because a CA
// which re-keys starts numbering again. Nor is a mark a trust decision: nothing here believes a
// CRL, and what admits a certificate is a signature which validates against the verified chain
// (see parsedCRL.verifiesAgainst), so a list which numbers itself very high cannot clear a
// revocation however it is signed. What it can do is make the genuine lists afterwards look like
// rollbacks, which is a refusal an operator can see and end by restarting Caddy — never an
// admission.
//
// A list this very source has already been accepted for is exempt from the comparison, which is
// what makes an overlap survivable: a publisher whose clock ran ahead when it issued the newer
// list leaves the older one sitting beside it, still saying everything the newer one will, and
// buildCRLSet already ranks it below. Refusing such a list because its own number is lower than
// the mark would drop the only current word about that CA and take every client down for the
// length of the overlap — which matters precisely because the newer list may be the one which is
// not yet valid, leaving the older one to answer until it can (see verifyCert). The exemption is by
// content, so it cannot admit a stranger: an older object this source has never served is judged on
// its own number and refused. Nor does the exemption stand on its own: an already-served list is
// exempt only where the same fetch carries a higher list for that issuer which is itself not behind
// the marks — at or above them, since re-reading an overlap leaves the top equal to the mark it
// raised. That is what an overlap looks like: it is the higher list which stands up for the batch,
// and the older one answers only while the newer one cannot. Where the batch's own highest list is
// behind the marks, the batch went backwards as a whole and its lowest list must not survive it — otherwise refusing
// the newer one would stand a future list in while this one kept answering for the issuer below it.
// The batch's highest list is found with the same tolerance behind uses for a key id nobody states,
// so a CA which starts publishing its key id in the middle of an overlap is not measured against a
// mark made by lists which stated no key at all. Without that tolerance the older list is refused as
// a rollback on every refresh it is served, and where the newer list is the one which is not yet
// valid — the shape an overlap usually exists for — the issuer is left with only a list which cannot
// answer yet. A source which served a newer list once and afterwards serves only lists behind the
// marks is refused; two fetches
// of lists the CA genuinely signed would otherwise walk the loaded set back to a stale one, which is
// the rollback this function exists to refuse. What survives is therefore the overlap itself: an old
// list replayed beside a newer one which is not yet valid is believed while the newer one cannot
// answer. Only a list the CA's key signed can answer for it — this function runs before any
// signature is checked, so a forged pair can refuse but never admit — and such a pair is one the
// CA's own publishing created; refusing it would refuse every legitimate overlap along with it.
//
// A list which was refused is not remembered as served: what lastGood holds is the lists kept and
// stood in, so a refused list is reported for as long as this source keeps serving it — nothing later
// rehabilitates those bytes. What a later fetch can end is the coverage gap: this source speaks for the
// issuer again once it serves a list at or above the mark, or from a restart, which starts from
// scratch. That is the cost of a guard which cannot tell a rollback from a CA republishing the past.
//
// The caller must hold v.mu.
func (v *CRLVerifier) regressed(location string, fresh []*parsedCRL) (keep, behind []*parsedCRL) {
	// Bytes this source has already been accepted for are not a rollback of it. lastGood holds the
	// lists kept or stood in last time: the caller stores this batch after returning.
	served := make(map[[sha256.Size]byte]bool, len(v.lastGood[location]))
	for _, prev := range v.lastGood[location] {
		served[prev.contentDigest()] = true
	}

	for _, crl := range fresh {
		if crl.number == nil {
			// Nothing to order it against: a list without a number cannot be shown to be old.
			keep = append(keep, crl)
			continue
		}
		key := location + "\x00" + crl.issuerKey
		aki := crl.akiKey()
		marks := v.maxNumber[key]
		if marks.behind(aki, crl.number) {
			// An already-served list survives only beside a higher one from the same batch which is
			// itself not behind the marks: an overlap, where the newer list will say everything this
			// one does and buildCRLSet ranks this one below it. A batch whose own top is behind the
			// marks has gone backwards as a whole, and keeping its lowest list would keep a stale
			// answer for the issuer in service while the refused one above it stands in from before.
			// A batch of one finds itself as its own top, which is what makes that case refuse.
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
		key := location + "\x00" + crl.issuerKey
		v.maxNumber[key] = v.maxNumber[key].raised(crl.akiKey(), crl.number)
	}
	return keep, behind
}

// crlNumberMark is the highest cRLNumber one source has served for one issuer under one signing
// key, with an empty key id standing for a source which does not say which key signed the list.
type crlNumberMark struct {
	aki    string
	number *big.Int
}

// crlNumberMarks are the high-water marks of one issuer at one source, one per signing key seen.
type crlNumberMarks []crlNumberMark

// behind reports whether a freshly loaded list is older than something this source already served
// for the same issuer. Two signing keys of one CA number independently, so they are not compared;
// a key id missing on either side is unknown rather than different, and is compared, so that a CA
// which starts or stops publishing its key id cannot slip a rollback past the guard.
func (marks crlNumberMarks) behind(aki string, number *big.Int) bool {
	for _, mark := range marks {
		if aki != "" && mark.aki != "" && aki != mark.aki {
			continue
		}
		if compareNumbers(number, mark.number) < 0 {
			return true
		}
	}
	return false
}

// batchTop returns the highest-numbered list of issuerKey in this batch whose signing key can be
// compared with aki under the same rule crlNumberMarks.behind uses — a key id either side leaves
// unstated is unknown rather than different, so it does not exclude the other. It carries the highest
// number this fetch states for that issuer under any key id which cannot be excluded, and it may be
// the list being examined itself: a batch whose top is behind the marks went backwards as a whole.
// The list being examined is always among the candidates and always comparable with itself, so a
// numbered list never gets a nil result back.
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

// raised returns the marks with this key id's high-water mark moved up to number, adding one where
// this signing key has not been seen from this source before. A mark only ever moves up: a list
// refused as regressed never brings one down.
func (marks crlNumberMarks) raised(aki string, number *big.Int) crlNumberMarks {
	for i, mark := range marks {
		if mark.aki == aki {
			if compareNumbers(number, mark.number) > 0 {
				marks[i].number = number
			}
			return marks
		}
	}
	return append(marks, crlNumberMark{aki: aki, number: number})
}

// superseded returns the previously loaded lists which stand in for the ones just refused as
// regressed, so that — where an earlier numbered copy exists — refusing a step backwards does not
// also drop the issuer from the set. A list stands in only for the list it is the earlier copy of:
// same issuer, and the same signing key where both say which one they carry — otherwise two CAs whose
// names are identical, or a CA which has re-keyed, would keep each other's stale lists in service.
//
// What stands in is chosen from what was loaded before, not from this batch's verdicts, so a list
// which this batch also refused can come back stood in when it stands above another refused list —
// the same bytes, now reported on rather than quietly served. The refusal is about what this source
// may establish going forward; coverage for the clients already under that issuer is the other half.
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

// regressedNames words a batch of refused lists for an operator: the issuers affected, each named
// once however many lists were refused for it, and the subset of them left with nothing from this
// source at all. The two differ whenever one issuer regresses with an earlier copy standing in while
// another is left uncovered, which is why they are not one list — a report which said "nothing
// covers that issuer" about both would send an operator looking for a missing trust anchor on the
// one which is still covered.
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

// boundedRefresh clamps a wait to what this module is willing to go without refetching, and leaves
// a little headroom so that a scheduled reload does not land exactly when a CRL expires.
func boundedRefresh(d time.Duration) time.Duration {
	d = max(min(d, defaultCRLRefresh), minCRLRefresh)
	if d <= time.Minute {
		return d
	}
	return d - d/10
}

// refreshDelay returns how long this list may be left alone before it is fetched again, given an
// upper bound. The answer comes from the list itself: a CA which shortens its CRL lifetime is
// followed without waiting for the current one to expire. The wait is measured from now rather
// than from the list's own start, since a process which starts near the end of a CRL's life
// should not wait a whole lifetime to fetch a new one.
func (c *parsedCRL) refreshDelay(now time.Time, bound time.Duration) time.Duration {
	if c.nextUpdate.IsZero() || c.thisUpdate.IsZero() {
		return bound
	}
	lifetime := c.nextUpdate.Sub(c.thisUpdate)
	if lifetime <= 0 {
		// A list which claims to expire no later than it started has no usable lifetime. Retry at
		// the failure interval rather than once a second: the publisher is broken, and polling it
		// faster does not make it less broken.
		return min(crlRetryOnFailure, bound)
	}
	// Fetch again when three fifths of the CRL's stated lifetime has elapsed.
	due := c.thisUpdate.Add(time.Duration(float64(lifetime) * 3 / 5))
	// Past due, or so close that polling any sooner would be a busy loop: the publisher is behind,
	// and hammering it does not make it publish. A list which is already expired is exactly when an
	// operator most wants a fast recovery, and one fetch per retry interval is fast enough for a CA
	// whose lifetime is measured in days without turning a stopped publisher into a request per
	// second forever.
	wait := max(due.Sub(now), crlRetryOnFailure)
	return min(wait, bound)
}
