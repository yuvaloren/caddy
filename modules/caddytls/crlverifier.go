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
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// How this module talks to a distribution point: the ceiling on one fetch, and how far a
// location may redirect it. Both are applied to the HTTP client built in Provision.
const (
	// defaultCRLTimeout bounds how long one source may take to answer one fetch, when the config
	// does not say otherwise. A distribution point which hangs must not hold up a config load.
	defaultCRLTimeout = 30 * time.Second

	// maxCRLRedirects bounds how far a distribution point may redirect a fetch.
	maxCRLRedirects = 3
)

func init() {
	caddy.RegisterModule(CRLVerifier{})
}

// CRLVerifier checks client certificates against certificate revocation lists (CRLs).
//
// Go's X.509 verification has no concept of revocation, so a verified chain says nothing
// about whether its leaf has been revoked; this verifier supplies that missing check. It
// runs after the client certificate chain has been verified against the configured trust
// pool, so it can take the trust needed to believe a CRL from the handshake itself: a CRL
// is honored only if its signature validates against the issuer certificate of that same
// verified chain (see parsedCRL.verifiesAgainst and issuerOf). A forged or corrupted CRL
// can therefore only cause connections to be refused; it cannot get a revoked certificate
// accepted, because no list which fails that check is ever believed. Distribution points
// named inside the client certificate are deliberately not followed, since those URLs are
// chosen by the peer being authenticated.
//
// There is one behavior and it is the strict one. Every certificate in a verified chain
// which has its issuer above it in that chain is checked against a current CRL from that
// issuer. The certificate at the top is asked about only where it is its own issuer — one
// which carries its own name as issuer answers for itself, and nothing else can speak for it —
// because an issuer outside the chain is not something the chain can prove, and RFC 5280 path
// validation
// does not ask about an anchor either. A chain of one which does not carry its own name as
// issuer — a certificate the trust pool trusts directly — is refused rather than passed: it is
// in nobody's CRL because there is no issuer in the handshake to write one (see notRevocable).
// Where the trust pool allows several chains, every one of them has to come out
// clean: a revocation or a gap which is visible on any path to the pool refuses the
// connection, so a pool holding an extra root can never become the way around a check.
// A connection is refused wherever the revocation status of a certificate in scope
// cannot be established: no CRL claims its issuer, a CRL is past its nextUpdate, or a
// CRL's signature does not validate against the chain. A check which is not working thus
// looks like an outage rather than like success. A client certificate which was presented
// but for which no chain could be verified also always refuses, because passing it would
// make this verifier inert exactly when it matters.
type CRLVerifier struct {
	// Paths of CRL files to load, in PEM or DER format. Every CRL object in a file is
	// loaded, so a bundle of several concatenated PEM CRLs works as expected (reading such
	// a bundle with `openssl crl` shows only the first object, which misleads people about
	// what is in it; this module reads them all).
	CRLFiles []string `json:"crl_files,omitempty"`

	// URLs of CRL distribution points to fetch. Only URLs configured here are ever
	// requested; the distribution points inside a client certificate are not followed,
	// because they would let a peer make the server issue HTTP requests at arbitrary
	// destinations. Both PEM and DER bodies are accepted.
	CRLURLs []string `json:"crl_urls,omitempty"`

	// How long to wait for a single CRL URL. Note that the sources are loaded once
	// synchronously while provisioning, so this also bounds how long a config load may
	// take per URL. Default: 30s.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	logger  *zap.Logger
	sources []crlSource
	client  *http.Client
	now     func() time.Time

	// The lock and the wait group are pointers, and the loaded set is reached through a
	// pointer, so that the module value stays copyable: CaddyModule has a value receiver, as
	// every module in this package does, and vet's copylocks rejects a struct which embeds a
	// lock or an atomic in it. This is how tls.go (bgWg, serverNamesMu) and ech.go (configsMu)
	// do it. They are allocated in Provision.
	snapshot *atomic.Pointer[crlSet]

	mu        *sync.Mutex
	lastGood  map[string][]*parsedCRL
	maxNumber map[string]crlNumberMarks

	// loggedOnce remembers what has already been reported about a list or a chain, so that
	// something which will be true on every connection is said once, at the level that case
	// deserves — loudly where it locks clients out, quietly where it costs only an attempt — and
	// afterwards only to whoever is looking. A pointer for the same reason as the lock above.
	loggedOnce *sync.Map

	summary string
	failing string
	wg      *sync.WaitGroup

	// The reload loop ends on a cancellation of its own, derived from the module's context, so
	// that Cleanup can end it without waiting for someone else to cancel first; see Cleanup. Like
	// the wait group above, it belongs to a provisioned instance and not to the module value.
	stopReload context.CancelFunc
	reloadCtx  context.Context
}

// CaddyModule returns the Caddy module information.
func (CRLVerifier) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.client_auth.verifier.crl",
		New: func() caddy.Module { return new(CRLVerifier) },
	}
}

// Provision implements caddy.Provisioner.
func (v *CRLVerifier) Provision(ctx caddy.Context) (err error) {
	v.logger = ctx.Logger()
	v.now = time.Now

	// Everything this module does in the background hangs off this one cancellation: it ends the
	// reload loop and it abandons a fetch which is still waiting on a distribution point.
	v.reloadCtx, v.stopReload = context.WithCancel(ctx)
	defer func() {
		if err != nil {
			// Nothing was started, and a context which outlives a config that was refused would
			// just be another thing holding the previous one open.
			v.stopReload()
		}
	}()

	v.snapshot = new(atomic.Pointer[crlSet])
	v.mu = new(sync.Mutex)
	v.wg = new(sync.WaitGroup)
	v.lastGood = make(map[string][]*parsedCRL)
	v.maxNumber = make(map[string]crlNumberMarks)
	v.loggedOnce = new(sync.Map)

	if err := v.buildSources(ctx); err != nil {
		return err
	}
	// A negative duration is not "unset" and must not be quietly replaced by a default: as a
	// timeout it would mean every fetch fails. Nothing else about this config can be wrong by value
	// — the sources are checked as they are built above, which is also where placeholder expansion
	// happens, since Caddy expands a loaded config in place everywhere else too. No default is
	// written back into the config fields: a timeout of zero there means this module's 30 seconds,
	// not a value somebody set.
	if v.Timeout < 0 {
		return errors.New("timeout must not be negative")
	}

	timeout := time.Duration(v.Timeout)
	if timeout == 0 {
		timeout = defaultCRLTimeout
	}
	// A clone of the default transport rather than the shared one: Caddy's own HTTP clients use
	// that instance, and changing anything about it here would change them too. If a plugin has
	// replaced the default transport with something else, start from a plain one; this module's
	// needs are modest and its redirects must not be governed by someone else's policy.
	transport := &http.Transport{}
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = base.Clone()
	}

	v.client = &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Go calls this only when a redirect is about to be followed, with via holding the
			// requests already made — the original included — so len(via) is one more than the
			// redirects followed so far, and the request under consideration is redirect number
			// len(via). Refusing it once that passes the limit follows exactly maxCRLRedirects.
			if len(via) > maxCRLRedirects {
				return fmt.Errorf("more than %d redirects", maxCRLRedirects)
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to unsupported scheme %q", req.URL.Scheme)
			}
			return nil
		},
	}

	// Load once synchronously so that a configuration which cannot obtain its CRLs is
	// refused now, at config load time, rather than silently admitting every certificate
	// later. This means an unreachable distribution point prevents a config reload until it
	// is reachable again or is removed from the config; crl_files avoids that coupling
	// entirely. Once loaded, a source which later fails keeps whatever was last obtained
	// from it, until that list ages past its own nextUpdate.
	next, err := v.reload(true)
	if err != nil {
		return err
	}

	v.wg.Add(1)
	go v.loop(next)

	return nil
}

// buildSources expands and checks the configured locations. Only http and https URLs are
// accepted: these fetches are made on the operator's behalf, and a scheme which can read local
// files or speak another protocol would turn the list of distribution points into something
// other than what was configured. Distribution points inside client certificates are never
// added here; see the note on the type about why they are not followed.
func (v *CRLVerifier) buildSources(ctx caddy.Context) error {
	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
	}
	for i, file := range v.CRLFiles {
		v.CRLFiles[i] = repl.ReplaceKnown(file, "")
		v.sources = append(v.sources, crlSource{kind: "file", location: v.CRLFiles[i]})
	}
	for i, rawURL := range v.CRLURLs {
		rawURL = repl.ReplaceKnown(rawURL, "")
		v.CRLURLs[i] = rawURL
		u, err := url.Parse(rawURL)
		if err != nil {
			// Redaction cannot be relied on for a URL which does not parse — an unescaped password
			// is one of the things which stops it parsing — and the parse error itself quotes the
			// text it failed on. So name the entry instead of repeating it, and report only the
			// reason, which is what tells an operator what to fix.
			var urlErr *url.Error
			reason := err
			if errors.As(err, &urlErr) {
				reason = urlErr.Err
			}
			return fmt.Errorf("invalid crl_url at index %d of crl_urls: %v", i, reason)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("crl_url '%s' must be an http or https URL", redactURL(rawURL))
		}
		if u.Host == "" {
			return fmt.Errorf("crl_url '%s' has no host", redactURL(rawURL))
		}
		v.sources = append(v.sources, crlSource{kind: "url", location: rawURL})
	}
	if len(v.sources) == 0 {
		return errors.New("no CRLs configured: set crl_files and/or crl_urls")
	}
	return nil
}

// Validate implements caddy.Validator.
func (v *CRLVerifier) Validate() error {
	set := v.current()
	if set == nil {
		return errors.New("no usable CRLs were loaded")
	}
	return nil
}

// Cleanup implements caddy.CleanerUpper. It stops the reload loop and waits for it to finish.
//
// Caddy normally cancels a module's context before calling this: the cancel returned by
// NewContextWithCause runs the cleanup funcs after cancelling (see context.go), and tls.go relies
// on that order itself - its Stop cancels its background context and then waits on a WaitGroup
// whose goroutines end on that cancellation.
// It does not always do so, though — a module whose Validate fails is cleaned up with its context
// still live (see Context.LoadModuleByID) — and a wait which can only be satisfied by someone else
// is a deadlock either way, so the loop is stopped here as well rather than relied on. Canceling
// twice and waiting with nothing running are both harmless, which is what makes this safe to call
// on a module which never provisioned.
func (v *CRLVerifier) Cleanup() error {
	if v.stopReload != nil {
		v.stopReload()
	}
	if v.wg != nil {
		v.wg.Wait()
	}
	if v.client != nil {
		// The reload loop is finished, so any connection it left open to a distribution point
		// can go now rather than when the process exits.
		v.client.CloseIdleConnections()
	}
	return nil
}

// current returns the loaded set, or nil if nothing has been loaded (which includes a module
// which was never provisioned).
func (v *CRLVerifier) current() *crlSet {
	if v.snapshot == nil {
		return nil
	}
	return v.snapshot.Load()
}

// logOnceLevel reports how this occurrence of something worth reporting once should be written,
// and whether it should be written at all: the level first for key the first time, debug every
// time after that, because whatever is true now will be true of every handshake until it changes.
// Callers build their fields only when this tells them to write, since they sit on the handshake
// path.
func (v *CRLVerifier) logOnceLevel(key string, first zapcore.Level) (zapcore.Level, bool) {
	if v.logger == nil || v.loggedOnce == nil {
		return 0, false
	}
	if _, seen := v.loggedOnce.LoadOrStore(key, struct{}{}); seen {
		first = zap.DebugLevel
	}
	if v.logger.Check(first, "") == nil {
		return 0, false
	}
	return first, true
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler:
//
//	verifier crl <file>... {
//		crl_file <path>
//		crl_url  <url>
//		timeout  <duration>
//	}
//
// The crl_file and crl_url subdirectives may be repeated to load more than one CRL, as may the
// inline file arguments.
func (v *CRLVerifier) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the module name

	// A file may be given inline, which is what most operators need: a path to a list they
	// already export. Everything else is a subdirective, and the nesting is taken from the
	// dispenser rather than assumed to be zero, because this runs inside client_auth.
	for d.NextArg() {
		v.CRLFiles = append(v.CRLFiles, d.Val())
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "crl_file":
			file, err := oneArg(d)
			if err != nil {
				return err
			}
			v.CRLFiles = append(v.CRLFiles, file)
		case "crl_url":
			rawURL, err := oneArg(d)
			if err != nil {
				return err
			}
			v.CRLURLs = append(v.CRLURLs, rawURL)
		case "timeout":
			dur, err := durationArg(d)
			if err != nil {
				return err
			}
			v.Timeout = caddy.Duration(dur)
		default:
			return d.Errf("unrecognized subdirective for the CRL verifier: %s", d.Val())
		}
	}
	return nil
}

func oneArg(d *caddyfile.Dispenser) (string, error) {
	if !d.NextArg() {
		return "", d.ArgErr()
	}
	arg := d.Val()
	if d.NextArg() {
		return "", d.Errf("expected one argument, got an extra '%s'", d.Val())
	}
	return arg, nil
}

func durationArg(d *caddyfile.Dispenser) (time.Duration, error) {
	arg, err := oneArg(d)
	if err != nil {
		return 0, err
	}
	dur, err := caddy.ParseDuration(arg)
	if err != nil {
		return 0, d.Errf("invalid duration '%s': %v", arg, err)
	}
	return dur, nil
}

// Interface guards
var (
	_ caddy.Provisioner         = (*CRLVerifier)(nil)
	_ caddy.Validator           = (*CRLVerifier)(nil)
	_ caddy.CleanerUpper        = (*CRLVerifier)(nil)
	_ caddyfile.Unmarshaler     = (*CRLVerifier)(nil)
	_ ClientCertificateVerifier = (*CRLVerifier)(nil)
)
