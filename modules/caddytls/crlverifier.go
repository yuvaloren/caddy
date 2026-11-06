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

const (
	// defaultCRLTimeout is the per-fetch timeout when none is configured.
	defaultCRLTimeout = 30 * time.Second

	// maxCRLRedirects is the most redirects a CRL fetch will follow.
	maxCRLRedirects = 3
)

func init() {
	caddy.RegisterModule(CRLVerifier{})
}

// CRLVerifier refuses client certificates that appear on a certificate
// revocation list (CRL). It runs after chain verification, and trusts a
// CRL only if its signature validates against the issuer certificate in
// the verified chain; distribution points inside the client certificate
// are never followed.
//
// The check fails closed: every certificate whose issuer is above it in
// the chain must be absent from a current, valid CRL from that issuer.
// A missing, expired, or unverifiable CRL refuses the connection. If the
// trust pool yields several chains, all of them must pass. The top
// certificate of a chain is checked only when it is self-issued, since
// nothing in the chain can vouch for a CRL from an outside issuer.
type CRLVerifier struct {
	// Paths of CRL files to load, in PEM or DER format. Every CRL in
	// a PEM bundle is loaded.
	CRLFiles []string `json:"crl_files,omitempty"`

	// URLs of CRLs to fetch over HTTP or HTTPS. PEM and DER bodies
	// are accepted.
	CRLURLs []string `json:"crl_urls,omitempty"`

	// How long to wait for a single CRL URL. Default: 30s. CRLs are
	// loaded synchronously during provisioning, so this also bounds
	// config load time.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	logger  *zap.Logger
	sources []crlSource
	client  *http.Client
	now     func() time.Time

	// pointers so the module value stays copyable (CaddyModule has a
	// value receiver and vet's copylocks rejects embedded locks)
	snapshot *atomic.Pointer[crlSet]

	mu       *sync.Mutex
	lastGood map[string][]*parsedCRL

	// highest cRLNumber accepted per source, issuer and signing key;
	// used to detect a CRL rolling back (see regressed)
	maxNumber map[sourceIssuer]crlNumberMarks

	// conditions already logged, so a persistent one is reported once
	loggedOnce *sync.Map

	summary string

	// source failures from the previous cycle, so an unchanged
	// condition is not logged on every refresh
	failing []sourceFailure

	wg *sync.WaitGroup

	// reloadCtx is derived from the module context so Cleanup can stop
	// the reload loop itself
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

	v.reloadCtx, v.stopReload = context.WithCancel(ctx)
	defer func() {
		if err != nil {
			v.stopReload()
		}
	}()

	v.snapshot = new(atomic.Pointer[crlSet])
	v.mu = new(sync.Mutex)
	v.wg = new(sync.WaitGroup)
	v.lastGood = make(map[string][]*parsedCRL)
	v.maxNumber = make(map[sourceIssuer]crlNumberMarks)
	v.loggedOnce = new(sync.Map)

	if err := v.buildSources(ctx); err != nil {
		return err
	}
	// a negative timeout would make every fetch fail; the default is
	// not written back so a zero in the config still means "default"
	if v.Timeout < 0 {
		return errors.New("timeout must not be negative")
	}

	timeout := time.Duration(v.Timeout)
	if timeout == 0 {
		timeout = defaultCRLTimeout
	}
	// clone rather than share the default transport, which Caddy's
	// own HTTP clients also use
	transport := &http.Transport{}
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = base.Clone()
	}

	v.client = &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// via includes the original request, so this is redirect number len(via)
			if len(via) > maxCRLRedirects {
				return fmt.Errorf("more than %d redirects", maxCRLRedirects)
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to unsupported scheme %q", req.URL.Scheme)
			}
			return nil
		},
	}

	// load synchronously so a config whose CRLs cannot be obtained is
	// refused at load time instead of admitting every certificate later
	next, err := v.reload(true)
	if err != nil {
		return err
	}

	v.wg.Add(1)
	go v.loop(next)

	return nil
}

// buildSources expands placeholders and validates the configured
// locations. Only http and https URLs are accepted.
func (v *CRLVerifier) buildSources(ctx caddy.Context) error {
	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
	}
	for i, file := range v.CRLFiles {
		v.CRLFiles[i] = repl.ReplaceKnown(file, "")
		v.sources = append(v.sources, crlFileSource(v.CRLFiles[i]))
	}
	for i, rawURL := range v.CRLURLs {
		rawURL = repl.ReplaceKnown(rawURL, "")
		v.CRLURLs[i] = rawURL
		u, err := url.Parse(rawURL)
		if err != nil {
			// url.Error quotes the URL, which may contain credentials
			reason := err
			if urlErr, ok := errors.AsType[*url.Error](err); ok {
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
		v.sources = append(v.sources, crlURLSource(rawURL))
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

// Cleanup implements caddy.CleanerUpper. It stops the reload loop and
// waits for it to finish. The loop is canceled here as well as by the
// module context because a module whose Provision fails is cleaned up
// with its context still live (see Context.LoadModuleByID).
func (v *CRLVerifier) Cleanup() error {
	if v.stopReload != nil {
		v.stopReload()
	}
	if v.wg != nil {
		v.wg.Wait()
	}
	if v.client != nil {
		v.client.CloseIdleConnections()
	}
	return nil
}

// current returns the loaded set, or nil if none is loaded.
func (v *CRLVerifier) current() *crlSet {
	if v.snapshot == nil {
		return nil
	}
	return v.snapshot.Load()
}

// logKind classifies conditions that are logged once rather than on
// every connection.
type logKind int

const (
	// a chain was accepted at its top certificate, which no CRL covers
	logChainTop logKind = iota
	// a certificate was refused because no loaded CRL covers its issuer
	logUncoveredIssuer
	// a certificate was refused because the CRL for its issuer is unusable
	logUnusableCRL
	// a source holds CRLs this module will not read
	logRefusedSource
)

// logKey identifies one once-logged condition. The fields are compared
// by ==, so nothing is assembled into a string.
type logKey struct {
	kind   logKind
	who    string // issuer or subject name, or a source location
	detail string // distinguishes ways the same subject can fail
}

// logOnceLevel returns the level to log a condition at (the given level
// the first time, debug after that) and whether to log it at all.
func (v *CRLVerifier) logOnceLevel(key logKey, first zapcore.Level) (zapcore.Level, bool) {
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

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. Syntax:
//
//	verifier crl [<file>...] {
//	    crl_file <path>
//	    crl_url  <url>
//	    timeout  <duration>
//	}
//
// The inline files, crl_file, and crl_url may be repeated.
func (v *CRLVerifier) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the module name

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
