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
	"bytes"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func TestCRLVerifierURLSource(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 14000)
	goodCRL := pki.crl(t, crlOptions{number: 1})

	for _, tc := range []struct {
		name      string
		handler   http.HandlerFunc
		wantError bool // provisioning is expected to fail
	}{
		{
			name: "der",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/pkix-crl")
				_, _ = w.Write(goodCRL)
			},
		},
		{
			name: "pem",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: pemTypeCRL, Bytes: goodCRL}))
			},
		},
		{
			name:      "not found with html",
			handler:   func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "<html>nope</html>", http.StatusNotFound) },
			wantError: true,
		},
		{
			name: "a response which never finishes",
			handler: func(w http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
			},
			wantError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			cfg := &CRLVerifier{
				CRLURLs: []string{srv.URL},
				Timeout: caddy.Duration(300 * time.Millisecond),
			}
			if tc.wantError {
				if err := provisionCRLVerifierExpectError(t, cfg); err == nil {
					t.Fatal("expected provisioning to fail")
				}
				return
			}

			v := provisionCRLVerifier(t, cfg)
			if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err != nil {
				t.Errorf("expected admission, got: %v", err)
			}
		})
	}

	t.Run("the request is a plain get with an empty body", func(t *testing.T) {
		var got http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			// net/http always hands out a non-nil body, so read it to know it is empty
			var body bytes.Buffer
			if _, err := body.ReadFrom(r.Body); err != nil {
				t.Errorf("reading the request body: %v", err)
			}
			if r.Method != http.MethodGet || body.Len() != 0 {
				t.Errorf("unexpected request: %s with %d bytes of body", r.Method, body.Len())
			}
			_, _ = w.Write(goodCRL)
		}
		srv := httptest.NewServer(got)
		defer srv.Close()

		v := provisionCRLVerifier(t, &CRLVerifier{CRLURLs: []string{srv.URL}})
		if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err != nil {
			t.Errorf("expected admission, got: %v", err)
		}
	})
}

func TestCRLVerifierRedirectsAreBounded(t *testing.T) {
	var hops int64
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hops, 1)
		w.Header().Set("Location", srv.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	err := provisionCRLVerifierExpectError(t, &CRLVerifier{CRLURLs: []string{srv.URL}, Timeout: caddy.Duration(time.Second)})
	if err == nil {
		t.Fatal("expected a redirect loop to fail the load")
	}
	// one request for the distribution point and one per redirect followed
	if got := atomic.LoadInt64(&hops); got > maxCRLRedirects+1 {
		t.Errorf("made %d requests, expected no more than %d", got, maxCRLRedirects+1)
	}
}

func TestCRLVerifierRedirectPolicy(t *testing.T) {
	pki := newCRLTestPKI(t)
	path := writeCRLDER(t, "issuing.crl", pki.crl(t, crlOptions{number: 1}))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	// fetches use a clone of the default transport, not the process-wide one
	if v.client.Transport == http.DefaultTransport {
		t.Error("the module shares http.DefaultTransport with the rest of Caddy")
	}

	request := func(rawURL string) *http.Request {
		t.Helper()
		u, err := url.Parse(rawURL)
		if err != nil {
			t.Fatalf("parsing %q: %v", rawURL, err)
		}
		return &http.Request{Method: "GET", URL: u}
	}

	// Go calls CheckRedirect with via holding the requests already made, so
	// the first redirect arrives with one entry, never zero
	var via []*http.Request
	for hop := 1; hop <= maxCRLRedirects+1; hop++ {
		via = append(via, request("https://crl.example/via"))
		err := v.client.CheckRedirect(request("https://crl.example/next"), via)
		switch {
		case hop <= maxCRLRedirects && err != nil:
			t.Errorf("redirect %d should have been followed: %v", hop, err)
		case hop > maxCRLRedirects && err == nil:
			t.Errorf("redirect %d should have been refused by the hop limit", hop)
		}
	}

	if err := v.client.CheckRedirect(request("file:///etc/passwd"), via[:1]); err == nil {
		t.Error("expected a redirect to a scheme which is not http or https to be refused")
	}
}

// Basic-auth credentials must not reach an operator through errors or log
// names. Go masks only the password, so the username goes too.
func TestCRLVerifierURLCredentialsAreRedacted(t *testing.T) {
	const secret = "s3cr3t-word"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()

	// net/http's own error quotes the URL with the password masked by Go, so
	// redaction cannot work by replacing the configured string
	unreachable := "http://reader:" + secret + "@127.0.0.1:1/crl"

	for _, tc := range []struct {
		name string
		url  string
	}{
		{"what the server said about it", strings.Replace(srv.URL, "127.0.0.1", "reader:"+secret+"@127.0.0.1", 1) + "/crl"},
		{"not being able to reach it at all", unreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := provisionCRLVerifierExpectError(t, &CRLVerifier{CRLURLs: []string{tc.url}})
			if err == nil {
				t.Fatal("expected a distribution point which cannot be used to be refused")
			}
			assertNoCredentials(t, err.Error(), secret)
			if !strings.Contains(err.Error(), "/crl") {
				t.Errorf("the error should still say which source failed, got: %v", err)
			}
		})
	}

	// display and redact write the URL into the log on a reload failure
	t.Run("what a source calls itself", func(t *testing.T) {
		src := crlURLSource(unreachable)
		assertNoCredentials(t, src.display(), secret)
		if !strings.Contains(src.display(), "/crl") {
			t.Errorf("the display name should still identify the source, got: %s", src.display())
		}
	})

	t.Run("what an error about it says", func(t *testing.T) {
		src := crlURLSource(unreachable)
		for _, raw := range []error{
			// the URL exactly as configured
			errors.New(`Get "` + unreachable + `": remote error: tls: handshake failure`),
			// what Go's http client produces, password masked by itself
			errors.New(`Get "http://reader:xxx@127.0.0.1:1/crl": dial tcp 127.0.0.1:1: connect: connection refused`),
			// the URL more than once, and once without credentials
			errors.New(`Get "http://reader:xxx@127.0.0.1:1/crl": after 3 redirects to http://reader:s3cr3t-word@127.0.0.1:1/crl`),
		} {
			got := src.redact(raw).Error()
			assertNoCredentials(t, got, secret)
			if !strings.Contains(got, "127.0.0.1:1/crl") {
				t.Errorf("the error should still say which source it is about, got: %s", got)
			}
		}

		// url.Parse takes the last @ in userinfo as the separator, so a password
		// with an unescaped @ is fetched as-is and must be redacted whole
		atSecret := errors.New(`Get "http://reader:pa` + "@" + `ss-word@127.0.0.1:1/crl": connection refused`)
		got := src.redact(atSecret).Error()
		if strings.Contains(got, "reader") || strings.Contains(got, "ss-word") {
			t.Errorf("part of a password containing @ survived redaction: %s", got)
		}
		if !strings.Contains(got, "127.0.0.1:1/crl") {
			t.Errorf("redaction took the host with it: %s", got)
		}

		// an error with no credentials is passed through unchanged
		plain := errors.New("connection reset by peer")
		if got := src.redact(plain); got.Error() != plain.Error() {
			t.Errorf("an error without credentials was altered: %v", got)
		}
	})

	// an @ which is not in a URL's userinfo must be left alone
	t.Run("what a message about something else says", func(t *testing.T) {
		src := crlURLSource(unreachable)
		for _, msg := range []string{
			// an @ in an address, not a URL
			`open /var/crls/team@ok.crl: no such file or directory`,
			`the alert went to ops@example.com but nobody read it`,
			`x509: certificate signed by unknown authority (someone@invalid)`,
			// a URL with no userinfo
			`Get "http://127.0.0.1:8080/crl": dial tcp: connection refused`,
			`redirect from http://one.invalid/crl to http://two.invalid/crl`,
			// an @ in a query or path is a value, not a separator
			`Get "http://127.0.0.1:8080/crl?issuer=team%40ok.net": server misbehaving`,
			`open "http://crl.invalid/team@ok.crl": not found`,
			`the alert went to crl-admin@teamok.net`,
			// a scheme-relative link
			`followed //crl.invalid/team@ok.crl and got nothing`,
		} {
			if got := src.redact(errors.New(msg)); got.Error() != msg {
				t.Errorf("a message with no credentials in it was altered:\n got: %s\nwant: %s", got, msg)
			}
		}
	})

	t.Run("what a message about two urls says", func(t *testing.T) {
		// the URL with credentials loses them; the one without is untouched
		src := crlURLSource(unreachable)
		msg := `Get "http://crl.invalid/crl" redirected to http://reader:` + secret + `@127.0.0.1:1/crl`
		got := src.redact(errors.New(msg)).Error()
		assertNoCredentials(t, got, secret)
		if !strings.Contains(got, `http://crl.invalid/crl`) {
			t.Errorf("the URL without credentials was rewritten: %s", got)
		}
		if !strings.Contains(got, "127.0.0.1:1/crl") {
			t.Errorf("the URL with credentials lost more than its credentials: %s", got)
		}

		// a username alone still identifies the account
		userOnly := src.redact(errors.New(`Get "http://reader@127.0.0.1:1/crl": connection refused`)).Error()
		if strings.Contains(userOnly, "reader@") {
			t.Errorf("a username survived redaction: %s", userOnly)
		}
		if !strings.Contains(userOnly, "127.0.0.1:1/crl") {
			t.Errorf("redaction took the host with the username: %s", userOnly)
		}
	})

	t.Run("an url which does not parse", func(t *testing.T) {
		// provisioning refuses an unparsable URL by position without echoing it;
		// redaction is textual, so even this string can be made safe
		unparsable := "http://reader:" + secret + "@exa mple.invalid/crl"
		err := provisionCRLVerifierExpectError(t, &CRLVerifier{CRLURLs: []string{unparsable}})
		if err == nil {
			t.Fatal("expected a URL with a space in it to be refused")
		}
		assertNoCredentials(t, err.Error(), secret)
		if !strings.Contains(err.Error(), "index 0") {
			t.Errorf("the error should say which entry is wrong, got: %v", err)
		}
		if got := redactURL(unparsable); strings.Contains(got, secret) || strings.Contains(got, "reader@") {
			t.Errorf("an unparsable URL could not be redacted: %s", got)
		} else if !strings.Contains(got, "exa mple.invalid/crl") {
			t.Errorf("redaction should leave the rest of the URL alone, got: %s", got)
		}
	})

	t.Run("a file path is not a url", func(t *testing.T) {
		// only URLs are rewritten; a path with an @ must not be mangled
		src := crlFileSource("/var/crls/team@ok.crl")
		if got := src.display(); got != src.key() {
			t.Errorf("a file source was rewritten: %s", got)
		}
	})
}

func TestCRLVerifierUnusableSource(t *testing.T) {
	pki := newCRLTestPKI(t)
	goodCRL := pki.crl(t, crlOptions{number: 1})

	for _, tc := range []struct {
		name     string
		contents func() []byte
	}{
		{name: "html where a crl should be", contents: func() []byte { return []byte("<html><body>Not Found</body></html>") }},
		{name: "empty file", contents: func() []byte { return nil }},
		{name: "a certificate rather than a crl", contents: func() []byte {
			_, other := mintCA(t, "Some Other CA", caPair{}, nil)
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeFile(t, "issuing.crl", tc.contents())
			// fail rather than start a verifier which admits everything
			if err := provisionCRLVerifierExpectError(t, &CRLVerifier{CRLFiles: []string{path}}); err == nil {
				t.Error("expected provisioning to fail when no CRL could be loaded")
			}
		})
	}

	t.Run("no sources at all", func(t *testing.T) {
		if err := provisionCRLVerifierExpectError(t, &CRLVerifier{}); err == nil {
			t.Error("expected provisioning to fail with no CRLs configured")
		}
	})

	t.Run("a url which is not http or https", func(t *testing.T) {
		err := provisionCRLVerifierExpectError(t, &CRLVerifier{CRLURLs: []string{"file:///etc/passwd"}})
		if err == nil || !strings.Contains(err.Error(), "http") {
			t.Errorf("expected a scheme which is not http or https to be refused, got: %v", err)
		}
	})

	t.Run("a url without a host", func(t *testing.T) {
		if err := provisionCRLVerifierExpectError(t, &CRLVerifier{CRLURLs: []string{"https://"}}); err == nil {
			t.Error("expected a URL with no host to be refused")
		}
	})

	t.Run("one good source and one broken one is refused at config load", func(t *testing.T) {
		// running on the subset which loaded would hide the CAs not being checked
		path := writeCRLDER(t, "issuing.crl", goodCRL)
		missing := filepath.Join(t.TempDir(), "absent.crl")
		err := provisionCRLVerifierExpectError(t, &CRLVerifier{CRLFiles: []string{path, missing}})
		if err == nil {
			t.Fatal("expected provisioning to fail when one source could not be read")
		}
		if !strings.Contains(err.Error(), "1 of the 2") || !strings.Contains(err.Error(), "absent.crl") {
			t.Errorf("expected the error to count and name the failed source, got: %v", err)
		}
	})

	t.Run("a source which breaks later keeps its last good crl", func(t *testing.T) {
		// once running, a brief outage must not drop known revocations
		path := writeCRLDER(t, "issuing.crl", goodCRL)
		v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
		if err := os.Remove(path); err != nil {
			t.Fatalf("removing the file: %v", err)
		}
		if _, err := v.reload(false); err == nil {
			t.Error("expected a reload to report the source which went away")
		}
		if got := v.current(); got == nil || len(got.byIssuer) != 1 {
			t.Fatalf("expected the last good CRL to still be in use, got %v", got)
		}
	})

	t.Run("an http url in crl_files is not fetched", func(t *testing.T) {
		var requests int64
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			atomic.AddInt64(&requests, 1)
		}))
		defer srv.Close()

		if err := provisionCRLVerifierExpectError(t, &CRLVerifier{CRLFiles: []string{srv.URL + "/crl"}}); err == nil {
			t.Error("a URL belongs in crl_urls; putting one in crl_files must not be fetched")
		}
		if atomic.LoadInt64(&requests) != 0 {
			t.Error("the module made a request for a configured file path")
		}
	})

	// a negative timeout would fail every fetch, so it is refused rather than defaulted
	t.Run("a negative timeout is refused", func(t *testing.T) {
		if err := provisionCRLVerifierExpectError(t, &CRLVerifier{
			CRLFiles: []string{writeCRLDER(t, "issuing.crl", goodCRL)},
			Timeout:  caddy.Duration(-time.Second),
		}); err == nil {
			t.Error("a negative timeout was accepted")
		}
	})
}

// endlessBody is a distribution point which never finishes sending.
type endlessBody struct{ read int64 }

func (e *endlessBody) Read(p []byte) (int, error) {
	clear(p)
	e.read += int64(len(p))
	return len(p), nil
}

func TestCRLVerifierRefusesABodyLongerThanTheCap(t *testing.T) {
	body := &endlessBody{}
	raw, err := readCapped(body)
	if err == nil {
		t.Fatalf("a body which never ends was accepted after %d bytes", len(raw))
	}
	if !errors.Is(err, errCRLTooLarge) {
		t.Errorf("the refusal should name the limit it hit, got: %v", err)
	}
	if raw != nil {
		t.Errorf("a refused body was handed back anyway, %d bytes of it", len(raw))
	}
	// the reader stops just past the cap, not at the end of a body which has none
	var want int64 = defaultCRLMaxSize + 1
	if body.read != want {
		t.Errorf("the reader took %d bytes from a source which never stops, want no more than %d", body.read, want)
	}
}
