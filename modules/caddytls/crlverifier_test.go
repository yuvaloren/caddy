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
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// provisionCRLVerifier provisions a verifier the way Caddy would and cleans it up
// when the test ends. Lists are minted around time.Now(); tests reload by hand.
func provisionCRLVerifier(t testing.TB, cfg *CRLVerifier) *CRLVerifier {
	t.Helper()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(func() {
		// cancel before Cleanup, as Caddy does
		cancel()
		if err := cfg.Cleanup(); err != nil {
			t.Errorf("cleaning up: %v", err)
		}
	})

	if err := cfg.Provision(ctx); err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validating: %v", err)
	}

	return cfg
}

// provisionCRLVerifierExpectError provisions a verifier which is expected to fail.
func provisionCRLVerifierExpectError(t testing.TB, cfg *CRLVerifier) error {
	t.Helper()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	err := cfg.Provision(ctx)
	if err == nil {
		// cancel first, as Caddy does, so the reload loop ends
		cancel()
		if cleanupErr := cfg.Cleanup(); cleanupErr != nil {
			t.Errorf("cleaning up a config which provisioned anyway: %v", cleanupErr)
		}
		return nil
	}
	cancel()
	return err
}

func TestCRLVerifierCaddyfile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   string
		want    func(*CRLVerifier) error
		wantErr bool
	}{
		{
			name:  "inline file",
			input: "crl /etc/caddy/issuing.crl",
			want: func(v *CRLVerifier) error {
				if len(v.CRLFiles) != 1 || v.CRLFiles[0] != "/etc/caddy/issuing.crl" {
					return fmt.Errorf("crl_files = %v", v.CRLFiles)
				}
				if v.Timeout != 0 {
					return fmt.Errorf("timeout = %v, want unset so the default applies", time.Duration(v.Timeout))
				}
				return nil
			},
		},
		{
			name: "block of subdirectives",
			input: `crl {
	crl_file /etc/caddy/issuing.crl
	crl_file /etc/caddy/root.crl
	crl_url http://pki.example.test/crl
	timeout 5s
}`,
			want: func(v *CRLVerifier) error {
				if len(v.CRLFiles) != 2 || v.CRLFiles[1] != "/etc/caddy/root.crl" {
					return fmt.Errorf("crl_files = %v", v.CRLFiles)
				}
				if len(v.CRLURLs) != 1 || v.CRLURLs[0] != "http://pki.example.test/crl" {
					return fmt.Errorf("crl_urls = %v", v.CRLURLs)
				}
				if time.Duration(v.Timeout) != 5*time.Second {
					return fmt.Errorf("timeout = %v", time.Duration(v.Timeout))
				}
				return nil
			},
		},
		{
			// inline paths are shorthand for crl_file
			name:  "inline files and subdirectives combine",
			input: "crl /etc/caddy/a.crl {\n\tcrl_file /x.crl\n}",
			want: func(v *CRLVerifier) error {
				if len(v.CRLFiles) != 2 || v.CRLFiles[0] != "/etc/caddy/a.crl" || v.CRLFiles[1] != "/x.crl" {
					return fmt.Errorf("crl_files = %v", v.CRLFiles)
				}
				return nil
			},
		},
		{name: "unknown subdirective", input: "crl {\n\tfollow_the_peer yes\n}", wantErr: true},
		{name: "a removed option is refused by name", input: "crl {\n\tcheck_chain false\n}", wantErr: true},
		{name: "missing value", input: "crl {\n\tcrl_file\n}", wantErr: true},
		{name: "bad duration", input: "crl {\n\ttimeout tomorrow\n}", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tc.input)
			v := new(CRLVerifier)
			err := v.UnmarshalCaddyfile(d)
			if tc.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err == nil && tc.want != nil {
				if problem := tc.want(v); problem != nil {
					t.Error(problem)
				}
			}
		})
	}
}

func TestCRLVerifierDefaults(t *testing.T) {
	pki := newCRLTestPKI(t)
	path := writeCRLDER(t, "issuing.crl", pki.crl(t, crlOptions{number: 1}))

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	if got := v.client.Timeout; got != defaultCRLTimeout {
		t.Errorf("the fetch timeout defaults to %v, got %v", defaultCRLTimeout, got)
	}

	v = provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}, Timeout: caddy.Duration(5 * time.Second)})
	if got := v.client.Timeout; got != 5*time.Second {
		t.Errorf("a configured timeout should be used as given, got %v", got)
	}

	err := provisionCRLVerifierExpectError(t, &CRLVerifier{CRLFiles: []string{path}, Timeout: caddy.Duration(-time.Second)})
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Errorf("a negative timeout should be refused by name, got: %v", err)
	}
}

// TestCRLVerifierLargeListCost measures what a very large CRL costs to hold and
// load, the reason for defaultCRLMaxSize. It is skipped unless CRL_COST_MEASURE
// names a count of revoked serials:
//
//	CRL_COST_MEASURE=1000000 go test -run TestCRLVerifierLargeListCost ./modules/caddytls/ -v
func TestCRLVerifierLargeListCost(t *testing.T) {
	const env = "CRL_COST_MEASURE"
	raw := os.Getenv(env)
	if raw == "" {
		t.Skipf("set %s to the number of revoked serials to mint, e.g. 1000000", env)
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		t.Fatalf("%s=%q is not a positive number of entries", env, raw)
	}

	pki := newCRLTestPKI(t)
	at := time.Now().UTC().Add(-time.Hour)
	revoked := make([]x509.RevocationListEntry, n)
	for i := range revoked {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			t.Fatalf("generating a serial: %v", err)
		}
		buf[0] &= 0x7f // positive, and still sixteen bytes when minimally encoded
		revoked[i] = x509.RevocationListEntry{SerialNumber: new(big.Int).SetBytes(buf), RevocationTime: at}
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "large.crl")
	if err := os.WriteFile(path, createCRL(t, pki.issCert, pki.issKey, crlOptions{revoked: revoked}), 0o600); err != nil {
		t.Fatalf("writing the list: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("statting the list: %v", err)
	}

	// drop the minted entries so only the loaded list is measured
	revoked = nil
	before := heapAllocated()

	start := time.Now()
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	load := time.Since(start)
	after := heapAllocated()

	set := v.current()
	if set == nil {
		t.Fatal("nothing was loaded")
	}
	var indexed int
	for _, lists := range set.byIssuer {
		for _, list := range lists {
			indexed += len(list.revoked)
		}
	}
	if indexed != n {
		t.Errorf("%d serials were published, %d were indexed", n, indexed)
	}

	const mib = float64(1 << 20)
	t.Logf("%d revoked serials: %.1f MiB of DER, loaded in %s, %.1f MiB retained (of which %.1f MiB is the body kept for signature checks)",
		n, float64(info.Size())/mib, load.Round(time.Millisecond),
		float64(int64(after)-int64(before))/mib, float64(info.Size())/mib)
}
