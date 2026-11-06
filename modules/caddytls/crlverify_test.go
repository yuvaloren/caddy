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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"
)

func TestCRLVerifierRevocation(t *testing.T) {
	pki := newCRLTestPKI(t)
	good, _ := pki.leaf(t, 1000)
	bad, _ := pki.leaf(t, 1001)

	for _, tc := range []struct {
		name    string
		revoked []x509.RevocationListEntry
		wantErr bool
	}{
		{name: "nothing revoked", wantErr: false},
		{name: "the client certificate is revoked", revoked: []x509.RevocationListEntry{revokedEntry(1001)}, wantErr: true},
		{name: "some other certificate is revoked", revoked: []x509.RevocationListEntry{revokedEntry(2002)}, wantErr: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCRLDER(t, "issuing.crl", pki.crl(t, crlOptions{number: 1, revoked: tc.revoked}))
			v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

			pki.requireAdmitted(t, v, good, "a certificate which is not revoked was refused")
			if tc.wantErr {
				pki.requireRefused(t, v, bad, "expected a revoked certificate to be refused, but it was admitted")
			} else {
				pki.requireAdmitted(t, v, bad, "a certificate which no CRL mentions should be served")
			}
		})
	}
}

func TestCRLVerifierNoCertificateAndNoChain(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 5000)
	path := writeCRLDER(t, "issuing.crl", pki.crl(t, crlOptions{number: 1}))

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	// presenting no certificate is the client_auth mode's business
	if err := v.VerifyClientCertificate(nil, nil); err != nil {
		t.Errorf("presenting no certificate should be left to the mode, got: %v", err)
	}

	// a presented certificate with no verified chain must not pass
	if err := v.VerifyClientCertificate(rawDER(t, client), nil); err == nil {
		t.Error("a presented certificate with no verified chain was admitted")
	}
	if err := v.VerifyClientCertificate(rawDER(t, client), [][]*x509.Certificate{}); err == nil {
		t.Error("a presented certificate with an empty set of chains was admitted")
	}
}

func TestCRLVerifierUnprovisionedRefuses(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 5500)

	v := new(CRLVerifier)
	pki.requireRefused(t, v, client, "a verifier which never loaded a CRL admitted a certificate")
}

func TestCRLVerifierForgedCRL(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 6000)

	// names the issuing CA but is signed by the root's key
	forged := writeCRLDER(t, "forged.crl", pki.crl(t, crlOptions{issuer: pki.issCert, signer: pki.rootKey, number: 99}))

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{forged}})
	err := pki.requireRefused(t, v, client, "a CRL which does not verify against the chain was relied upon")
	if !strings.Contains(err.Error(), "does not verify against the verified chain") {
		t.Errorf("expected a signature failure to be named, got: %v", err)
	}

	t.Run("signed by an unrelated key", func(t *testing.T) {
		strangerKey := newTestKey(t)
		path := writeCRLDER(t, "forged.crl", pki.crl(t, crlOptions{issuer: pki.issCert, signer: strangerKey, number: 99}))
		v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
		pki.requireRefused(t, v, client, "a CRL signed by an unrelated key was relied upon")
	})

	t.Run("a list whose issuer is not in the chain covers nothing", func(t *testing.T) {
		// the issuer is not in the chain, so the refusal is about coverage, not a signature
		v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{forged}})
		chain := [][]*x509.Certificate{{client, pki.rootCert}}
		err := v.VerifyClientCertificate(rawDER(t, client), chain)
		if err == nil {
			t.Fatal("a CRL was relied upon with no issuer certificate in the chain")
		}
		if !strings.Contains(err.Error(), "no configured CRL covers") {
			t.Errorf("expected a refusal about missing coverage, got: %v", err)
		}
	})
}

func TestCRLVerifierNotYetValid(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 8000)

	path := writeCRLDER(t, "issuing.crl", pki.crl(t, crlOptions{number: 1, thisUpdate: time.Now().Add(time.Hour)}))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	err := pki.requireRefused(t, v, client, "a CRL which is not valid yet was relied upon")
	if !strings.Contains(err.Error(), "not valid until") {
		t.Errorf("expected the reason to name validity, got: %v", err)
	}
}

func TestCRLVerifierHandshake(t *testing.T) {
	pki := newCRLTestPKI(t)
	clientCert, clientKey := pki.leaf(t, 20000)
	clientPair := tlsCert(t, clientCert, clientKey)
	serverPair := pki.serverLeaf(t)

	for _, version := range []struct {
		name     string
		min, max uint16
	}{
		{name: "tls 1.3", min: tls.VersionTLS13, max: tls.VersionTLS13},
		{name: "tls 1.2", min: tls.VersionTLS12, max: tls.VersionTLS12},
	} {
		t.Run(version.name, func(t *testing.T) {
			// each version gets its own list, since the run below revokes the client
			crlPath := filepath.Join(t.TempDir(), "issuing.crl")
			writeCRL := func(entries ...x509.RevocationListEntry) {
				t.Helper()
				der := pki.crl(t, crlOptions{number: 1, revoked: entries})
				if err := os.WriteFile(crlPath, pem.EncodeToMemory(&pem.Block{Type: pemTypeCRL, Bytes: der}), 0o600); err != nil {
					t.Fatalf("writing the CRL: %v", err)
				}
			}
			writeCRL()

			v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{crlPath}})

			var resumed bool
			server := &tls.Config{
				Certificates: []tls.Certificate{serverPair},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    pki.pool,
				MinVersion:   version.min,
				MaxVersion:   version.max,
				// client_auth installs the verifier in VerifyConnection, which also runs
				// on resumed connections
				VerifyConnection: func(cs tls.ConnectionState) error {
					resumed = cs.DidResume
					return v.VerifyClientCertificate(rawDER(t, cs.PeerCertificates...), cs.VerifiedChains)
				},
			}
			client := &tls.Config{
				Certificates:       []tls.Certificate{clientPair},
				RootCAs:            pki.pool,
				MinVersion:         version.min,
				MaxVersion:         version.max,
				ServerName:         "localhost",
				ClientSessionCache: tls.NewLRUClientSessionCache(8),
			}

			// the second connection must resume, so the denial below is on a resumed session
			if err := handshake(server, client); err != nil {
				t.Fatalf("the first connection failed: %v", err)
			}
			if resumed {
				t.Fatal("the first connection should not have resumed")
			}
			if err := handshake(server, client); err != nil {
				t.Fatalf("the second connection failed: %v", err)
			}
			if !resumed {
				t.Fatal("the second connection did not resume, so this test would not prove anything")
			}

			writeCRL(revokedEntry(20000))
			if _, err := v.reload(false); err != nil {
				t.Fatalf("reloading the CRL: %v", err)
			}

			err := handshake(server, client)
			if err == nil {
				t.Fatal("a revoked certificate was admitted by the handshake")
			}
			// crypto/tls answers a VerifyConnection failure with bad_certificate
			if !resumed || !strings.Contains(err.Error(), "bad certificate") {
				t.Errorf("expected a resumed session refused with a bad certificate, got resumed=%v: %v", resumed, err)
			}
		})
	}
}

func TestCRLVerifierMultipleChains(t *testing.T) {
	// a cross-signed intermediate: one key, two roots, two valid chains
	rootAKey, rootACert := mintCA(t, "Cross Root A", caPair{}, nil)
	rootBKey, rootBCert := mintCA(t, "Cross Root B", caPair{}, nil)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	_, interA := mintCA(t, "Cross Signed Issuing CA", caPair{rootACert, rootAKey}, interKey)
	_, interB := mintCA(t, "Cross Signed Issuing CA", caPair{rootBCert, rootBKey}, interKey)
	if interA.SerialNumber.Cmp(interB.SerialNumber) == 0 {
		t.Fatal("the two cross-signed certificates share a serial number")
	}

	clientCert, _ := mintLeafUnder(t, 21000, interA, interKey)

	crlA := writeCRLDER(t, "root-a.crl", crlSignedBy(t, rootACert, rootAKey, interA.SerialNumber))
	crlB := writeCRLDER(t, "root-b.crl", crlSignedBy(t, rootBCert, rootBKey))

	chains := [][]*x509.Certificate{
		{clientCert, interA, rootACert},
		{clientCert, interB, rootBCert},
	}
	raw := rawDER(t, clientCert, interA, interB)

	for _, tc := range []struct {
		name         string
		sources      []string
		wantErr      bool
		wantContains string // expected in the refusal
	}{
		{
			// neither path is covered, so refused as uncovered before revocation is reached
			name:         "the other path has no crl",
			sources:      []string{crlA},
			wantErr:      true,
			wantContains: "no configured CRL covers",
		},
		{
			// a clean path does not rescue a revoked one: every path must be clean
			name:         "the other path has a crl which does not revoke it",
			sources:      []string{crlA, crlB, writeCRLDER(t, "issuing-b.crl", crlSignedBy(t, interB, interKey))},
			wantErr:      true,
			wantContains: "revoked",
		},
		{
			name: "both paths revoked it",
			sources: []string{crlA,
				writeCRLDER(t, "root-b-revoked.crl", crlSignedBy(t, rootBCert, rootBKey, interB.SerialNumber)),
				// both paths covered to the leaf, so the refusal is the revocation
				writeCRLDER(t, "issuing-a.crl", crlSignedBy(t, interA, interKey)),
				writeCRLDER(t, "issuing-b.crl", crlSignedBy(t, interB, interKey))},
			wantErr:      true,
			wantContains: "revoked",
		},
		{
			// every path covered and clean; a verifier that refuses everything fails here
			name: "neither path revoked it",
			sources: []string{
				writeCRLDER(t, "root-a-clean.crl", crlSignedBy(t, rootACert, rootAKey)),
				writeCRLDER(t, "root-b-clean.crl", crlSignedBy(t, rootBCert, rootBKey)),
				writeCRLDER(t, "issuing-a.crl", crlSignedBy(t, interA, interKey)),
				writeCRLDER(t, "issuing-b.crl", crlSignedBy(t, interB, interKey)),
			},
			wantErr: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: tc.sources})

			err := v.VerifyClientCertificate(raw, chains)
			if tc.wantErr && err == nil {
				t.Error("expected the connection to be refused")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected admission, got: %v", err)
			}
			if tc.wantContains != "" && err != nil && !strings.Contains(err.Error(), tc.wantContains) {
				t.Errorf("expected the refusal to contain %q, got: %v", tc.wantContains, err)
			}
		})
	}
}

// TestCRLVerifierHandshakeChainFromThePool checks an issuing CA revoked by its
// root. What gets checked depends on the chain crypto/tls builds, which stops
// at the first certificate the pool holds.
func TestCRLVerifierHandshakeChainFromThePool(t *testing.T) {
	pki := newCRLTestPKI(t)
	clientCert, clientKey := pki.leaf(t, 22000)
	serverPair := pki.serverLeaf(t)

	rootOnly := x509.NewCertPool()
	rootOnly.AddCert(pki.rootCert)

	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.crl")
	writeRootCRL := func(serials ...*big.Int) {
		t.Helper()
		der := crlSignedBy(t, pki.rootCert, pki.rootKey, serials...)
		if err := os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: pemTypeCRL, Bytes: der}), 0o600); err != nil {
			t.Fatalf("writing the root CRL: %v", err)
		}
	}
	writeRootCRL()
	issuingPath := writeCRLDER(t, "issuing.crl", pki.crl(t, crlOptions{number: 1}))
	writeIssuingCRL := func(entries ...x509.RevocationListEntry) {
		t.Helper()
		der := pki.crl(t, crlOptions{number: 2, revoked: entries})
		if err := os.WriteFile(issuingPath, pem.EncodeToMemory(&pem.Block{Type: pemTypeCRL, Bytes: der}), 0o600); err != nil {
			t.Fatalf("writing the issuing CRL: %v", err)
		}
	}

	full := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{rootPath, issuingPath}})

	handshakeWith := func(verifier *CRLVerifier, pool *x509.CertPool, sendIntermediate bool, depth, chains *int, said *error) error {
		t.Helper()
		server := &tls.Config{
			Certificates: []tls.Certificate{serverPair},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			VerifyConnection: func(cs tls.ConnectionState) error {
				*depth, *chains = 0, len(cs.VerifiedChains)
				if *chains > 0 {
					*depth = len(cs.VerifiedChains[0])
				}
				*said = verifier.VerifyClientCertificate(rawDER(t, cs.PeerCertificates...), cs.VerifiedChains)
				return *said
			},
		}
		sent := [][]byte{clientCert.Raw}
		if sendIntermediate {
			// a client holding only its own certificate sends the leaf alone
			sent = append(sent, pki.issCert.Raw)
		}
		client := &tls.Config{
			Certificates: []tls.Certificate{{Certificate: sent, PrivateKey: clientKey}},
			// under test is how the server builds its client's chain from its own pool
			RootCAs:    pki.pool,
			ServerName: "localhost",
		}
		return handshake(server, client)
	}

	t.Run("a root in the pool is enough to check the ca under it", func(t *testing.T) {
		var depth, chains int
		var said error
		if err := handshakeWith(full, rootOnly, true, &depth, &chains, &said); err != nil {
			t.Fatalf("the connection failed before anything was revoked: %v (verifier said: %v)", err, said)
		}
		if depth < 3 {
			t.Errorf("expected the chain to be built through the issuing CA to the root, got depth %d", depth)
		}

		writeRootCRL(pki.issCert.SerialNumber)
		if _, err := full.reload(false); err != nil {
			t.Fatalf("reloading the root CRL: %v", err)
		}

		err := handshakeWith(full, rootOnly, true, &depth, &chains, &said)
		if err == nil {
			t.Fatal("a certificate under an issuing CA revoked by its root was admitted")
		}
		if said == nil || !strings.Contains(said.Error(), "revoked") ||
			!strings.Contains(said.Error(), pki.issCert.Subject.CommonName) {
			t.Errorf("expected the refusal to name the revoked issuing CA, got: %v", said)
		}
		if !strings.Contains(err.Error(), "bad certificate") {
			t.Errorf("expected the peer to report a bad certificate, got: %v", err)
		}

		// un-revoke, so the refusal above was not a setup problem
		writeRootCRL()
		if _, err := full.reload(false); err != nil {
			t.Fatalf("reloading the root CRL again: %v", err)
		}
		if err := handshakeWith(full, rootOnly, true, &depth, &chains, &said); err != nil {
			t.Errorf("the connection should work once the CA is no longer revoked: %v (verifier said: %v)", err, said)
		}
	})

	t.Run("a bundle in the pool still reaches the root for a client that sends its ca", func(t *testing.T) {
		// root and issuing CA together: Go offers both the short and the full chain
		var depth, chains int
		var said error
		if err := handshakeWith(full, pki.pool, true, &depth, &chains, &said); err != nil {
			t.Fatalf("the connection failed before anything was revoked: %v (verifier said: %v)", err, said)
		}
		if chains < 2 {
			t.Errorf("expected crypto/tls to offer both the short and the full path, got %d chain(s)", chains)
		}

		writeRootCRL(pki.issCert.SerialNumber)
		if _, err := full.reload(false); err != nil {
			t.Fatalf("reloading the root CRL: %v", err)
		}
		err := handshakeWith(full, pki.pool, true, &depth, &chains, &said)
		if err == nil {
			t.Fatal("a certificate under an issuing CA revoked by its root was admitted through a bundle pool")
		}
		if said == nil || !strings.Contains(said.Error(), "revoked") {
			t.Errorf("expected the refusal to name a revocation, got: %v", said)
		}

		writeRootCRL()
		if _, err := full.reload(false); err != nil {
			t.Fatalf("reloading the root CRL again: %v", err)
		}
	})

	t.Run("a chain which stops at a directly trusted ca is checked only as far as it goes", func(t *testing.T) {
		// a client sending only its leaf gets a chain ending at the trusted issuing
		// CA, so the root's word about that CA is out of reach
		var depth, chains int
		var said error
		if err := handshakeWith(full, pki.pool, false, &depth, &chains, &said); err != nil {
			t.Fatalf("a leaf its own CA says nothing about should be served: %v (verifier said: %v)", err, said)
		}
		if chains != 1 || depth > 2 {
			t.Errorf("expected one chain ending at the trusted issuing CA, got %d chain(s) of depth %d", chains, depth)
		}

		writeIssuingCRL(revokedEntry(22000))
		if _, err := full.reload(false); err != nil {
			t.Fatalf("reloading the issuing CRL: %v", err)
		}
		err := handshakeWith(full, pki.pool, false, &depth, &chains, &said)
		if err == nil || said == nil || !strings.Contains(said.Error(), "revoked") {
			t.Errorf("expected the revoked leaf to be refused on a short chain, got: %v (verifier said: %v)", err, said)
		}

		// the CA's own revocation is enforced only on a chain which reaches the root
		writeIssuingCRL()
		writeRootCRL(pki.issCert.SerialNumber)
		if _, err := full.reload(false); err != nil {
			t.Fatalf("reloading both CRLs: %v", err)
		}
		if err := handshakeWith(full, pki.pool, false, &depth, &chains, &said); err != nil {
			t.Errorf("a short chain answers from the leaf's own list; it should be served, got: %v (verifier said: %v)", err, said)
		}
		if err := handshakeWith(full, pki.pool, true, &depth, &chains, &said); err == nil {
			t.Error("a certificate under an issuing CA revoked by its root was admitted through a bundle pool")
		}

		writeRootCRL()
		if _, err := full.reload(false); err != nil {
			t.Fatalf("reloading the root CRL again: %v", err)
		}
	})
}

// An uncovered refusal reaches only crypto/tls, which ends the handshake in
// silence, so the first refusal per issuer is a warning and later ones debug.
func TestCRLVerifierUncoveredRefusalIsAnnouncedOncePerIssuer(t *testing.T) {
	pki := newCRLTestPKI(t)
	leaf, _ := pki.leaf(t, 7452)

	// a list for the root and none for the issuing CA
	path := writeCRLDER(t, "root.crl", pki.crl(t, crlOptions{issuer: pki.rootCert, signer: pki.rootKey, number: 1}))

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	logs := observeLogs(t, v, zapcore.DebugLevel)

	raw, chains := rawDER(t, leaf), pki.chainsFor(leaf)
	for range 3 {
		requireRefused(t, v, raw, chains, "a certificate which no loaded CRL speaks for was admitted")
	}

	got := logs.FilterMessage("rejecting a certificate which no configured CRL covers").All()
	if len(got) != 3 {
		t.Fatalf("%d lines about the uncovered refusal, want one per connection", len(got))
	}
	if got[0].Level != zapcore.WarnLevel {
		t.Errorf("the first refusal was logged at %s, want a warning", got[0].Level)
	}
	for _, entry := range got[1:] {
		if entry.Level != zapcore.DebugLevel {
			t.Errorf("a later refusal was logged at %s, want debug so a busy server is not drowned", entry.Level)
		}
	}
	fields := got[0].ContextMap()
	if fields["subject"] != leaf.Subject.String() || fields["serial"] != leaf.SerialNumber.String() {
		t.Errorf("the refusal names %v / %v, want the refused certificate itself", fields["subject"], fields["serial"])
	}
	if fields["issuer"] != pki.issCert.Subject.String() {
		t.Errorf("the refusal blames issuer %v, want the CA which signed it (%s)", fields["issuer"], pki.issCert.Subject)
	}
}

// TestCRLVerifierDirectlyTrustedIssuer checks that a chain ending at a directly
// trusted issuing CA is checked only as far as it goes.
func TestCRLVerifierDirectlyTrustedIssuer(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 7700)

	rootCRL := createCRL(t, pki.rootCert, pki.rootKey, crlOptions{number: 1})
	path := writeLists(t, "issuing.crl", pki.crl(t, crlOptions{number: 1}), rootCRL)

	short := [][]*x509.Certificate{{client, pki.issCert}}
	full := pki.chainsToRoot(client)

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	if err := v.VerifyClientCertificate(rawDER(t, client), short); err != nil {
		t.Errorf("a chain which ends at a directly trusted CA should be checked only as far as it goes, got: %v", err)
	}
	if err := v.VerifyClientCertificate(rawDER(t, client), full); err != nil {
		t.Errorf("a complete chain with a list for every issuer should verify, got: %v", err)
	}

	// the root revoking the issuing CA bites only where the chain reaches the root
	revokedIssuer := createCRL(t, pki.rootCert, pki.rootKey, crlOptions{
		number:  2,
		revoked: []x509.RevocationListEntry{revokedEntry(pki.issCert.SerialNumber.Int64())},
	})
	badPath := writeLists(t, "issuing.crl", pki.crl(t, crlOptions{number: 1}), revokedIssuer)
	vetoed := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{badPath}})
	err := requireRefused(t, vetoed, rawDER(t, client), full, "an issuing CA its own root has revoked was served on a chain which reaches that root")
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("the refusal should say the issuing CA is revoked, got: %v", err)
	}
	if err := vetoed.VerifyClientCertificate(rawDER(t, client), short); err != nil {
		t.Errorf("the short chain cannot be asked about its own top, got: %v", err)
	}
}

// TestCRLVerifierSelfSignedClientCertificate checks that a self-signed top of
// chain answers only to its own list, so a root needs a current CRL.
func TestCRLVerifierSelfSignedClientCertificate(t *testing.T) {
	pki := newCRLTestPKI(t)
	_, selfID := mintCA(t, "Self-Signed Client", caPair{}, nil)
	path := writeCRLDER(t, "issuing.crl", pki.crl(t, crlOptions{number: 1}))

	t.Run("nothing loaded for its own name", func(t *testing.T) {
		raw, chain := rawDER(t, selfID), [][]*x509.Certificate{{selfID}}
		v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
		err := v.VerifyClientCertificate(raw, chain)
		if err == nil {
			t.Fatal("a certificate no CRL can cover was admitted")
		}
		if !strings.Contains(err.Error(), "no configured CRL covers") {
			t.Errorf("the refusal should say nothing covers its issuer, got: %v", err)
		}
	})

	client, _ := pki.leaf(t, 7470)

	t.Run("a root which revoked itself is refused at the top of a chain", func(t *testing.T) {
		rootList := writeCRLDER(t, "root.crl", crlSignedBy(t, pki.rootCert, pki.rootKey, pki.rootCert.SerialNumber))
		v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path, rootList}})
		requireRefused(t, v, rawDER(t, client), pki.chainsToRoot(client), "a root which revoked itself was accepted at the top of a chain")
	})

	t.Run("a complete chain with a current list for every issuer is served", func(t *testing.T) {
		cleanRoot := writeCRLDER(t, "root.crl", crlSignedBy(t, pki.rootCert, pki.rootKey))
		v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path, cleanRoot}})
		requireAdmitted(t, v, rawDER(t, client), pki.chainsToRoot(client), "a complete chain with a current list for every issuer should verify")
	})

	t.Run("a chain reaching a root with no list from it is refused by name", func(t *testing.T) {
		// a chain reaching the root with no list from it is uncovered, and says whose
		v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
		err := requireRefused(t, v, rawDER(t, client), pki.chainsToRoot(client), "the issuing CA was accepted with nothing saying whether its own key is still good")
		if !strings.Contains(err.Error(), pki.rootCert.Subject.CommonName) {
			t.Errorf("the refusal should name the missing coverage by its issuer, got: %v", err)
		}
	})
}

func TestCRLVerifierReportsARevocationOncePerConnection(t *testing.T) {
	rootAKey, rootACert := mintCA(t, "Report Root A", caPair{}, nil)
	rootBKey, rootBCert := mintCA(t, "Report Root B", caPair{}, nil)
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	_, interA := mintCA(t, "Report Issuing CA", caPair{rootACert, rootAKey}, interKey)
	_, interB := mintCA(t, "Report Issuing CA", caPair{rootBCert, rootBKey}, interKey)
	clientCert, _ := mintLeafUnder(t, 22000, interA, interKey)

	crlA := writeCRLDER(t, "report-a.crl", crlSignedBy(t, rootACert, rootAKey, interA.SerialNumber))
	crlB := writeCRLDER(t, "report-b.crl", crlSignedBy(t, rootBCert, rootBKey))
	issuingB := writeCRLDER(t, "report-issuing-b.crl", crlSignedBy(t, interB, interKey))

	chains := [][]*x509.Certificate{
		{clientCert, interA, rootACert},
		{clientCert, interB, rootBCert},
	}
	raw := rawDER(t, clientCert, interA, interB)

	for _, tc := range []struct {
		name        string
		sources     []string
		wantErr     bool
		wantReports int
	}{
		{
			// the same CA revoked on both paths, reported once for the connection
			name: "every path revoked it",
			sources: []string{
				crlA,
				writeCRLDER(t, "report-b-revoked.crl", crlSignedBy(t, rootBCert, rootBKey, interB.SerialNumber)),
				writeCRLDER(t, "report-issuing-a.crl", crlSignedBy(t, interA, interKey)),
				issuingB,
			},
			wantErr:     true,
			wantReports: 1,
		},
		{
			name:        "another path is clean",
			sources:     []string{crlA, crlB, issuingB},
			wantErr:     true,
			wantReports: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: tc.sources})

			logs := observeLogs(t, v, zapcore.ErrorLevel)

			err := v.VerifyClientCertificate(raw, chains)
			if tc.wantErr && err == nil {
				t.Fatal("expected the connection to be refused")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected the connection to be admitted, got: %v", err)
			}

			if got := logs.FilterMessage("rejecting a revoked client certificate").Len(); got != tc.wantReports {
				t.Errorf("%d error lines about a revocation, want %d", got, tc.wantReports)
			}
			// the report names the revoked issuing CA, not the clean leaf
			wantSerials := map[string]bool{
				interA.SerialNumber.String(): true,
				interB.SerialNumber.String(): true,
			}
			for _, entry := range logs.All() {
				data := entry.ContextMap()
				if serial, _ := data["serial"].(string); !wantSerials[serial] {
					t.Errorf("the log names serial %v, which is neither revoked certificate", serial)
				}
				if subject, _ := data["subject"].(string); subject == "" {
					t.Errorf("the log carries no subject: %v", data)
				}
			}
		})
	}
}

// TestCRLVerifierDirectlyTrustedCertificateWhichIsNotSelfSigned checks a
// certificate in the trust pool presented as an identity: nothing above it can
// cover it, and the refusal must not call it self-signed.
func TestCRLVerifierDirectlyTrustedCertificateWhichIsNotSelfSigned(t *testing.T) {
	pki := newCRLTestPKI(t)
	path := writeCRLDER(t, "issuing.crl", pki.crl(t, crlOptions{number: 1}))
	raw, chain := rawDER(t, pki.issCert), [][]*x509.Certificate{{pki.issCert}}

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	err := v.VerifyClientCertificate(raw, chain)
	if err == nil {
		t.Fatal("a certificate which no CRL can cover was admitted")
	}
	if !strings.Contains(err.Error(), "trusted directly") {
		t.Errorf("the refusal should say the certificate is trusted directly, got: %v", err)
	}
	if strings.Contains(err.Error(), "self-signed") {
		t.Errorf("the refusal calls it self-signed, which it is not: %v", err)
	}
	if !strings.Contains(err.Error(), "issue client certificates from a CA") {
		t.Errorf("the refusal should say what to do instead, got: %v", err)
	}
}

func TestCRLVerifierNotYetValidListDoesNotHideAnOlderOne(t *testing.T) {
	// a not-yet-valid list from a publisher with a fast clock must not hide the
	// current one in the same file
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 7840)
	good, _ := pki.leaf(t, 7841)

	notYet := pki.crl(t, crlOptions{
		number:     2,
		thisUpdate: time.Now().Add(10 * time.Minute),
		nextUpdate: time.Now().Add(72 * time.Hour),
	})
	current := pki.crl(t, crlOptions{number: 1, revoked: []x509.RevocationListEntry{revokedEntry(7840)}})
	path := writeLists(t, "issuing.crl", notYet, current)

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	err := pki.requireRefused(t, v, client, "a serial its CA has revoked was served")
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("the older in-date list should be the one which answers, got: %v", err)
	}
	pki.requireAdmitted(t, v, good, "a serial the older list does not revoke should be served")
}

// TestCRLVerifierAnUnusableCRLSaysWhyOutLoud checks that a loaded but unusable
// list is logged once at warning and then at debug.
func TestCRLVerifierAnUnusableCRLSaysWhyOutLoud(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 7843)

	// a copy of the issuing CA with another subject key id, so the list's
	// authority key id names a key the chain does not hold
	retiredKey := *pki.issCert
	retiredKey.SubjectKeyId = []byte{0x01, 0x02, 0x03}

	for _, tc := range []struct {
		name   string
		list   []byte
		want   string // in the refusal
		reason string // in the log line
	}{
		{
			name: "a list past its nextUpdate",
			list: pki.crl(t, crlOptions{
				number:     1,
				thisUpdate: time.Now().Add(-96 * time.Hour),
				nextUpdate: time.Now().Add(-time.Hour),
			}),
			want:   "passed its nextUpdate",
			reason: "passed its nextUpdate",
		},
		{
			name: "a list which has not begun",
			list: pki.crl(t, crlOptions{
				number:     1,
				thisUpdate: time.Now().Add(10 * time.Minute),
				nextUpdate: time.Now().Add(72 * time.Hour),
			}),
			want:   "not valid until",
			reason: "not valid until",
		},
		{
			name:   "a list the chain did not sign",
			list:   pki.crl(t, crlOptions{issuer: pki.issCert, signer: pki.rootKey, number: 1}),
			want:   "does not verify",
			reason: "is not valid:",
		},
		{
			name:   "every list set aside",
			list:   pki.crl(t, crlOptions{number: 1, issuer: &retiredKey}),
			want:   "cannot be relied on",
			reason: "every list for it was set aside",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{writeCRLDER(t, "issuing.crl", tc.list)}})

			logs := observeLogs(t, v, zapcore.DebugLevel)

			err := pki.requireRefused(t, v, client, "a certificate under an unusable CRL was served")
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected the refusal to say %q, got: %v", tc.want, err)
			}

			const message = "rejecting a certificate whose CRL cannot be relied on"
			if got := logs.FilterMessage(message).FilterLevelExact(zapcore.WarnLevel).Len(); got != 1 {
				t.Errorf("the unusable CRL was reported loudly %d times, want once", got)
			}
			said := logs.FilterMessage(message).All()
			if len(said) > 0 {
				if reason := fmt.Sprint(said[0].ContextMap()["reason"]); !strings.Contains(reason, tc.reason) {
					t.Errorf("expected the logged reason to contain %q, got: %s", tc.reason, reason)
				}
			}

			// the same condition again is not a new warning, but stays visible at debug
			pki.requireRefused(t, v, client, "a certificate under an unusable CRL was served")
			if got := logs.FilterMessage(message).FilterLevelExact(zapcore.WarnLevel).Len(); got != 1 {
				t.Errorf("an unchanged condition was announced loudly again: %d lines", got)
			}
			if logs.FilterMessage(message).FilterLevelExact(zapcore.DebugLevel).Len() == 0 {
				t.Error("the standing condition should stay visible at debug")
			}
		})
	}
}

// TestCRLVerifierExpiryIsStrict checks that a list past its nextUpdate is
// refused in its own words, as OpenSSL does with "CRL has expired".
func TestCRLVerifierExpiryIsStrict(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 7860)

	lapsed := pki.crl(t, crlOptions{
		number:     1,
		thisUpdate: time.Now().Add(-96 * time.Hour),
		nextUpdate: time.Now().Add(-time.Hour),
	})
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{writeCRLDER(t, "lapsed.crl", lapsed)}})
	err := pki.requireRefused(t, v, client, "a certificate was served on the word of a CA which stopped speaking an hour ago")
	if !strings.Contains(err.Error(), "nextUpdate") {
		t.Errorf("the refusal should say the list passed its nextUpdate, got: %v", err)
	}

	// only drift within crlClockSkew is tolerated
	nearMiss := pki.crl(t, crlOptions{
		number:     2,
		thisUpdate: time.Now().Add(-time.Hour),
		nextUpdate: time.Now().Add(-time.Minute),
	})
	v = provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{writeCRLDER(t, "near-miss.crl", nearMiss)}})
	pki.requireAdmitted(t, v, client, "a list a minute past its nextUpdate is inside the tolerated clock drift")

	beyondSkew := pki.crl(t, crlOptions{
		number:     3,
		thisUpdate: time.Now().Add(-time.Hour),
		nextUpdate: time.Now().Add(-(crlClockSkew + time.Minute)),
	})
	v = provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{writeCRLDER(t, "beyond-skew.crl", beyondSkew)}})
	pki.requireRefused(t, v, client, "a list past the tolerated clock drift was still believed")

	// RFC 5280 lets a list with no nextUpdate stay current indefinitely
	timeless := pki.crl(t, crlOptions{number: 4, noNextUpdate: true})
	v = provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{writeCRLDER(t, "timeless.crl", timeless)}})
	pki.requireAdmitted(t, v, client, "a list without nextUpdate should remain current")
}

func TestIssuerOf(t *testing.T) {
	// the names must differ, or every certificate looks self-issued
	leaf := &x509.Certificate{RawSubject: []byte("client"), RawIssuer: []byte("issuing")}
	intermediate := &x509.Certificate{RawSubject: []byte("issuing"), RawIssuer: []byte("root")}
	root := &x509.Certificate{RawSubject: []byte("root"), RawIssuer: []byte("root")}
	chain := []*x509.Certificate{leaf, intermediate, root}

	if got := issuerOf(chain, 0); got != intermediate {
		t.Error("the issuer of the leaf is not the next certificate in the chain")
	}
	if got := issuerOf(chain, 1); got != root {
		t.Error("the issuer of the intermediate is not the next certificate in the chain")
	}
	// a self-issued last certificate is its own issuer: a self-signed root, or a
	// re-keyed CA in the trust pool
	if got := issuerOf(chain, 2); got != root {
		t.Error("a self-issued last certificate should be its own issuer")
	}

	if got := issuerOf([]*x509.Certificate{leaf, intermediate}, 1); got != nil {
		t.Error("a last certificate which is not self-issued should have no issuer in the chain")
	}
}

// TestCRLVerifierIssuerOfNamesWhoSpeaksForWhom checks which certificate
// answers for which.
func TestCRLVerifierIssuerOfNamesWhoSpeaksForWhom(t *testing.T) {
	pki := newCRLTestPKI(t)
	leaf, _ := pki.leaf(t, 7850)

	short := []*x509.Certificate{leaf, pki.issCert}
	if got := issuerOf(short, 0); got != pki.issCert {
		t.Error("the certificate above a leaf should be the one which speaks for it")
	}
	if got := issuerOf(short, 1); got != nil {
		t.Errorf("a chain ends where its last certificate's issuer is not in it, got %v", got)
	}

	full := pki.chainsToRoot(leaf)[0]
	if got := issuerOf(full, 2); got != pki.rootCert {
		t.Error("a self-signed certificate at the top of a chain should answer for itself")
	}

	// self-issued is not self-signed: a CA re-keyed in place keeps its name
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7851),
		Subject:               pki.rootCert.Subject,
		Issuer:                pki.rootCert.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	reKeyed := createCert(t, template, pki.rootCert, key.Public(), pki.rootKey)
	if !bytes.Equal(reKeyed.RawSubject, reKeyed.RawIssuer) {
		t.Fatal("the test certificate is not self-issued, so it proves nothing")
	}
	if err := reKeyed.CheckSignatureFrom(reKeyed); err == nil {
		t.Fatal("the test certificate signs itself, so it is not the case under test")
	}
	// issuerOf goes by name; the signature check keeps the old key's list out
	if got := issuerOf([]*x509.Certificate{leaf, reKeyed}, 1); got != reKeyed {
		t.Errorf("a self-issued certificate at the top of a chain should answer for its own name, got %v", got)
	}
}

// BenchmarkVerifyClientCertificate measures one check as the list grows. The
// signature verdict is remembered after the first check, so this is steady state.
func BenchmarkVerifyClientCertificate(b *testing.B) {
	pki := newCRLTestPKI(b)
	client, _ := pki.leaf(b, 7860)

	for _, entries := range []int{0, 1000, 20000} {
		b.Run(fmt.Sprintf("revoked=%d", entries), func(b *testing.B) {
			var revoked []x509.RevocationListEntry
			for i := range entries {
				revoked = append(revoked, revokedEntry(int64(100_000+i)))
			}
			path := writeCRLDER(b, "issuing.crl", pki.crl(b, crlOptions{number: 1, revoked: revoked}))
			v := provisionCRLVerifier(b, &CRLVerifier{CRLFiles: []string{path}})
			raw, chains := rawDER(b, client), pki.chainsFor(client)

			b.ReportAllocs()
			for b.Loop() {
				if err := v.VerifyClientCertificate(raw, chains); err != nil {
					b.Fatalf("a certificate which is not revoked was refused: %v", err)
				}
			}
		})
	}
}
