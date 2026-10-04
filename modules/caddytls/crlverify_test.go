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

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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

			if err := v.VerifyClientCertificate(rawDER(t, good), pki.chainsFor(good)); err != nil {
				t.Errorf("a certificate which is not revoked was refused: %v", err)
			}
			err := v.VerifyClientCertificate(rawDER(t, bad), pki.chainsFor(bad))
			if tc.wantErr && err == nil {
				t.Error("expected a revoked certificate to be refused, but it was admitted")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected admission, got: %v", err)
			}
		})
	}
}

func TestCRLVerifierNoCertificateAndNoChain(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 5000)
	path := writeCRLDER(t, "issuing.crl", pki.crl(t, crlOptions{number: 1}))

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	// Whether a client may present no certificate at all is the client_auth mode's business.
	if err := v.VerifyClientCertificate(nil, nil); err != nil {
		t.Errorf("presenting no certificate should be left to the mode, got: %v", err)
	}

	// A presented certificate with no verified chain must not pass: under a mode which does not
	// build chains, and under verify_if_given for a certificate which does not verify, this is
	// the only place that can be noticed.
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
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err == nil {
		t.Error("a verifier which never loaded a CRL admitted a certificate")
	}
}

func TestCRLVerifierForgedCRL(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 6000)

	// A CRL which names the issuing CA but is signed by some other key. It claims the issuer, so
	// it cannot be waved through as "no CRL for this issuer", and it must not clear a revocation
	// either: an empty list signed by nobody is exactly what makes a revoked certificate look
	// valid.
	forged := writeCRLDER(t, "forged.crl", pki.crl(t, crlOptions{issuer: pki.issCert, signer: pki.rootKey, number: 99}))

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{forged}})
	err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client))
	if err == nil {
		t.Fatal("a CRL which does not verify against the chain was relied upon")
	}
	if !strings.Contains(err.Error(), "does not verify against the verified chain") {
		t.Errorf("expected a signature failure to be named, got: %v", err)
	}

	t.Run("signed by an unrelated key", func(t *testing.T) {
		strangerKey := newTestKey(t)
		path := writeCRLDER(t, "forged.crl", pki.crl(t, crlOptions{issuer: pki.issCert, signer: strangerKey, number: 99}))
		v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
		if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err == nil {
			t.Fatal("a CRL signed by an unrelated key was relied upon")
		}
	})

	t.Run("a list whose issuer is not in the chain covers nothing", func(t *testing.T) {
		// A CRL which claims a name, with a chain which does not hold that certificate: there is
		// nothing to anchor it on. No list is reached, so no signature is asked about — what this
		// pins is that an issuer the chain does not carry leaves no coverage rather than borrowing
		// another CA's list, which is why the refusal is about coverage and not about a signature.
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

	err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client))
	if err == nil {
		t.Fatal("a CRL which is not valid yet was relied upon")
	}
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
			// Each version gets its own list and its own verifier: the run below revokes the
			// client's serial, and a second version which inherited that file would refuse the
			// connection for the wrong reason.
			crlPath := filepath.Join(t.TempDir(), "issuing.crl")
			writeCRL := func(entries ...x509.RevocationListEntry) {
				t.Helper()
				der := pki.crl(t, crlOptions{number: 1, revoked: entries})
				if err := os.WriteFile(crlPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o600); err != nil {
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
				// This is how client_auth installs a verifier: the check runs in VerifyConnection,
				// which crypto/tls calls on every connection, resumed ones included. connpolicy.go
				// moves an existing VerifyPeerCertificate hook into VerifyConnection for this reason.
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

			// Before revocation: two connections, the second of which must resume, so that a later
			// denial cannot be explained away as a fresh full handshake.
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

			// Now revoke and reconnect, on the resumed session.
			writeCRL(revokedEntry(20000))
			if _, err := v.reload(false); err != nil {
				t.Fatalf("reloading the CRL: %v", err)
			}

			err := handshake(server, client)
			if err == nil {
				t.Fatal("a revoked certificate was admitted by the handshake")
			}
			// crypto/tls answers any VerifyConnection failure with bad_certificate; and the denial must
			// arrive on a resumed session, else it would only prove that fresh handshakes are checked.
			if !resumed || !strings.Contains(err.Error(), "bad certificate") {
				t.Errorf("expected a resumed session refused with a bad certificate, got resumed=%v: %v", resumed, err)
			}
		})
	}
}

func TestCRLVerifierMultipleChains(t *testing.T) {
	// A cross-signed intermediate: one key with a certificate from each of two roots, so that one
	// client certificate has two valid chains. Revoking it on one path and taking the other is
	// what any-chain semantics mean, so this pins the behaviour instead of leaving it to chance.
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
		wantContains string // in the refusal, so that a verifier which refuses everything passes for the right reason
	}{
		{
			// Only the cross-signing root of path A published a list, so neither path is covered and
			// the leaf is refused as uncovered before either intermediate is examined — which is what
			// wantContains pins. Coverage of every path is the precondition; revocation never gets
			// to be the tie-breaker here.
			name:         "the other path has no crl",
			sources:      []string{crlA},
			wantErr:      true,
			wantContains: "no configured CRL covers",
		},
		{
			// Chain B fully covered and clean. It does not rescue chain A: every path has to be
			// clean, because the shortest path is always clean once a pool holds an issuing CA and
			// its root together — admitting on that would leave nothing able to refuse. Revoking a
			// cross-signed CA therefore means publishing for every path, as here.
			name:         "the other path has a crl which does not revoke it",
			sources:      []string{crlA, crlB, writeCRLDER(t, "issuing-b.crl", crlSignedBy(t, interB, interKey))},
			wantErr:      true,
			wantContains: "revoked",
		},
		{
			// Revoked on both paths, refused whatever else is true.
			name: "both paths revoked it",
			sources: []string{crlA,
				writeCRLDER(t, "root-b-revoked.crl", crlSignedBy(t, rootBCert, rootBKey, interB.SerialNumber)),
				// Both paths covered down to the leaf, so that what refuses here is the
				// revocation of the intermediate and not a gap in coverage.
				writeCRLDER(t, "issuing-a.crl", crlSignedBy(t, interA, interKey)),
				writeCRLDER(t, "issuing-b.crl", crlSignedBy(t, interB, interKey))},
			wantErr:      true,
			wantContains: "revoked",
		},
		{
			// Every path covered and clean. Without this row the test is satisfied by a
			// verifier which refuses everything, which is the failure mode an operator feels as
			// a locked listener rather than the one it guards against.
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

// TestCRLVerifierHandshakeChainFromThePool is the shape of the outage this module exists to
// prevent — an issuing CA revoked by its own root while every end-entity certificate it issued
// still looks clean — and it is an integration test because what gets checked depends on how
// crypto/tls assembles the chain, which is not something the module controls.
//
// What the trust pool holds turns out to be most of the story. A client that sends its
// intermediate reaches the root whether or not the issuing CA is also in the pool, so everything in
// the path is checked. A client that sends only its leaf stops at the first certificate the server
// already trusts, and from there the root — the only key which could vouch for that CA's own CRL —
// is not part of what the verifier is handed. The last subtest is that shape: the leaf is still
// checked against its own CA's list, and the status of the CA above it is simply not something this
// handshake can learn, which is why a deployment which means to enforce that publishes for a pool
// from which Go can build to the root.
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
		if err := os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o600); err != nil {
			t.Fatalf("writing the root CRL: %v", err)
		}
	}
	writeRootCRL()
	issuingPath := writeCRLDER(t, "issuing.crl", pki.crl(t, crlOptions{number: 1}))
	writeIssuingCRL := func(entries ...x509.RevocationListEntry) {
		t.Helper()
		der := pki.crl(t, crlOptions{number: 2, revoked: entries})
		if err := os.WriteFile(issuingPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o600); err != nil {
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
			// The leaf alone is what a client configured with only its own certificate sends, which
			// is common enough to be the case worth testing against; sending the intermediate is the
			// other shape, and the only way a server holding just a root can reach the CA below it.
			sent = append(sent, pki.issCert.Raw)
		}
		client := &tls.Config{
			Certificates: []tls.Certificate{{Certificate: sent, PrivateKey: clientKey}},
			// The client verifies the server against the full pool; under test is how the server
			// assembles the chain of *its* client from *its* trust pool.
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
		// crypto/tls answers any VerifyConnection failure with bad_certificate (42).
		if !strings.Contains(err.Error(), "bad certificate") {
			t.Errorf("expected the peer to report a bad certificate, got: %v", err)
		}

		// Same pool, same client, revoked no more — so that the refusal above cannot be attributed
		// to anything about the setup.
		writeRootCRL()
		if _, err := full.reload(false); err != nil {
			t.Fatalf("reloading the root CRL again: %v", err)
		}
		if err := handshakeWith(full, rootOnly, true, &depth, &chains, &said); err != nil {
			t.Errorf("the connection should work once the CA is no longer revoked: %v (verifier said: %v)", err, said)
		}
	})

	t.Run("a bundle in the pool still reaches the root for a client that sends its ca", func(t *testing.T) {
		// Root and issuing together, which is what pointing trust_pool at a bundle produces. Go
		// builds every path it can find, so the chain which stops at the issuing CA sits beside one
		// that goes on to the root; the second one is what carries the enforcement below.
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
		// The same pool with a client that sends only its leaf: crypto/tls ends the chain at the
		// certificate it already trusts, so there is no path to the root and nothing above the
		// issuing CA is in hand to be asked about. What is checked still has to be checked — the
		// leaf's own revocation is refused here — and what cannot be checked is named rather than
		// pretended to, since an operator reading "chains are checked" would otherwise believe CA
		// revocation was enforced while nothing of the kind is happening.
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

		// The CA's own revocation is the other half: visible only on a chain which reaches its
		// issuer. With the root saying the issuing CA is revoked, the short chain still answers from
		// the leaf's own list — and the same client sending its intermediate, which gives Go the
		// path to the root, is refused. A pool holding the issuing CA is what makes that difference,
		// and it is why the documentation says to trust a self-signed root alone.
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

// An uncovered refusal travels back to Go and no further: the handshake ends and nothing is
// written. A deployment which loaded one CRL too few therefore turns every client away in silence —
// measured on a listener whose trust pool named an issuing CA no loaded list spoke for, where good
// certificates were refused with no log line at any level. So the first refusal per issuer is
// announced at warning level, and the connections after it go to debug: the operator hears about it
// once, loudly, rather than never or once per handshake.
func TestCRLVerifierUncoveredRefusalIsAnnouncedOncePerIssuer(t *testing.T) {
	pki := newCRLTestPKI(t)
	leaf, _ := pki.leaf(t, 7452)

	// A list for the root and none for the CA which signed this certificate: the half-configured
	// deployment which locks a listener out, since the chain's issuer is covered by nothing.
	path := writeCRLDER(t, "root.crl", pki.crl(t, crlOptions{issuer: pki.rootCert, signer: pki.rootKey, number: 1}))

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	core, logs := observer.New(zapcore.DebugLevel)
	v.logger = zap.New(core)

	raw, chains := rawDER(t, leaf), pki.chainsFor(leaf)
	for range 3 {
		if err := v.VerifyClientCertificate(raw, chains); err == nil {
			t.Fatal("a certificate which no loaded CRL speaks for was admitted")
		}
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

// TestCRLVerifierDirectlyTrustedIssuer is what a trust pool which holds the issuing CA itself means
// for the chain rule. Pointing trust_pool at a root-plus-issuing bundle makes crypto/x509 stop
// verified chains at the issuing CA, and such a chain holds no certificate whose key could vouch for
// a list about that CA — so the module checks what the chain can answer and goes no further. What
// that costs is visible from the other side: a client which sends its issuing CA completes the chain
// to the root, and then the root's word about that CA is enforced.
func TestCRLVerifierDirectlyTrustedIssuer(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 7700)

	rootCRL := createCRL(t, pki.rootCert, pki.rootKey, crlOptions{number: 1})
	path := writeFile(t, "issuing.crl", writeCRLPEMBytes(pki.crl(t, crlOptions{number: 1}), rootCRL))

	short := [][]*x509.Certificate{{client, pki.issCert}}
	full := pki.chainsToRoot(client)

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	if err := v.VerifyClientCertificate(rawDER(t, client), short); err != nil {
		t.Errorf("a chain which ends at a directly trusted CA should be checked only as far as it goes, got: %v", err)
	}
	if err := v.VerifyClientCertificate(rawDER(t, client), full); err != nil {
		t.Errorf("a complete chain with a list for every issuer should verify, got: %v", err)
	}

	// The root revoking the issuing CA: refused where the chain reaches the root, and still served on
	// the short chain, which cannot be asked about it. A deployment which wants that revocation to
	// bite trusts its root alone and has clients send their intermediate — or accepts that the
	// shorter path is checked less.
	revokedIssuer := createCRL(t, pki.rootCert, pki.rootKey, crlOptions{
		number:  2,
		revoked: []x509.RevocationListEntry{revokedEntry(pki.issCert.SerialNumber.Int64())},
	})
	badPath := writeFile(t, "issuing.crl", writeCRLPEMBytes(pki.crl(t, crlOptions{number: 1}), revokedIssuer))
	vetoed := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{badPath}})
	err := vetoed.VerifyClientCertificate(rawDER(t, client), full)
	if err == nil {
		t.Fatal("an issuing CA its own root has revoked was served on a chain which reaches that root")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("the refusal should say the issuing CA is revoked, got: %v", err)
	}
	if err := vetoed.VerifyClientCertificate(rawDER(t, client), short); err != nil {
		t.Errorf("the short chain cannot be asked about its own top, got: %v", err)
	}
}

// TestCRLVerifierSelfSignedClientCertificate is what the chain rule means at the top of a chain:
// a certificate is asked about by the certificate above it, and one which vouches for itself has no
// other answer available than its own list. A root therefore needs a current CRL of its own to be
// the top of a checked chain — which is the same rule nginx's ssl_crl applies to every CA in the
// path, and the same one which took a deployment down when a root stopped publishing.
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
		if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsToRoot(client)); err == nil {
			t.Error("a root which revoked itself was accepted at the top of a chain")
		}
	})

	t.Run("a complete chain with a current list for every issuer is served", func(t *testing.T) {
		cleanRoot := writeCRLDER(t, "root.crl", crlSignedBy(t, pki.rootCert, pki.rootKey))
		v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path, cleanRoot}})
		if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsToRoot(client)); err != nil {
			t.Errorf("expected admission, got: %v", err)
		}
	})

	t.Run("a chain reaching a root with no list from it is refused by name", func(t *testing.T) {
		// The issuing CA is only as good as the root's word about it. With a chain which reaches the
		// root and no list from the root, that word is missing — so this refuses and says whose
		// coverage is absent rather than trusting the CA on its own say-so.
		v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
		err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsToRoot(client))
		if err == nil {
			t.Fatal("the issuing CA was accepted with nothing saying whether its own key is still good")
		}
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
			// Two chains and the same CA revoked on both of them — which is what revoking a
			// cross-signed certificate means in practice. The leaf itself is clean on both paths, so
			// the refusal comes from a revocation rather than from missing coverage, and it is
			// reported once for the connection instead of once per chain tried.
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
			// One path revoked, the other clean: refused on the strength of the one path, and
			// reported once — not once per chain which objected, and not silently because a
			// different path had nothing to say about it.
			name:        "another path is clean",
			sources:     []string{crlA, crlB, issuingB},
			wantErr:     true,
			wantReports: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: tc.sources})

			core, logs := observer.New(zapcore.ErrorLevel)
			v.logger = zap.New(core)

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
			// What is reported is the certificate a CRL actually named, which here is the issuing CA
			// on one of its two certificates — not the leaf, which is clean on both paths.
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

// TestCRLVerifierDirectlyTrustedCertificateWhichIsNotSelfSigned covers a certificate which is in
// the trust pool and presented as an identity, but is not self-signed — a CA certificate placed
// there so that chains complete, for instance. Go builds a chain of one for it, so nothing above it
// could have revoked it, and a status which cannot be established is a refusal: issuerOf answers
// only for a top which carries its own name as issuer. The advice in the refusal has to fit the
// certificate at hand, which is why it says nothing about being self-signed.
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
	// A publisher whose clock runs a few minutes ahead writes a list which is not valid yet. The
	// list before it, still inside its own lifetime, says everything the new one will; answering
	// "not valid until" while it sits in the same file would take every client down for the length
	// of the overlap.
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 7840)
	good, _ := pki.leaf(t, 7841)

	notYet := pki.crl(t, crlOptions{
		number:     2,
		thisUpdate: time.Now().Add(10 * time.Minute),
		nextUpdate: time.Now().Add(72 * time.Hour),
	})
	current := pki.crl(t, crlOptions{number: 1, revoked: []x509.RevocationListEntry{revokedEntry(7840)}})
	path := writeCRLPEM(t, "issuing.crl", notYet, current)

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client))
	if err == nil {
		t.Fatal("a serial its CA has revoked was served")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("the older in-date list should be the one which answers, got: %v", err)
	}
	if err := v.VerifyClientCertificate(rawDER(t, good), pki.chainsFor(good)); err != nil {
		t.Errorf("a serial the older list does not revoke should be served, got: %v", err)
	}
}

// TestCRLVerifierAnUnusableCRLSaysWhyOutLoud covers the refusals which look like coverage from the
// outside: a list is loaded for this issuer, but it cannot be relied on — it passed its nextUpdate,
// or has not begun, or does not carry the verified chain's signature, or every list for that issuer
// had to be set aside. A refusal only travels back to Go, which ends the handshake and says nothing
// further, so an operator is left with clients turning away and a log with nothing in it. Each of
// these is said once loudly and then quietly for as long as it stays true.
func TestCRLVerifierAnUnusableCRLSaysWhyOutLoud(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 7843)

	// A list which names a key the certificate in hand does not hold — one CA certificate retired,
	// another issued under the same subject. It is minted from a copy of the issuing CA carrying a
	// different subject key id, which is what Go publishes as the list's authority key id, so the
	// list holds exactly one such extension: an injected extra would leave two and test which one
	// Go's parser keeps.
	retiredKey := *pki.issCert
	retiredKey.SubjectKeyId = []byte{0x01, 0x02, 0x03}

	for _, tc := range []struct {
		name   string
		list   []byte
		want   string // in the refusal handed back to Go
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

			core, logs := observer.New(zapcore.DebugLevel)
			v.logger = zap.New(core)

			err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client))
			if err == nil {
				t.Fatal("a certificate under an unusable CRL was served")
			}
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

			// The next client under the same CA is refused for the same reason, and that is the same
			// news: it must not become a wall of warnings, but it should stay visible to whoever is
			// looking with debug on.
			if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err == nil {
				t.Fatal("a certificate under an unusable CRL was served")
			}
			if got := logs.FilterMessage(message).FilterLevelExact(zapcore.WarnLevel).Len(); got != 1 {
				t.Errorf("an unchanged condition was announced loudly again: %d lines", got)
			}
			if logs.FilterMessage(message).FilterLevelExact(zapcore.DebugLevel).Len() == 0 {
				t.Error("the standing condition should stay visible at debug")
			}
		})
	}
}

// TestCRLVerifierExpiryIsStrict pins that a list is trusted only inside the lifetime its issuer
// published, with nothing to switch that off. Past nextUpdate the CA has said nothing about this
// certificate, and that is a refusal in its own words rather than a fall through to "no CRL covers
// it" — the same call OpenSSL makes with "CRL has expired".
func TestCRLVerifierExpiryIsStrict(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 7860)

	lapsed := pki.crl(t, crlOptions{
		number:     1,
		thisUpdate: time.Now().Add(-96 * time.Hour),
		nextUpdate: time.Now().Add(-time.Hour),
	})
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{writeCRLDER(t, "lapsed.crl", lapsed)}})
	err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client))
	if err == nil {
		t.Fatal("a certificate was served on the word of a CA which stopped speaking an hour ago")
	}
	if !strings.Contains(err.Error(), "nextUpdate") {
		t.Errorf("the refusal should say the list passed its nextUpdate, got: %v", err)
	}

	// A lapse measured in seconds is still a lapse; only drift between this clock and the issuer's
	// is tolerated, and only within crlClockSkew.
	nearMiss := pki.crl(t, crlOptions{
		number:     2,
		thisUpdate: time.Now().Add(-time.Hour),
		nextUpdate: time.Now().Add(-time.Minute),
	})
	v = provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{writeCRLDER(t, "near-miss.crl", nearMiss)}})
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err != nil {
		t.Errorf("a list a minute past its nextUpdate is inside the tolerated clock drift, got: %v", err)
	}

	beyondSkew := pki.crl(t, crlOptions{
		number:     3,
		thisUpdate: time.Now().Add(-time.Hour),
		nextUpdate: time.Now().Add(-(crlClockSkew + time.Minute)),
	})
	v = provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{writeCRLDER(t, "beyond-skew.crl", beyondSkew)}})
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err == nil {
		t.Error("a list past the tolerated clock drift was still believed")
	}

	// A list with no nextUpdate makes no promise to expire by, and RFC 5280 lets a client treat it as
	// current indefinitely. The reload schedule is what notices such a publisher has stopped; the
	// list itself stays usable, since refusing on it would be inventing an expiry its issuer declined
	// to publish.
	timeless := pki.crl(t, crlOptions{number: 4, noNextUpdate: true})
	v = provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{writeCRLDER(t, "timeless.crl", timeless)}})
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err != nil {
		t.Errorf("a list without nextUpdate should remain current, got: %v", err)
	}
}

func TestIssuerOf(t *testing.T) {
	// The names have to differ from one another: two certificates with empty names have equal
	// RawSubject and RawIssuer, which would make each of them look self-issued.
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
	// A self-issued last certificate is its own issuer. What reaches here is a CA which re-keyed in
	// place and is in the trust pool: the same name on both sides with a different key behind it,
	// so its status really is somebody's to state and this is the only copy of it available to
	// verify such a list against. The same answer covers an ordinary self-signed root at the top of
	// a real chain — which is why a deployment trusting a root alone has to load that root's CRL —
	// and a peer certificate presented as the whole chain which carries its own name as issuer.
	if got := issuerOf(chain, 2); got != root {
		t.Error("a self-issued last certificate should be its own issuer")
	}

	// A chain which ends at an intermediate which is trusted directly without being self-issued —
	// a trust_pool holding the issuing CA — holds no copy of that CA's issuer, so there is nothing
	// to verify its CRL against and its revocation status cannot be established from this chain.
	// A peer certificate presented alone looks exactly like this, since a client certificate is not
	// self-issued; verifyChain refuses both rather than passing them.
	if got := issuerOf([]*x509.Certificate{leaf, intermediate}, 1); got != nil {
		t.Error("a last certificate which is not self-issued should have no issuer in the chain")
	}
}

// TestCRLVerifierIssuerOfNamesWhoSpeaksForWhom pins which certificate may answer for which: the
// one above it in the verified chain. At the top of a chain there is no one above it, so either the
// certificate vouches for itself — and then its own list is the only possible answer — or nothing
// can be established about it at all.
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

	// A self-signed root at the top is its own issuer: asking it about itself is meaningful, and a
	// deployment which trusts a root alone therefore needs that root to publish.
	full := pki.chainsToRoot(leaf)[0]
	if got := issuerOf(full, 2); got != pki.rootCert {
		t.Error("a self-signed certificate at the top of a chain should answer for itself")
	}

	// Self-issued is not self-signed: a CA which renews itself in place keeps its name and changes
	// its key, so its own word does not stand in for an issuer's and it is not treated as an anchor
	// whose status nobody can question.
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
	// The name is what issuerOf goes by, and this certificate's subject is its own: it answers for
	// itself, exactly as a self-signed root would. What keeps the root's own list from being taken as
	// this certificate's word is the signature check — a list signed by the old key does not verify
	// against the new one, which TestCRLVerifierAuthorityKeyIDMustMatchTheIssuer and
	// TestCRLVerifierNumberRegressionIsScopedToItsOwnSigningKey cover from each side.
	if got := issuerOf([]*x509.Certificate{leaf, reKeyed}, 1); got != reKeyed {
		t.Errorf("a self-issued certificate at the top of a chain should answer for its own name, got %v", got)
	}
}

// BenchmarkVerifyClientCertificate measures what checking one client certificate costs as the list
// grows: a signature verification per certificate in scope, plus a lookup in an index which holds
// everything the CA has revoked. The entry count is the axis worth watching, since it is the number
// here a CA controls; TestCRLVerifierLargeListCost measures the memory side of the same list. What
// the growing count costs is left to the numbers rather than explained here — reading where the time
// goes needs a profile, and this is the place which will show a regression in it.
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
