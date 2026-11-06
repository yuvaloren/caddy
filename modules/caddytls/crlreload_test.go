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
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
)

func TestCRLVerifierNumberRegression(t *testing.T) {
	pki := newCRLTestPKI(t)
	revokedCert, _ := pki.leaf(t, 9001)

	path := filepath.Join(t.TempDir(), "issuing.crl")
	write := func(number int64, entries []x509.RevocationListEntry) {
		t.Helper()
		der := pki.crl(t, crlOptions{number: number, revoked: entries})
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: pemTypeCRL, Bytes: der}), 0o600); err != nil {
			t.Fatalf("writing the CRL: %v", err)
		}
	}

	// number 5 revokes the certificate
	write(5, []x509.RevocationListEntry{revokedEntry(9001)})
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	if err := v.VerifyClientCertificate(rawDER(t, revokedCert), pki.chainsFor(revokedCert)); err == nil {
		t.Fatal("the revoked certificate was admitted")
	}

	// an older list which does not mention it must not un-revoke it
	write(4, nil)
	if _, err := v.reload(false); err == nil {
		t.Error("a CRL older than one already loaded was accepted")
	}
	if err := v.VerifyClientCertificate(rawDER(t, revokedCert), pki.chainsFor(revokedCert)); err == nil {
		t.Error("the older CRL un-revoked a certificate the newer one had revoked")
	}

	// a newer number is accepted again
	write(6, nil)
	if _, err := v.reload(false); err != nil {
		t.Fatalf("a newer CRL was refused: %v", err)
	}
	if err := v.VerifyClientCertificate(rawDER(t, revokedCert), pki.chainsFor(revokedCert)); err != nil {
		t.Errorf("the revocation is gone from number 6, so it should be believed now, got: %v", err)
	}

	// a config reload starts from scratch, the documented remedy for a real rollback
	fresh := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	if err := fresh.VerifyClientCertificate(rawDER(t, revokedCert), pki.chainsFor(revokedCert)); err != nil {
		t.Errorf("after a reload the current CRL should be believed again, got: %v", err)
	}
}

// An overlap followed by only its older half is a rollback: the older list alone
// would un-revoke what the newer one revoked.
func TestCRLVerifierAnOlderListAloneAfterANewerOneIsRefused(t *testing.T) {
	pki := newCRLTestPKI(t)
	revokedCert, _ := pki.leaf(t, 9600)

	older := pki.crl(t, crlOptions{number: 5})
	newer := pki.crl(t, crlOptions{number: 6, revoked: []x509.RevocationListEntry{revokedEntry(9600)}})
	path := writeFile(t, "issuing.crl", writeCRLPEMBytes(older, newer))

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	if err := v.VerifyClientCertificate(rawDER(t, revokedCert), pki.chainsFor(revokedCert)); err == nil {
		t.Fatal("the certificate the newer list revokes was admitted")
	}

	// only number 5 is served again, but this source already served 6
	if err := os.WriteFile(path, writeCRLPEMBytes(older), 0o600); err != nil {
		t.Fatalf("writing the older list: %v", err)
	}
	if _, err := v.reload(false); err == nil {
		t.Error("a source which went back to an older list it had already served was accepted")
	}
	if err := v.VerifyClientCertificate(rawDER(t, revokedCert), pki.chainsFor(revokedCert)); err == nil {
		t.Error("the older list alone un-revoked a certificate the newer list had revoked")
	}

	// serving the refused list beside a newer one does not rehabilitate it: 7 is
	// accepted and 6 stands in for the refused 5
	if err := os.WriteFile(path, writeCRLPEMBytes(older, pki.crl(t, crlOptions{number: 7})), 0o600); err != nil {
		t.Fatalf("writing the older list beside a newer one: %v", err)
	}
	_, err := v.reload(false)
	if err == nil {
		t.Fatal("a refused list was believed again once something newer arrived beside it")
	}
	if !strings.Contains(err.Error(), "is older than one this source served before") {
		t.Errorf("the refusal should name the rollback, not some other trouble: %v", err)
	}
	numbers := serviceNumbers(v.current(), pki.issCert)
	// number 5 must not be in service
	if !slices.Equal(numbers, []int64{6, 7}) {
		t.Errorf("expected the two newer lists — 6 and 7 — in service after the refusal, got %v", numbers)
	}

	// the source recovers once it serves something newer
	if err := os.WriteFile(path, writeCRLPEMBytes(pki.crl(t, crlOptions{number: 8})), 0o600); err != nil {
		t.Fatalf("writing the newest list: %v", err)
	}
	if _, err := v.reload(false); err != nil {
		t.Errorf("a newer list was refused after an earlier rollback: %v", err)
	}
	if err := v.VerifyClientCertificate(rawDER(t, revokedCert), pki.chainsFor(revokedCert)); err != nil {
		t.Errorf("number 8 does not revoke the certificate, so it should be believed now, got: %v", err)
	}
}

func TestCRLVerifierNumberAbsentIsNotCompared(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 9500)

	// EJBCA's issuing CRL carries no cRLNumber; numbers are compared only when both
	// lists have one
	path := writeCRLDER(t, "issuing.crl", pki.crl(t, crlOptions{omitNumber: true}))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err != nil {
		t.Errorf("a CRL without a cRLNumber should be usable, got: %v", err)
	}

	write := func(ders ...[]byte) {
		t.Helper()
		if err := os.WriteFile(path, writeCRLPEMBytes(ders...), 0o600); err != nil {
			t.Fatalf("writing the CRLs: %v", err)
		}
	}

	// a numbered list raises this source's mark
	write(pki.crl(t, crlOptions{number: 3}))
	if _, err := v.reload(false); err != nil {
		t.Fatalf("a first numbered list was refused: %v", err)
	}

	// an un-numbered list afterwards cannot be shown to be older; its absent number
	// must not be read as zero
	write(pki.crl(t, crlOptions{omitNumber: true}))
	if _, err := v.reload(false); err != nil {
		t.Errorf("a list without a cRLNumber was compared against a numbered one: %v", err)
	}
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err != nil {
		t.Errorf("the un-numbered list should still be usable, got: %v", err)
	}

	// the mark still stands
	write(pki.crl(t, crlOptions{number: 2}))
	logs := observeLogs(t, v, zapcore.ErrorLevel)
	_, reloadErr := v.reload(false)
	if reloadErr == nil {
		t.Fatal("a numbered list below one this source served before was accepted")
	}
	if !strings.Contains(reloadErr.Error(), "is older than one this source served before") {
		t.Errorf("the refusal should name the rollback, got: %v", reloadErr)
	}

	// nothing stands in for an un-numbered list, so the set is emptied and the
	// certificate is refused as uncovered rather than admitted on a stale snapshot
	if got := len(v.current().byIssuer[string(pki.issCert.RawSubject)]); got != 0 {
		t.Errorf("%d CRLs are in service for the issuer this source stopped covering, want none", got)
	}
	err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client))
	if err == nil {
		t.Fatal("a certificate which no loaded CRL covers was served")
	}
	if !strings.Contains(err.Error(), "no configured CRL covers") {
		t.Errorf("the refusal should say the issuer is uncovered, got: %v", err)
	}
	// the set is empty, and the refusal says so
	if !strings.Contains(err.Error(), "no CRL is loaded at all") {
		t.Errorf("the refusal should say that no CRL is loaded, got: %v", err)
	}
	// the transition into that state is logged
	if !strings.Contains(reloadErr.Error(), "no earlier list from this source covers") {
		t.Errorf("the refusal should say nothing is left standing in for this issuer, got: %v", reloadErr)
	}
	if want := pki.issCert.Subject.String(); !strings.Contains(reloadErr.Error(), "covers "+want) {
		t.Errorf("the refusal should name %s as the issuer left with nothing, got: %v", want, reloadErr)
	}
	if got := len(logs.FilterMessage("no CRL is in service").All()); got != 1 {
		t.Errorf("%d lines announced that no CRL is in service, want 1", got)
	}

	// logged once per transition: an un-numbered list reopens the source, and a
	// second rollback empties it again
	write(pki.crl(t, crlOptions{omitNumber: true}))
	if _, err := v.reload(false); err != nil {
		t.Fatalf("a list without a number was refused after a rollback: %v", err)
	}
	if got := len(v.current().byIssuer[string(pki.issCert.RawSubject)]); got != 1 {
		t.Errorf("%d CRLs are in service after the source spoke again, want 1", got)
	}
	write(pki.crl(t, crlOptions{number: 2}))
	if _, err := v.reload(false); err == nil {
		t.Fatal("a numbered list below the mark was accepted after a recovery")
	}
	if got := len(logs.FilterMessage("no CRL is in service").All()); got != 2 {
		t.Errorf("%d lines announced that no CRL is in service, want one per transition into it", got)
	}

	// staying in that state is not a new incident
	if _, err := v.reload(false); err == nil {
		t.Fatal("a numbered list below the mark was accepted on a later refresh")
	}
	if got := len(logs.FilterMessage("no CRL is in service").All()); got != 2 {
		t.Errorf("%d lines announced that no CRL is in service after a refresh which changed nothing, want 2", got)
	}
}

// A CA which starts publishing its authority key id mid-overlap has not rolled
// back: the older, un-keyed list must not be refused against a mark set by a list
// under a key it never claimed.
func TestCRLVerifierAKeyIDPublishedMidOverlapIsNotARollback(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 9501)

	// noNextUpdate takes the hand-written path, which carries no authority key id
	older := pki.crl(t, crlOptions{number: 5, noNextUpdate: true})
	middle := pki.crl(t, crlOptions{number: 6, noNextUpdate: true})
	// crypto/x509 writes the authority key id
	newer := pki.crl(t, crlOptions{number: 7})

	lists, _, err := parseCRLs(writeCRLPEMBytes(older, newer))
	if err != nil || len(lists) != 2 {
		t.Fatalf("parsing the two lists: %d lists, %v", len(lists), err)
	}
	if len(lists[0].crl.AuthorityKeyId) != 0 {
		t.Fatal("the hand-written list carries an authority key id, so it does not test this case")
	}
	if len(lists[1].crl.AuthorityKeyId) == 0 {
		t.Fatal("the Go-written list carries no authority key id, so it does not test this case")
	}

	// the overlap first, both lists the old way: the mark is now 6
	path := writeFile(t, "issuing.crl", writeCRLPEMBytes(older, middle))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	// the CA publishes its key id from here on, with the older list still beside it
	if err := os.WriteFile(path, writeCRLPEMBytes(older, newer), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.reload(false); err != nil {
		t.Errorf("a CA which started publishing its key id mid-overlap was refused: %v", err)
	}

	set := v.current()
	numbers := serviceNumbers(set, pki.issCert)
	if !slices.Equal(numbers, []int64{5, 7}) {
		t.Errorf("expected both overlapping lists — 5 and 7 — in service, got %v", numbers)
	}
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err != nil {
		t.Errorf("a certificate covered by the overlap was refused: %v", err)
	}
}

// A cRLNumber is compared only within one source, one issuer and one signing key:
// a twin CA of the same name is not a rollback.
func TestCRLVerifierNumberRegressionIsScopedToItsOwnSigningKey(t *testing.T) {
	pki := newCRLTestPKI(t)

	// a second CA with the same name and a different key
	twinKey, twin := mintCA(t, "CRL Test Issuing CA", caPair{}, nil)
	if !bytes.Equal(twin.RawSubject, pki.issCert.RawSubject) {
		t.Fatal("the twin CA was expected to have the identical name encoding")
	}

	path := writeCRLDER(t, "issuing.crl", pki.crl(t, crlOptions{number: 7}))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	write := func(ders ...[]byte) {
		t.Helper()
		if err := os.WriteFile(path, writeCRLPEMBytes(ders...), 0o600); err != nil {
			t.Fatalf("writing the CRLs: %v", err)
		}
	}

	t.Run("a lower number from another ca of the same name is not a rollback", func(t *testing.T) {
		write(pki.crl(t, crlOptions{number: 8}), createCRL(t, twin, twinKey, crlOptions{number: 3}))
		if _, err := v.reload(false); err != nil {
			t.Fatalf("two lists with independent counters were refused as a rollback: %v", err)
		}
	})

	t.Run("a lower number from the same list is", func(t *testing.T) {
		write(pki.crl(t, crlOptions{number: 8}), createCRL(t, twin, twinKey, crlOptions{number: 2}))
		if _, err := v.reload(false); err == nil {
			t.Error("expected the twin CA's list going backwards to be reported")
		}
		// the last good lists stay in service
		var numbers []int64
		for _, list := range v.current().byIssuer {
			for _, crl := range list {
				if crl.number != nil {
					numbers = append(numbers, crl.number.Int64())
				}
			}
		}
		slices.Sort(numbers)
		if len(numbers) != 2 || numbers[0] != 3 || numbers[1] != 8 {
			t.Errorf("expected the last good lists — numbers 3 and 8 — to still be in service, got %v", numbers)
		}
	})

}

// The older half of an overlap must survive a second read of the same file: the
// mark the batch itself raised must not refuse it.
func TestCRLVerifierOverlapSurvivesAReload(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 7850)

	notYet := pki.crl(t, crlOptions{
		number:     2,
		thisUpdate: time.Now().Add(10 * time.Minute),
		nextUpdate: time.Now().Add(72 * time.Hour),
	})
	current := pki.crl(t, crlOptions{number: 1})
	path := writeLists(t, "issuing.crl", notYet, current)

	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	if _, err := v.reload(false); err != nil {
		t.Fatalf("a healthy bundle was reported as a failing source on its second load: %v", err)
	}
	if got := len(v.current().byIssuer[string(pki.issCert.RawSubject)]); got != 2 {
		t.Errorf("the overlap kept %d lists on reload, want both", got)
	}
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err != nil {
		t.Errorf("the older current list should still answer for this certificate, got: %v", err)
	}
}

// One bundle regresses two issuers: one has an earlier list standing in, the other
// has none because its last accepted list carried no number. The report names
// both, but only the second as left uncovered.
func TestCRLVerifierABatchWhichRegressesTwoIssuersWordsThemApart(t *testing.T) {
	pki := newCRLTestPKI(t)

	root := func(number int64) []byte {
		t.Helper()
		return pki.crl(t, crlOptions{issuer: pki.rootCert, signer: pki.rootKey, number: number})
	}
	path := writeFile(t, "bundle.pem", writeCRLPEMBytes(pki.crl(t, crlOptions{number: 3}), root(3)))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	write := func(ders ...[]byte) {
		t.Helper()
		if err := os.WriteFile(path, writeCRLPEMBytes(ders...), 0o600); err != nil {
			t.Fatalf("writing the bundle: %v", err)
		}
	}

	// the issuing CA's list loses its number, so nothing can later stand in for it
	write(pki.crl(t, crlOptions{omitNumber: true}), root(3))
	if _, err := v.reload(false); err != nil {
		t.Fatalf("a list without a number was refused beside one at its mark: %v", err)
	}

	write(pki.crl(t, crlOptions{number: 2}), root(2))
	_, err := v.reload(false)
	if err == nil {
		t.Fatal("both lists in the bundle went backwards and the source was accepted")
	}
	message := err.Error()
	if !strings.Contains(message, "is older than one this source served before") {
		t.Errorf("the refusal should name the rollback, got: %s", message)
	}
	issuingDN, rootDN := pki.issCert.Subject.String(), pki.rootCert.Subject.String()

	// both issuers are named
	for _, want := range []string{issuingDN, rootDN} {
		if !strings.Contains(message, want) {
			t.Errorf("the refusal should name %s, got: %s", want, message)
		}
	}
	// but only the issuer with nothing standing in is reported as uncovered, so the
	// sentence is compared exactly rather than by containment
	const uncoveredPrefix = "no earlier list from this source covers "
	if _, rest, found := strings.Cut(message, uncoveredPrefix); !found {
		t.Errorf("the refusal should say an issuer is left with nothing, got: %s", message)
	} else if named, _, _ := strings.Cut(rest, ", so unless another source does"); named != issuingDN {
		t.Errorf("the refusal names %q as left with nothing, want only %q — got: %s", named, issuingDN, message)
	}

	// the set agrees with the report: root 3 answers, the issuing CA has nothing
	set := v.current()
	if set == nil {
		t.Fatal("no CRL set is in use")
	}
	rootNumbers := serviceNumbers(set, pki.rootCert)
	if !slices.Equal(rootNumbers, []int64{3}) {
		t.Errorf("the root is answered by lists %v, want [3]", rootNumbers)
	}
	if got := len(set.byIssuer[string(pki.issCert.RawSubject)]); got != 0 {
		t.Errorf("%d lists are in service for the issuer left with nothing, want none", got)
	}
	client, _ := pki.leaf(t, 7891)
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err == nil {
		t.Error("a certificate whose issuer lost its only list was admitted")
	}
}

// A bundle with a stale sibling is refused on every refresh, and each refresh
// parses new objects. The stand-in for the refusal must come from the distinct
// lists, or lastGood grows by one parsed CRL per retry.
func TestCRLVerifierARefusingBundleIsRememberedOncePerReload(t *testing.T) {
	pki := newCRLTestPKI(t)

	path := writeFile(t, "bundle.pem", writeCRLPEMBytes(pki.crl(t, crlOptions{number: 4})))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	// the current list beside a stale one this source never accepted
	if err := os.WriteFile(path, writeCRLPEMBytes(
		pki.crl(t, crlOptions{number: 5}), pki.crl(t, crlOptions{number: 3})), 0o600); err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 3; i++ {
		if _, err := v.reload(false); err == nil {
			t.Fatalf("refresh %d: a bundle holding a stale list was accepted", i)
		}
		if got := len(v.lastGood[path]); got != 2 {
			t.Errorf("after refresh %d this source remembers %d lists, want 2: the current one and the one standing in for the refused", i, got)
		}
		// 5 answers and 4 stands in for the refused 3, on every refresh
		numbers := serviceNumbers(v.current(), pki.issCert)
		if !slices.Equal(numbers, []int64{4, 5}) {
			t.Errorf("after refresh %d the issuer is answered by lists %v, want [4 5]", i, numbers)
		}
	}
}

// A list first seen at a number below what this source served is a rollback even
// beside a future-dated list which cannot answer yet; the superseded list keeps
// answering.
func TestCRLVerifierAReplayedOlderListIsRefusedEvenBesideAFutureDatedOne(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 7842)

	path := writeFile(t, "issuing.crl", writeCRLPEMBytes(pki.crl(t, crlOptions{
		number: 5, revoked: []x509.RevocationListEntry{revokedEntry(7842)},
	})))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err == nil {
		t.Fatal("a serial the loaded CRL revokes was served")
	}

	future := pki.crl(t, crlOptions{
		number:     6,
		thisUpdate: time.Now().Add(10 * time.Minute),
		nextUpdate: time.Now().Add(72 * time.Hour),
	})
	replay := pki.crl(t, crlOptions{number: 4}) // in date, and silent about the revocation
	if err := os.WriteFile(path, writeCRLPEMBytes(future, replay), 0o600); err != nil {
		t.Fatal(err)
	}
	logs := observeLogs(t, v, zapcore.ErrorLevel)

	if _, err := v.reload(false); err == nil {
		t.Error("a source which went backwards was accepted")
	}
	const refusedMessage = "a CRL source reported a problem"
	handled := logs.FilterMessage(refusedMessage).All()
	if len(handled) == 0 {
		t.Fatal("a list replayed at a lower number should be refused out loud")
	}
	reason := fmt.Sprint(handled[0].ContextMap()["reason"])
	for _, want := range []string{"is older than one this source served before", "restarting Caddy"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the refusal should say the source went backwards and how to end it (want %q), got: %s", want, reason)
		}
	}
	set := v.current()
	if set == nil {
		t.Fatal("no CRL set is in use")
	}
	numbers := serviceNumbers(set, pki.issCert)
	// the future-dated 6 and the stand-in 5, not the replayed 4
	if !slices.Equal(numbers, []int64{5, 6}) {
		t.Errorf("expected the future-dated list and the one standing in — 5 and 6 — in service, got %v", numbers)
	}

	err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client))
	if err == nil {
		t.Fatal("a serial its CA revoked was served on the strength of a list this source had never served")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("the superseded list should be the one which answers, got: %v", err)
	}
}

// A source which stays broken is reported once, but one which starts failing in a
// new way (unreachable, then rolling back) is reported again.
func TestCRLVerifierASourceWhichStartsFailingDifferentlyIsAnnouncedAgain(t *testing.T) {
	pki := newCRLTestPKI(t)

	path := writeFile(t, "issuing.crl", writeCRLPEMBytes(pki.crl(t, crlOptions{number: 3})))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	logs := observeLogs(t, v, zapcore.ErrorLevel)

	const problemMessage = "a CRL source reported a problem"
	announced := func() int { return len(logs.FilterMessage(problemMessage).All()) }

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := v.reload(false); err == nil {
		t.Fatal("a source whose file disappeared was accepted")
	}
	if got := announced(); got != 1 {
		t.Fatalf("%d lines reported the problem after the first failed refresh, want 1", got)
	}
	if _, err := v.reload(false); err == nil {
		t.Fatal("a source whose file is still missing was accepted")
	}
	if got := announced(); got != 1 {
		t.Errorf("%d lines reported the same missing file twice, want 1 — a source which stays broken is one condition", got)
	}

	// the file comes back, but goes backwards
	if err := os.WriteFile(path, writeCRLPEMBytes(pki.crl(t, crlOptions{number: 2})), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.reload(false); err == nil {
		t.Fatal("a list below the number this source served before was accepted")
	}
	if got := announced(); got != 2 {
		t.Fatalf("%d lines reported the rollback, want 2 — a source which starts failing in a new way has something new to say", got)
	}
	reason := fmt.Sprint(logs.FilterMessage(problemMessage).All()[1].ContextMap()["reason"])
	if !strings.Contains(reason, "is older than one this source served before") {
		t.Errorf("the second line should describe the rollback rather than the missing file, got: %s", reason)
	}
	if _, err := v.reload(false); err == nil {
		t.Fatal("the same rollback was accepted on a later refresh")
	}
	if got := announced(); got != 2 {
		t.Errorf("%d lines reported the same rollback twice, want 2 — the wording is unchanged, so this is one condition", got)
	}
}

// A rollback at one of two sources for the same CA is named in the log, but
// nothing is uncovered while the other source still answers.
func TestCRLVerifierAnIssuerAnotherSourceStillCoversIsNamedButNotLost(t *testing.T) {
	pki := newCRLTestPKI(t)

	rolling := writeFile(t, "rolling.pem", writeCRLPEMBytes(pki.crl(t, crlOptions{number: 3})))
	steady := writeFile(t, "steady.pem", writeCRLPEMBytes(pki.crl(t, crlOptions{number: 5})))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{rolling, steady}})

	// the rolling source's last accepted list carries no number, so nothing can
	// stand in for it
	if err := os.WriteFile(rolling, writeCRLPEMBytes(pki.crl(t, crlOptions{omitNumber: true})), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.reload(false); err != nil {
		t.Fatalf("a list without a number was refused beside a higher one from another source: %v", err)
	}
	if err := os.WriteFile(rolling, writeCRLPEMBytes(pki.crl(t, crlOptions{number: 2})), 0o600); err != nil {
		t.Fatal(err)
	}

	logs := observeLogs(t, v, zapcore.ErrorLevel)
	if _, err := v.reload(false); err != nil {
		t.Fatalf("one source rolling back while the other answers should not fail the refresh: %v", err)
	}

	handled := logs.FilterMessage("a CRL source reported a problem").All()
	if len(handled) != 1 {
		t.Fatalf("%d lines reported the rollback, want 1: %v", len(handled), handled)
	}
	reason := fmt.Sprint(handled[0].ContextMap()["reason"])
	for _, want := range []string{"is older than one this source served before", "no earlier list from this source covers"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the refusal should say %q, got: %s", want, reason)
		}
	}
	if dn := pki.issCert.Subject.String(); !strings.Contains(reason, dn) {
		t.Errorf("the refusal should name %s, got: %s", dn, reason)
	}

	// the steady source's number 5 still answers on its own
	client, _ := pki.leaf(t, 7892)
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err != nil {
		t.Errorf("a certificate covered by the source which did not roll back was refused: %v", err)
	}
	if got := len(v.current().byIssuer[string(pki.issCert.RawSubject)]); got != 1 {
		t.Errorf("%d lists are in service for that issuer, want only the steady source's", got)
	}
}

// Two lists refused for one issuer in a single bundle name that issuer once.
func TestCRLVerifierTwoListsRefusedForOneIssuerNameItOnce(t *testing.T) {
	pki := newCRLTestPKI(t)

	path := writeFile(t, "bundle.pem", writeCRLPEMBytes(pki.crl(t, crlOptions{number: 3})))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	if err := os.WriteFile(path, writeCRLPEMBytes(
		pki.crl(t, crlOptions{number: 2}), pki.crl(t, crlOptions{number: 1})), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := v.reload(false)
	if err == nil {
		t.Fatal("two lists below the number this source served before were accepted")
	}
	dn := pki.issCert.Subject.String()
	if got := strings.Count(err.Error(), dn); got != 1 {
		t.Errorf("%s is named %d times in the refusal, want once — got: %s", dn, got, err)
	}
	// the number this source served before still answers
	numbers := serviceNumbers(v.current(), pki.issCert)
	if !slices.Equal(numbers, []int64{3}) {
		t.Errorf("that issuer is answered by lists %v, want the [3] this source served before", numbers)
	}
}

func TestCRLVerifierReloadStopsOnCleanup(t *testing.T) {
	pki := newCRLTestPKI(t)
	var loads int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&loads, 1)
		_, _ = w.Write(pki.crl(t, crlOptions{
			number:     1,
			thisUpdate: time.Now().Add(-3 * time.Hour),
			nextUpdate: time.Now().Add(-time.Hour),
		}))
	}))
	defer srv.Close()

	// the refetch interval comes from the list's lifetime, so the list is already
	// past due and the retry floor is shortened
	old := crlRetryOnFailure
	crlRetryOnFailure = 100 * time.Millisecond
	defer func() { crlRetryOnFailure = old }()

	cfg := &CRLVerifier{CRLURLs: []string{srv.URL}}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	v := cfg
	if err := v.Provision(ctx); err != nil {
		t.Fatalf("provisioning: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for atomic.LoadInt64(&loads) < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if atomic.LoadInt64(&loads) < 2 {
		t.Fatalf("the reload loop did not fetch again, loads=%d", atomic.LoadInt64(&loads))
	}

	if err := v.Cleanup(); err != nil {
		t.Fatalf("cleaning up: %v", err)
	}
	stoppedAt := atomic.LoadInt64(&loads)
	time.Sleep(2500 * time.Millisecond)
	if got := atomic.LoadInt64(&loads); got != stoppedAt {
		t.Errorf("the reload loop kept fetching after Cleanup: %d then %d", stoppedAt, got)
	}
}

func TestCRLVerifierCleanupInterruptsAFetch(t *testing.T) {
	// Cleanup must not wait for a fetch in flight; the client timeout is a minute.
	// Caddy cancels the context before Cleanup between configs, but cleans up a
	// module whose Validate failed with the context still live, so both orders are
	// covered.
	for _, tc := range []struct {
		name          string
		cancelContext bool
	}{
		{"cleanup alone, with the context still live", false},
		{"the context canceled first, as between configs", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := newCRLTestPKI(t)
			first := pem.EncodeToMemory(&pem.Block{Type: pemTypeCRL, Bytes: pki.crl(t, crlOptions{
				number:     1,
				thisUpdate: time.Now().Add(-3 * time.Hour),
				nextUpdate: time.Now().Add(-time.Hour),
			})})

			// the server answers once and then hangs
			hang := make(chan struct{})
			var hits atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if hits.Add(1) == 1 {
					w.Write(first) //nolint:errcheck // a client which went away is not an error here
					return
				}
				select {
				case <-r.Context().Done():
				case <-hang:
					w.Write(first) //nolint:errcheck
				}
			}))
			defer srv.Close()
			defer close(hang)

			// the list is past its nextUpdate, so the loop waits only the retry floor
			old := crlRetryOnFailure
			crlRetryOnFailure = 100 * time.Millisecond
			defer func() { crlRetryOnFailure = old }()

			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			cfg := &CRLVerifier{
				CRLURLs: []string{srv.URL + "/crl"},
				Timeout: caddy.Duration(time.Minute),
			}
			if err := cfg.Provision(ctx); err != nil {
				t.Fatalf("provisioning: %v", err)
			}

			// wait for the loop's own second fetch, not the one Provision made
			for i := 0; i < 500 && hits.Load() < 2; i++ {
				time.Sleep(10 * time.Millisecond)
			}
			if hits.Load() < 2 {
				t.Fatal("the reload loop never made a second request")
			}

			start := time.Now()
			if tc.cancelContext {
				cancel()
			} else {
				// the context stays live, as after a failed Validate
				defer cancel()
			}
			if err := cfg.Cleanup(); err != nil {
				t.Errorf("cleaning up: %v", err)
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Errorf("cleanup took %v with a fetch in flight, which means the fetch was not interrupted", elapsed)
			}

			// the loop stopped, not just the one fetch
			before := hits.Load()
			time.Sleep(150 * time.Millisecond)
			if after := hits.Load(); after != before {
				t.Errorf("the reload loop kept running after Cleanup: %d requests became %d", before, after)
			}
		})
	}
}

func TestCRLVerifierConcurrentHandshakesAndReloads(t *testing.T) {
	pki := newCRLTestPKI(t)
	good, _ := pki.leaf(t, 7900)
	bad, _ := pki.leaf(t, 7901)

	// prepared on the test goroutine so the race detector watches only the verifier
	badDER, goodDER := rawDER(t, bad), rawDER(t, good)
	badChains, goodChains := pki.chainsFor(bad), pki.chainsFor(good)

	path := writeCRLDER(t, "issuing.crl", pki.crl(t, crlOptions{number: 1, revoked: []x509.RevocationListEntry{revokedEntry(7901)}}))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := v.VerifyClientCertificate(badDER, badChains); err == nil {
					t.Error("the revoked certificate was admitted")
					return
				}
				if err := v.VerifyClientCertificate(goodDER, goodChains); err != nil {
					t.Errorf("the certificate no CRL mentions was refused: %v", err)
					return
				}
			}
		}()
	}

	// reload while handshakes are in flight
	for number := int64(2); number <= 6; number++ {
		der := pki.crl(t, crlOptions{number: number, revoked: []x509.RevocationListEntry{revokedEntry(7901)}})
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: pemTypeCRL, Bytes: der}), 0o600); err != nil {
			t.Fatalf("writing the CRL: %v", err)
		}
		if _, err := v.reload(false); err != nil {
			t.Fatalf("reloading number %d: %v", number, err)
		}
	}

	close(stop)
	wg.Wait()
}
