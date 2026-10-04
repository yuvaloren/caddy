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

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/caddyserver/caddy/v2"
)

func TestCRLVerifierNumberRegression(t *testing.T) {
	pki := newCRLTestPKI(t)
	revokedCert, _ := pki.leaf(t, 9001)

	path := filepath.Join(t.TempDir(), "issuing.crl")
	write := func(number int64, entries []x509.RevocationListEntry) {
		t.Helper()
		der := pki.crl(t, crlOptions{number: number, revoked: entries})
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o600); err != nil {
			t.Fatalf("writing the CRL: %v", err)
		}
	}

	// The CA publishes number 5, which revokes the certificate.
	write(5, []x509.RevocationListEntry{revokedEntry(9001)})
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	if err := v.VerifyClientCertificate(rawDER(t, revokedCert), pki.chainsFor(revokedCert)); err == nil {
		t.Fatal("the revoked certificate was admitted")
	}

	// Something then serves an older list for the same issuer which does not mention it. Without
	// a number check that silently un-revokes the certificate.
	write(4, nil)
	if _, err := v.reload(false); err == nil {
		t.Error("a CRL older than one already loaded was accepted")
	}
	if err := v.VerifyClientCertificate(rawDER(t, revokedCert), pki.chainsFor(revokedCert)); err == nil {
		t.Error("the older CRL un-revoked a certificate the newer one had revoked")
	}

	// A fresh number is believed again.
	write(6, nil)
	if _, err := v.reload(false); err != nil {
		t.Fatalf("a newer CRL was refused: %v", err)
	}
	if err := v.VerifyClientCertificate(rawDER(t, revokedCert), pki.chainsFor(revokedCert)); err != nil {
		t.Errorf("the revocation is gone from number 6, so it should be believed now, got: %v", err)
	}

	// A config reload starts from scratch, which is the documented remedy for a CA which really
	// has rolled its CRL number back.
	fresh := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	if err := fresh.VerifyClientCertificate(rawDER(t, revokedCert), pki.chainsFor(revokedCert)); err != nil {
		t.Errorf("after a reload the current CRL should be believed again, got: %v", err)
	}
}

// TestCRLVerifierAnOlderListAloneAfterANewerOneIsRefused is the second shape of a rollback: a
// distribution point serves an overlap once and afterwards only the older half of it. That older list
// is one this very source has served, so the exemption which exists to let an overlap survive a
// reload (see regressed) would wave it through on its own — and the revocation only the newer list
// carried would be gone, with nothing but an Info line about what was loaded.
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

	// The overlap ends and only number 5 is served again. There is nothing wrong with that list by
	// itself — the CA signed it — but this source has already served number 6, so believing number 5
	// alone would undo what has been published since.
	if err := os.WriteFile(path, writeCRLPEMBytes(older), 0o600); err != nil {
		t.Fatalf("writing the older list: %v", err)
	}
	if _, err := v.reload(false); err == nil {
		t.Error("a source which went back to an older list it had already served was accepted")
	}
	if err := v.VerifyClientCertificate(rawDER(t, revokedCert), pki.chainsFor(revokedCert)); err == nil {
		t.Error("the older list alone un-revoked a certificate the newer list had revoked")
	}

	// Serving it again beside a newer list does not rehabilitate it. The exemption is for bytes this
	// source has accepted and still holds — an overlap which never left the set (see
	// TestCRLVerifierOverlapSurvivesAReload) — and this one was refused, so nothing here vouches for
	// it any more. What the refusal costs is the noise and nothing else: number 7 is accepted, and
	// number 6 — the list this source last had for this issuer — stands in beside it, which is what
	// the assertions below check rather than leaving the next step to imply it.
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
	var numbers []int64
	for _, crl := range v.current().byIssuer[string(pki.issCert.RawSubject)] {
		if crl.number != nil {
			numbers = append(numbers, crl.number.Int64())
		}
	}
	slices.Sort(numbers)
	// Number 7 was accepted, and number 6 — the list this source last had which spoke for this
	// issuer — stands in for the one which was refused. What must not be here is number 5: coverage
	// continues on the newer lists while the refusal is reported, rather than the set losing the
	// issuer or dropping back to the list which undid a publication.
	if len(numbers) != 2 || numbers[0] != 6 || numbers[1] != 7 {
		t.Errorf("expected the two newer lists — 6 and 7 — in service after the refusal, got %v", numbers)
	}

	// The source recovers on its own as soon as it serves something newer than what it last accepted.
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

	// EJBCA's issuing CRL carries no cRLNumber at all, so a CA which does not publish one must
	// still be usable; numbers are only compared when both lists have one.
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

	// A numbered list from the same issuer raises this source's mark. Nothing has been compared to
	// do it: the un-numbered list said nothing about order, and neither did this one.
	write(pki.crl(t, crlOptions{number: 3}))
	if _, err := v.reload(false); err != nil {
		t.Fatalf("a first numbered list was refused: %v", err)
	}

	// An un-numbered list afterwards cannot be shown to be older. Reading its absent number as zero
	// would refuse it against that mark, and a CA which never published one — or stopped — would
	// find every client refused for the shape of its CRL rather than its contents.
	write(pki.crl(t, crlOptions{omitNumber: true}))
	if _, err := v.reload(false); err != nil {
		t.Errorf("a list without a cRLNumber was compared against a numbered one: %v", err)
	}
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err != nil {
		t.Errorf("the un-numbered list should still be usable, got: %v", err)
	}

	// And the mark it left behind still stands: what one list declined to say is not licence for
	// the next to go backwards.
	write(pki.crl(t, crlOptions{number: 2}))
	core, logs := observer.New(zapcore.ErrorLevel)
	v.logger = zap.New(core)
	_, reloadErr := v.reload(false)
	if reloadErr == nil {
		t.Fatal("a numbered list below one this source served before was accepted")
	}
	if !strings.Contains(reloadErr.Error(), "is older than one this source served before") {
		t.Errorf("the refusal should name the rollback, got: %v", reloadErr)
	}

	// Nothing stands in for a list which has no number to have stood in before, so this source now
	// covers nobody and the set in service is emptied rather than left holding the list it no longer
	// serves. A certificate whose revocation status cannot be established is refused: that is what
	// the refusal above promised an operator, and leaving the previous snapshot standing would admit
	// on it instead (see reload).
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
	// The set holds nothing at all by this point, and the refusal has to read as that state rather
	// than as a sentence whose list went missing.
	if !strings.Contains(err.Error(), "no CRL is loaded at all") {
		t.Errorf("the refusal should say that no CRL is loaded, got: %v", err)
	}
	// The change of state is said out loud too. No "loaded CRLs" line can describe an empty set —
	// there is no list to name — and a log full of per-source fetch errors does not read as
	// "nothing answers for any issuer any more", which is what every handshake now meets.
	if !strings.Contains(reloadErr.Error(), "no earlier list from this source covers") {
		t.Errorf("the refusal should say nothing is left standing in for this issuer, got: %v", reloadErr)
	}
	if want := pki.issCert.Subject.String(); !strings.Contains(reloadErr.Error(), "covers "+want) {
		t.Errorf("the refusal should name %s as the issuer left with nothing, got: %v", want, reloadErr)
	}
	if got := len(logs.FilterMessage("no CRL is in service").All()); got != 1 {
		t.Errorf("%d lines announced that no CRL is in service, want 1", got)
	}

	// And once per transition into that state rather than once per process: an operator who watched the
	// door close, saw it reopen, and is watching it close again needs to be told again. An un-numbered
	// list reopens it — there is nothing to compare it against, so nothing to refuse — and going
	// backwards a second time empties the set once more, with the same nothing standing in.
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

	// Staying in that state is not a new incident. The refusal repeats on every refresh while the file
	// says the same thing, so without this the line would be written once per cycle and the count would
	// stop meaning anything.
	if _, err := v.reload(false); err == nil {
		t.Fatal("a numbered list below the mark was accepted on a later refresh")
	}
	if got := len(logs.FilterMessage("no CRL is in service").All()); got != 2 {
		t.Errorf("%d lines announced that no CRL is in service after a refresh which changed nothing, want 2", got)
	}
}

// TestCRLVerifierAKeyIDPublishedMidOverlapIsNotARollback is the overlap of
// TestCRLVerifierOverlapSurvivesAReload seen from the day a CA starts publishing its authority key
// id. The older list carries no key id, because that is how this CA published before; the newer one
// names its key. Comparing the two strictly by key id finds nothing to compare — which is not the
// same as finding no rollback, because the mark for a key id never stated has to stand against a
// list which now states one. If the batch's own highest list were looked for only among lists with
// the same key id, the older list is measured against that new mark alone and refused as a rollback
// of a key it never signed with that key: reported on every refresh which serves it, and — where the
// newer list is the one not yet valid, which is what an overlap usually exists for — leaving the
// issuer to answer from a list which cannot answer yet.
func TestCRLVerifierAKeyIDPublishedMidOverlapIsNotARollback(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 9501)

	// A list written by hand: numbered, and with no nextUpdate so that it stays current for the
	// whole test. crypto/x509 always writes both, which is why asking for either takes the handmade
	// path — and that path is what leaves a list without an authority key id, as CRLs from a CA which
	// does not publish one look.
	older := pki.crl(t, crlOptions{number: 5, noNextUpdate: true})
	middle := pki.crl(t, crlOptions{number: 6, noNextUpdate: true})
	// A list the way Go writes it, which is with the issuer's subject key id published as its own.
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

	// The overlap first, both lists published the old way: this source's mark for the issuer is now
	// number 6, and number 5 sits beside it still saying everything 6 does.
	path := writeFile(t, "issuing.crl", writeCRLPEMBytes(older, middle))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	// The CA publishes its key id from here on, and keeps the older list beside the new one. Number 5
	// is below what this source has served, so it is measured against that mark — and the only thing
	// in this fetch above the mark names a key which 5 never claimed to be signed by.
	if err := os.WriteFile(path, writeCRLPEMBytes(older, newer), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.reload(false); err != nil {
		t.Errorf("a CA which started publishing its key id mid-overlap was refused: %v", err)
	}

	set := v.current()
	var numbers []int64
	for _, crl := range set.byIssuer[string(pki.issCert.RawSubject)] {
		if crl.number != nil {
			numbers = append(numbers, crl.number.Int64())
		}
	}
	slices.Sort(numbers)
	if len(numbers) != 2 || numbers[0] != 5 || numbers[1] != 7 {
		t.Errorf("expected both overlapping lists — 5 and 7 — in service, got %v", numbers)
	}
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err != nil {
		t.Errorf("a certificate covered by the overlap was refused: %v", err)
	}
}

// TestCRLVerifierNumberRegressionIsScopedToItsOwnSigningKey pins what a cRLNumber is comparable
// against: the same source's word about one issuer under one signing key. Two CAs which share a
// name, or one CA which has changed its key and started numbering again, are not a rollback.
func TestCRLVerifierNumberRegressionIsScopedToItsOwnSigningKey(t *testing.T) {
	pki := newCRLTestPKI(t)

	// A second CA with a name identical to the issuing CA's, and a different key: its CRLs carry
	// the same issuer name and a different authority key identifier. The two have nothing to say
	// about each other's counters.
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
		// A source which reports a rollback keeps what it had: the list which did not regress and
		// the newer copy of the one which did, never the older one.
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

// TestCRLVerifierOverlapSurvivesAReload is the second half of the story told by
// TestCRLVerifierNotYetValidListDoesNotHideAnOlderOne: the older list has to still be there after
// the module has read its file once. Judging each list against a high-water mark which the same
// batch just raised makes a healthy file a failing source on its second load, dropping the only
// current word about that CA and refusing every client for the length of the overlap.
func TestCRLVerifierOverlapSurvivesAReload(t *testing.T) {
	pki := newCRLTestPKI(t)
	client, _ := pki.leaf(t, 7850)

	notYet := pki.crl(t, crlOptions{
		number:     2,
		thisUpdate: time.Now().Add(10 * time.Minute),
		nextUpdate: time.Now().Add(72 * time.Hour),
	})
	current := pki.crl(t, crlOptions{number: 1})
	path := writeCRLPEM(t, "issuing.crl", notYet, current)

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

// TestCRLVerifierABatchWhichRegressesTwoIssuersWordsThemApart is a rollback report in the shape an
// operator actually gets it: one file holding a list for two CAs, both of them behind what this source
// already loaded. One has an earlier copy which can be shown to stand above the refused list — Root 3
// beside the refused Root 2 — and the other has nothing, because what it last accepted carried no number
// and an un-numbered list cannot be shown to be above anything. Both halves of the report therefore have
// to come from one reload, and they are not interchangeable: one issuer needs its CA looked at, the other
// is a source which stopped speaking for a CA it used to cover, whose clients are refused as uncovered
// until it serves a list at or above the number again.
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

	// The issuing CA's list loses its number, which leaves its mark at 3 with nothing later able to
	// compare against it. That is what makes the two issuers differ below rather than the test needing
	// two sources or a hand-built call to the wording helper.
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

	// Both issuers had a list refused, so both are named...
	for _, want := range []string{issuingDN, rootDN} {
		if !strings.Contains(message, want) {
			t.Errorf("the refusal should name %s, got: %s", want, message)
		}
	}
	// ...but only the one with nothing standing in is reported as left uncovered, and that half names
	// exactly one issuer. Saying it about the other would send an operator looking for a CRL which is
	// loaded and answering right now, so matching on containment is not enough here: the sentence is
	// read out and compared, list and all.
	const uncoveredPrefix = "no earlier list from this source covers "
	if _, rest, found := strings.Cut(message, uncoveredPrefix); !found {
		t.Errorf("the refusal should say an issuer is left with nothing, got: %s", message)
	} else if named, _, _ := strings.Cut(rest, ", so unless another source does"); named != issuingDN {
		t.Errorf("the refusal names %q as left with nothing, want only %q — got: %s", named, issuingDN, message)
	}

	// The set says the same thing the report does: Root 3 still answers for its own clients, and the
	// issuing CA has nothing in service — so a certificate under it is refused as uncovered rather than
	// admitted on a list this source can no longer place in time.
	set := v.current()
	if set == nil {
		t.Fatal("no CRL set is in use")
	}
	var rootNumbers []int64
	for _, crl := range set.byIssuer[string(pki.rootCert.RawSubject)] {
		if crl.number != nil {
			rootNumbers = append(rootNumbers, crl.number.Int64())
		}
	}
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

// TestCRLVerifierARefusingBundleIsRememberedOncePerReload is about what a source keeps between refreshes.
// A bundle holding a stale sibling has that sibling refused on every refresh, and each refresh parses the
// file into new objects: if the list standing in for a refusal were chosen from everything remembered, an
// earlier parse of a kept list would stand in beside its fresh copy and be remembered alongside it — so
// the source would hold another whole parsed CRL, revoked entries and raw bytes included, on every retry,
// for as long as the stale list is served. Nothing in the set in service can show this, because the set
// indexes by content and drops copies of itself; only what is remembered grows, quietly, under a source
// whose whole visible symptom is one log line per cycle.
func TestCRLVerifierARefusingBundleIsRememberedOncePerReload(t *testing.T) {
	pki := newCRLTestPKI(t)

	path := writeFile(t, "bundle.pem", writeCRLPEMBytes(pki.crl(t, crlOptions{number: 4})))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})

	// The current list beside a stale one this source has never accepted for that issuer. Every refresh
	// refuses the stale list and takes an earlier copy to stand in for it, which is right once and would
	// accumulate every time after if "earlier" were read out of the remembered lists rather than the
	// distinct ones.
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
		// The set in service says the same thing across all three refreshes: number 5 answers, and 4
		// is there because the refusal below it needs something to leave behind.
		var numbers []int64
		for _, crl := range v.current().byIssuer[string(pki.issCert.RawSubject)] {
			if crl.number != nil {
				numbers = append(numbers, crl.number.Int64())
			}
		}
		if !slices.Equal(numbers, []int64{5, 4}) {
			t.Errorf("after refresh %d the issuer is answered by lists %v, want [5 4]", i, numbers)
		}
	}
}

// TestCRLVerifierAReplayedOlderListIsRefusedEvenBesideAFutureDatedOne is the overlap of
// TestCRLVerifierOverlapSurvivesAReload with a stranger in it. There the two lists are ones this
// source has served before, so neither is a step backwards; here the older list arrives for the
// first time at a number below what the same source already served. Answering from it would undo
// what the superseded list said about this serial — and it would be able to, because the newer list
// beside it has a thisUpdate ahead of this clock and cannot answer yet. So it is refused as the
// rollback it is, and the superseded list keeps answering until the new one comes into validity.
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
	core, logs := observer.New(zapcore.ErrorLevel)
	v.logger = zap.New(core)

	if _, err := v.reload(false); err == nil {
		t.Error("a source which went backwards was accepted")
	}
	// The module's own words for what happened, not a generic failure line.
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
	var numbers []int64
	for _, crl := range set.byIssuer[string(pki.issCert.RawSubject)] {
		if crl.number != nil {
			numbers = append(numbers, crl.number.Int64())
		}
	}
	slices.Sort(numbers)
	// The future-dated list this batch was allowed to raise, and the list this source had already
	// accepted standing in for the refused copy — not the replayed number 4.
	if len(numbers) != 2 || numbers[0] != 5 || numbers[1] != 6 {
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

// TestCRLVerifierASourceWhichStartsFailingDifferentlyIsAnnouncedAgain is about the log's memory. A
// source which stays broken is reported once rather than on every poll, which is right — but the set of
// failing sources says nothing about what a source is now doing wrong, and the two problems an operator
// can act on are different: a distribution point which cannot be reached at all, and one which has
// started serving a list older than the one it served before. The second is the only refusal which names
// the issuers left with nothing standing in for them, so a source which was 404ing for hours and then
// begins rolling back would otherwise change the world for the clients under that CA without a line ever
// reaching the log above debug.
func TestCRLVerifierASourceWhichStartsFailingDifferentlyIsAnnouncedAgain(t *testing.T) {
	pki := newCRLTestPKI(t)

	path := writeFile(t, "issuing.crl", writeCRLPEMBytes(pki.crl(t, crlOptions{number: 3})))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
	core, logs := observer.New(zapcore.ErrorLevel)
	v.logger = zap.New(core)

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

	// The file comes back, and what it serves goes backwards instead.
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

// TestCRLVerifierAnIssuerAnotherSourceStillCoversIsNamedButNotLost pins both halves of a rollback at one
// of two sources: another distribution point for the same CA keeps answering, so no client is turned
// away, and yet the source which rolled back has to be named — its own word about that CA is what went
// backwards, and an operator reading only "everything is covered" would never learn that one of the two
// places publishing this CA's revocations has started serving the past.
func TestCRLVerifierAnIssuerAnotherSourceStillCoversIsNamedButNotLost(t *testing.T) {
	pki := newCRLTestPKI(t)

	rolling := writeFile(t, "rolling.pem", writeCRLPEMBytes(pki.crl(t, crlOptions{number: 3})))
	steady := writeFile(t, "steady.pem", writeCRLPEMBytes(pki.crl(t, crlOptions{number: 5})))
	v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{rolling, steady}})

	// The rolling source's last accepted list carries no number, so nothing can stand in for it when it
	// goes backwards; the steady source is untouched.
	if err := os.WriteFile(rolling, writeCRLPEMBytes(pki.crl(t, crlOptions{omitNumber: true})), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.reload(false); err != nil {
		t.Fatalf("a list without a number was refused beside a higher one from another source: %v", err)
	}
	if err := os.WriteFile(rolling, writeCRLPEMBytes(pki.crl(t, crlOptions{number: 2})), 0o600); err != nil {
		t.Fatal(err)
	}

	core, logs := observer.New(zapcore.ErrorLevel)
	v.logger = zap.New(core)
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

	// And nothing about that CA is uncovered: the steady source's number 5 answers on its own, so a
	// client under this CA is still admitted while the other source is refused.
	client, _ := pki.leaf(t, 7892)
	if err := v.VerifyClientCertificate(rawDER(t, client), pki.chainsFor(client)); err != nil {
		t.Errorf("a certificate covered by the source which did not roll back was refused: %v", err)
	}
	if got := len(v.current().byIssuer[string(pki.issCert.RawSubject)]); got != 1 {
		t.Errorf("%d lists are in service for that issuer, want only the steady source's", got)
	}
}

// TestCRLVerifierTwoListsRefusedForOneIssuerNameItOnce is about the report reading as one sentence about
// one CA. A bundle can hold two lists for the same issuer and lose both — a CA which published 2 beside
// a stale 1 after this source saw 3, say — and the refusal is about that CA either way. Listing its name
// twice reads as two separate problems, and an operator counting names counts issuers they have to chase.
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
	// What answers for that CA is the number this source served before, which stands in below both
	// refusals — so the report names one problem and coverage does not move.
	var numbers []int64
	for _, crl := range v.current().byIssuer[string(pki.issCert.RawSubject)] {
		if crl.number != nil {
			numbers = append(numbers, crl.number.Int64())
		}
	}
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

	// Nothing sets how often a source is fetched — it comes from the list's own lifetime — so this
	// publishes one which is already past due and shortens the floor on refetching, which is what
	// a behind-the-times publisher leaves us with.
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
	// Tearing the module down must not wait for a fetch it has in flight. A hung distribution point
	// would otherwise stall a config change for the whole client timeout, which is a minute here —
	// so nothing but cancellation can end the test quickly, which is the point.
	//
	// Both orders are Caddy's: between configs the context is canceled first (tls.go), while a
	// module whose Validate fails is cleaned up with its context still live. The second order can
	// only be satisfied by Cleanup canceling the reload itself, so it is tested on its own rather
	// than left to whichever order happens to be exercised.
	for _, tc := range []struct {
		name          string
		cancelContext bool
	}{
		{"cleanup alone, with the context still live", false},
		{"the context canceled first, as between configs", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := newCRLTestPKI(t)
			first := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: pki.crl(t, crlOptions{
				number:     1,
				thisUpdate: time.Now().Add(-3 * time.Hour),
				nextUpdate: time.Now().Add(-time.Hour),
			})})

			// The distribution point answers the first request and then stops answering, which is
			// what an unresponsive CA looks like from here.
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

			// Nothing configures how often a source is fetched, so make the loop want to come back
			// soon: a list which is already past its nextUpdate leaves the retry floor, and that
			// floor is what this test shortens.
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

			// Wait for the loop's own second fetch to be in flight. The reload which hangs has to be
			// the one Cleanup is responsible for; a fetch started by Provision would say nothing
			// about that.
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
				// Nothing else is going to end this fetch, and the parent context stays live exactly
				// as it does when Caddy cleans up after a failed Validate.
				defer cancel()
			}
			if err := cfg.Cleanup(); err != nil {
				t.Errorf("cleaning up: %v", err)
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Errorf("cleanup took %v with a fetch in flight, which means the fetch was not interrupted", elapsed)
			}

			// The other half of the promise: the loop stopped rather than merely losing one fetch, so
			// no further requests are made once Cleanup has returned.
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

	// Everything a handshake needs is prepared on the test goroutine: crypto and testing helpers
	// are not what this is looking for races in.
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

	// Reload while handshakes are in flight. The set is replaced rather than edited, so a reader
	// either sees the whole previous list or the whole new one.
	for number := int64(2); number <= 6; number++ {
		der := pki.crl(t, crlOptions{number: number, revoked: []x509.RevocationListEntry{revokedEntry(7901)}})
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o600); err != nil {
			t.Fatalf("writing the CRL: %v", err)
		}
		if _, err := v.reload(false); err != nil {
			t.Fatalf("reloading number %d: %v", number, err)
		}
	}

	close(stop)
	wg.Wait()
}
