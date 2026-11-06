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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"
	"time"
)

func TestCRLVerifierSetIgnoresDuplicates(t *testing.T) {
	pki := newCRLTestPKI(t)

	// the same list from two sources is one list
	pemBundle := pem.EncodeToMemory(&pem.Block{Type: pemTypeCRL, Bytes: pki.crl(t, crlOptions{number: 1})})
	pemBundle = append(pemBundle, pemBundle...)
	crls, _, err := parseCRLs(pemBundle)
	if err != nil {
		t.Fatalf("parsing two copies: %v", err)
	}
	if len(crls) != 2 {
		t.Fatalf("expected both copies to parse, got %d", len(crls))
	}

	set := buildCRLSet(crls)
	if got := len(set.byIssuer[string(pki.issCert.RawSubject)]); got != 1 {
		t.Errorf("the same CRL twice became %d lists", got)
	}
	if set.summary() == "" {
		t.Error("the summary an operator is given should name what was loaded")
	}
}

func TestCRLVerifierIssuerNameFallback(t *testing.T) {
	// two legal DER encodings of one issuer name; the lookup keys on the encoding and
	// falls back to the rendered name only where that identifies exactly one CA
	const commonName = "Cross-Encoded Test CA"
	cnOID := asn1.ObjectIdentifier{2, 5, 4, 3}

	printableValue, err := asn1.MarshalWithParams(commonName, "printable")
	if err != nil {
		t.Fatalf("marshaling a printable string: %v", err)
	}
	printableDER, err := asn1.Marshal(pkix.RDNSequence{{{Type: cnOID, Value: asn1.RawValue{FullBytes: printableValue}}}})
	if err != nil {
		t.Fatalf("marshaling a printable name: %v", err)
	}
	// written by hand: encoding/asn1 re-encodes anything that fits a PrintableString
	// as one
	utf8Value := derElement(0x0C, []byte(commonName))
	utf8DER, err := asn1.Marshal(pkix.RDNSequence{{{Type: cnOID, Value: asn1.RawValue{FullBytes: utf8Value}}}})
	if err != nil {
		t.Fatalf("marshaling a utf8 name: %v", err)
	}
	if string(printableDER) == string(utf8DER) {
		t.Fatal("the two encodings are identical, so this test proves nothing")
	}

	rendered := pkix.Name{CommonName: commonName}.String()

	crlFor := func(issuerKey []byte, raw []byte) *parsedCRL {
		return &parsedCRL{
			crl:        &x509.RevocationList{Raw: raw},
			issuerKey:  string(issuerKey),
			issuerName: rendered,
			thisUpdate: time.Now(),
		}
	}

	t.Run("one ca re-encoded", func(t *testing.T) {
		set := buildCRLSet([]*parsedCRL{crlFor(utf8DER, []byte("a"))})
		cert := &x509.Certificate{RawIssuer: printableDER, Issuer: pkix.Name{CommonName: commonName}}
		issuer := &x509.Certificate{RawSubject: printableDER}

		crls := set.lookup(cert, issuer)
		if len(crls) != 1 {
			t.Fatalf("a CRL whose issuer name is encoded differently should be found by name, got %d candidates", len(crls))
		}
	})

	t.Run("two ca names which render the same", func(t *testing.T) {
		// two issuers whose rendered names collide: neither is reachable by name
		set := buildCRLSet([]*parsedCRL{crlFor(utf8DER, []byte("a")), crlFor(printableDER, []byte("b"))})

		cert := &x509.Certificate{RawIssuer: printableDER, Issuer: pkix.Name{CommonName: commonName}}
		issuer := &x509.Certificate{RawSubject: printableDER}
		if crls := set.lookup(cert, issuer); len(crls) != 1 {
			t.Errorf("the exact encoding should still be found without guessing, got %d candidates", len(crls))
		}

		// a third encoding matches neither key, and the rendered name is ambiguous
		thirdValue := derElement(0x16, []byte(commonName)) // IA5String
		thirdDER, err := asn1.Marshal(pkix.RDNSequence{{{Type: cnOID, Value: asn1.RawValue{FullBytes: thirdValue}}}})
		if err != nil {
			t.Fatalf("marshaling a third encoding: %v", err)
		}
		cert.RawIssuer = thirdDER
		issuer.RawSubject = thirdDER
		if crls := set.lookup(cert, issuer); len(crls) != 0 {
			t.Errorf("an ambiguous rendered name should not select a CRL for a differently-encoded issuer, got %d", len(crls))
		}
	})

	t.Run("an unrelated issuer", func(t *testing.T) {
		set := buildCRLSet([]*parsedCRL{crlFor(printableDER, []byte("a"))})
		_, unrelated := mintCA(t, "Unrelated CA", caPair{}, nil)
		cert := &x509.Certificate{RawIssuer: unrelated.RawSubject, Issuer: unrelated.Issuer}
		if crls := set.lookup(cert, unrelated); len(crls) != 0 {
			t.Errorf("a CRL was matched to an issuer it does not name, got %d", len(crls))
		}
	})

	t.Run("no issuer certificate in the chain", func(t *testing.T) {
		// without the issuer certificate there is no key to check a CRL's signature against
		set := buildCRLSet([]*parsedCRL{crlFor(printableDER, []byte("a"))})
		cert := &x509.Certificate{RawIssuer: printableDER, Issuer: pkix.Name{CommonName: commonName}}
		if crls := set.lookup(cert, nil); len(crls) != 0 {
			t.Errorf("no CRL may be used without the issuer certificate, got %d", len(crls))
		}
	})

	// a list naming its CA in a different encoding is signed by the real key, so it
	// must pass the signature check and revoke
	t.Run("a revocation reached through the fallback is enforced", func(t *testing.T) {
		key, ca := mintCA(t, commonName, caPair{}, nil)
		alt := *ca
		alt.RawSubject = utf8SpellingOf(t, ca.Subject)
		if bytes.Equal(alt.RawSubject, ca.RawSubject) {
			t.Fatal("the two encodings are identical, so this proves nothing")
		}
		if renderedName(alt.RawSubject) != renderedName(ca.RawSubject) {
			t.Fatalf("the re-encoded name renders differently: %q against %q",
				renderedName(alt.RawSubject), renderedName(ca.RawSubject))
		}

		bad, _ := mintLeafUnder(t, 7301, ca, key)
		good, _ := mintLeafUnder(t, 7302, ca, key)
		path := writeCRLDER(t, "re-encoded-issuer.crl", createCRL(t, &alt, key, crlOptions{
			number:  1,
			revoked: []x509.RevocationListEntry{revokedEntry(7301)},
		}))

		v := provisionCRLVerifier(t, &CRLVerifier{CRLFiles: []string{path}})
		chains := [][]*x509.Certificate{{bad, ca}}
		if err := v.VerifyClientCertificate(rawDER(t, bad), chains); err == nil {
			t.Error("a certificate revoked by a list whose issuer name is re-encoded was admitted")
		}
		if err := v.VerifyClientCertificate(rawDER(t, good), [][]*x509.Certificate{{good, ca}}); err != nil {
			t.Errorf("expected admission of the certificate no list mentions, got: %v", err)
		}
	})
}
