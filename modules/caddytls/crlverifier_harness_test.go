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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// crlTestPKI is a throwaway root and issuing CA for these tests.
type crlTestPKI struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	issCert  *x509.Certificate
	issKey   *ecdsa.PrivateKey

	pool *x509.CertPool
}

// caPair is a CA certificate and its signing key.
type caPair struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCRLTestPKI(t testing.TB) *crlTestPKI {
	t.Helper()

	p := new(crlTestPKI)
	p.rootKey, p.rootCert = mintCA(t, "CRL Test Root CA", caPair{}, nil)
	p.issKey, p.issCert = mintCA(t, "CRL Test Issuing CA", caPair{p.rootCert, p.rootKey}, nil)

	p.pool = x509.NewCertPool()
	p.pool.AddCert(p.rootCert)
	p.pool.AddCert(p.issCert)

	return p
}

// serials keeps serial numbers distinct within one nanosecond.
var serials atomic.Int64

func uniqueSerial() *big.Int {
	return big.NewInt(time.Now().UnixNano() + serials.Add(1))
}

// mintCA makes a CA certificate. A nil parent means self-signed; a nil key means a fresh one.
func mintCA(t testing.TB, commonName string, parent caPair, key *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	var err error
	if key == nil {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating a key: %v", err)
		}
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          uniqueSerial(),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Caddy Test"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * 365 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	signer, signerKey := template, key
	if parent.cert != nil {
		signer, signerKey = parent.cert, parent.key
	}

	cert := createCert(t, template, signer, key.Public(), signerKey)
	return key, cert
}

// mintLeafUnder mints a client certificate under an arbitrary issuer.
func mintLeafUnder(t testing.TB, serial int64, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: fmt.Sprintf("client-%d", serial), Organization: []string{"Caddy Test"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return createCert(t, template, issuer, key.Public(), issuerKey), key
}

func createCert(t testing.TB, template, signer *x509.Certificate, pub any, signerKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, template, signer, pub, signerKey)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing a certificate: %v", err)
	}
	return cert
}

// leaf mints a client certificate with the given serial, signed by the issuing CA.
func (p *crlTestPKI) leaf(t testing.TB, serial int64) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return p.leafWithCDP(t, serial, "")
}

// leafWithCDP mints a client certificate naming crlURL as its distribution point.
func (p *crlTestPKI) leafWithCDP(t testing.TB, serial int64, crlURL string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: fmt.Sprintf("client-%d", serial), Organization: []string{"Caddy Test"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if crlURL != "" {
		template.CRLDistributionPoints = []string{crlURL}
	}
	return createCert(t, template, p.issCert, key.Public(), p.issKey), key
}

// serverLeaf mints a server certificate for localhost.
func (p *crlTestPKI) serverLeaf(t testing.TB) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: uniqueSerial(),
		Subject:      pkix.Name{CommonName: "localhost", Organization: []string{"Caddy Test"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	cert := createCert(t, template, p.issCert, key.Public(), p.issKey)

	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}
}

// crlOptions describes a CRL to mint; the zero value is a current, empty list.
type crlOptions struct {
	// issuer and signer default to the issuing CA; mismatching them forges a list
	issuer *x509.Certificate
	signer *ecdsa.PrivateKey
	number int64

	// crypto/x509 always writes these, so either option means handmadeCRL
	omitNumber   bool
	noNextUpdate bool

	thisUpdate time.Time
	nextUpdate time.Time
	revoked    []x509.RevocationListEntry
	exts       []pkix.Extension
}

func (p *crlTestPKI) crl(t testing.TB, opts crlOptions) []byte {
	t.Helper()
	return createCRL(t, p.issCert, p.issKey, opts)
}

func createCRL(t testing.TB, defaultIssuer *x509.Certificate, defaultSigner *ecdsa.PrivateKey, opts crlOptions) []byte {
	t.Helper()

	now := time.Now()
	if opts.issuer == nil {
		opts.issuer = defaultIssuer
	}
	if opts.signer == nil {
		opts.signer = defaultSigner
	}
	if opts.thisUpdate.IsZero() {
		opts.thisUpdate = now.Add(-time.Hour)
	}
	if opts.nextUpdate.IsZero() && !opts.noNextUpdate {
		opts.nextUpdate = now.Add(72 * time.Hour)
	}

	if opts.noNextUpdate || opts.omitNumber || hasEntryExtensions(opts.revoked) {
		list := handmadeCRL{
			issuer:     opts.issuer,
			signer:     opts.signer,
			thisUpdate: opts.thisUpdate,
			nextUpdate: opts.nextUpdate,
			exts:       opts.exts,
		}
		if !opts.omitNumber {
			list.number = big.NewInt(opts.number)
		}
		for _, entry := range opts.revoked {
			list.revoked = append(list.revoked, handmadeEntry{
				serial: entry.SerialNumber,
				at:     entry.RevocationTime,
				exts:   entryExtensions(t, entry),
			})
		}
		return list.der(t)
	}

	template := &x509.RevocationList{
		ThisUpdate:                opts.thisUpdate,
		NextUpdate:                opts.nextUpdate,
		RevokedCertificateEntries: opts.revoked,
		Number:                    big.NewInt(opts.number),
		// CreateRevocationList ignores Extensions
		ExtraExtensions: opts.exts,
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, opts.issuer, opts.signer)
	if err != nil {
		t.Fatalf("creating the CRL: %v", err)
	}
	return der
}

// hasEntryExtensions reports whether an entry needs handmadeCRL's encoder.
func hasEntryExtensions(entries []x509.RevocationListEntry) bool {
	for _, entry := range entries {
		if len(entry.Extensions) > 0 || entry.ReasonCode != 0 {
			return true
		}
	}
	return false
}

// entryExtensions returns an entry's extensions with its reason code encoded.
func entryExtensions(t testing.TB, entry x509.RevocationListEntry) []pkix.Extension {
	t.Helper()

	exts := entry.Extensions
	if entry.ReasonCode == 0 {
		return exts
	}
	// reasonCode is an ENUMERATED, which asn1.Marshal will not write for an int
	value := derEnumeration(entry.ReasonCode)
	return append([]pkix.Extension{{Id: oidReasonCode, Value: value}}, exts...)
}

// handmadeCRL writes a CRL element by element (RFC 5280 section 5.1), for
// the shapes crypto/x509 will not mint: no cRLNumber, no nextUpdate, or
// extensions on an entry.
type handmadeCRL struct {
	issuer *x509.Certificate // names and signs the list
	signer *ecdsa.PrivateKey

	number     *big.Int // nil leaves out the cRLNumber extension
	thisUpdate time.Time
	nextUpdate time.Time // zero leaves out nextUpdate
	revoked    []handmadeEntry
	exts       []pkix.Extension
}

// handmadeEntry is one revoked certificate.
type handmadeEntry struct {
	serial *big.Int
	at     time.Time
	exts   []pkix.Extension
}

// ecdsaWithSHA256 is the signature algorithm of every key these tests mint.
var ecdsaWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

func (h handmadeCRL) der(t testing.TB) []byte {
	t.Helper()

	if h.issuer == nil || h.signer == nil {
		t.Fatal("a CRL written by hand needs an issuer and the key to sign it with")
	}
	if h.thisUpdate.IsZero() {
		h.thisUpdate = time.Now().Add(-time.Hour)
	}

	// a v2 CRL is encoded as version 1 (RFC 5280 section 5.1.2.1)
	version := derInteger(t, big.NewInt(1))

	algorithm := derConstructed(0x30, derOID(t, ecdsaWithSHA256))
	elements := [][]byte{
		version,
		algorithm,
		h.issuer.RawSubject,
		derGeneralizedTime(h.thisUpdate),
	}
	if !h.nextUpdate.IsZero() {
		elements = append(elements, derGeneralizedTime(h.nextUpdate))
	}

	if len(h.revoked) > 0 {
		var entries [][]byte
		for _, entry := range h.revoked {
			parts := [][]byte{derInteger(t, entry.serial), derGeneralizedTime(entry.at)}
			if len(entry.exts) > 0 {
				parts = append(parts, derExtensions(t, entry.exts))
			}
			entries = append(entries, derConstructed(0x30, parts...))
		}
		elements = append(elements, derConstructed(0x30, entries...))
	}

	if h.number != nil || len(h.exts) > 0 {
		exts := make([]pkix.Extension, 0, len(h.exts)+1)
		if h.number != nil {
			value, err := asn1.Marshal(h.number)
			if err != nil {
				t.Fatalf("encoding the CRL number: %v", err)
			}
			exts = append(exts, pkix.Extension{Id: oidCRLNumber, Value: value})
		}
		exts = append(exts, h.exts...)
		elements = append(elements, derContext(0, true, derExtensions(t, exts)))
	}

	tbs := derConstructed(0x30, elements...)
	digest := sha256.Sum256(tbs)
	signature, err := ecdsa.SignASN1(rand.Reader, h.signer, digest[:])
	if err != nil {
		t.Fatalf("signing the CRL: %v", err)
	}
	list := derConstructed(0x30, tbs, algorithm, derElement(0x03, append([]byte{0}, signature...)))

	// parse it back so a bug in this encoder is not blamed on the module
	parsed, err := x509.ParseRevocationList(list)
	if err != nil {
		t.Fatalf("the hand-written CRL cannot be parsed, so its encoding is wrong: %v", err)
	}
	if err := parsed.CheckSignatureFrom(h.issuer); err != nil {
		t.Fatalf("the hand-written CRL does not verify against its issuer: %v", err)
	}
	return list
}

// derOID encodes an OBJECT IDENTIFIER.
func derOID(t testing.TB, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	element, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("encoding the object identifier %v: %v", oid, err)
	}
	return element
}

// derInteger encodes an INTEGER.
func derInteger(t testing.TB, n *big.Int) []byte {
	t.Helper()
	element, err := asn1.Marshal(n)
	if err != nil {
		t.Fatalf("encoding the number %v: %v", n, err)
	}
	return element
}

// derGeneralizedTime encodes a GeneralizedTime.
func derGeneralizedTime(when time.Time) []byte {
	return derElement(0x18, []byte(when.UTC().Format("20060102150405Z")))
}

// derEnumeration encodes an ENUMERATED.
func derEnumeration(value int) []byte {
	contents := big.NewInt(int64(value)).Bytes()
	if len(contents) == 0 || contents[0]&0x80 != 0 {
		contents = append([]byte{0}, contents...)
	}
	return derElement(0x0A, contents)
}

// derExtensions encodes an Extensions SEQUENCE.
func derExtensions(t testing.TB, exts []pkix.Extension) []byte {
	t.Helper()

	var encoded [][]byte
	for _, ext := range exts {
		parts := [][]byte{derOID(t, ext.Id)}
		if ext.Critical {
			parts = append(parts, derElement(0x01, []byte{0xFF}))
		}
		parts = append(parts, derElement(0x04, ext.Value))
		encoded = append(encoded, derConstructed(0x30, parts...))
	}
	return derConstructed(0x30, encoded...)
}

// crlSignedBy mints a current CRL for any CA, revoking the given serials.
func crlSignedBy(t testing.TB, issuer *x509.Certificate, key *ecdsa.PrivateKey, serials ...*big.Int) []byte {
	t.Helper()

	var entries []x509.RevocationListEntry
	for _, serial := range serials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Hour),
			ReasonCode:     reasonCACompromise,
		})
	}
	return createCRL(t, issuer, key, crlOptions{number: 1, revoked: entries})
}

// Revocation reason codes from RFC 5280 section 5.3.1.
const (
	reasonUnspecified     = 0
	reasonKeyCompromise   = 1
	reasonCACompromise    = 2
	reasonCertificateHold = 6
	reasonRemoveFromCRL   = 8
)

// revokedEntry is one entry revoking the certificate with the given serial.
func revokedEntry(serial int64) x509.RevocationListEntry {
	return x509.RevocationListEntry{
		SerialNumber:   big.NewInt(serial),
		RevocationTime: time.Now().Add(-time.Hour),
		ReasonCode:     reasonKeyCompromise,
	}
}

// writeLists writes CRLs to one PEM file in the test's temp dir and returns its path.
func writeLists(t testing.TB, name string, ders ...[]byte) string {
	t.Helper()

	return writeFile(t, name, writeCRLPEMBytes(ders...))
}

// overwriteLists replaces the file at path with these CRLs as PEM.
func overwriteLists(t testing.TB, path string, ders ...[]byte) {
	t.Helper()

	if err := os.WriteFile(path, writeCRLPEMBytes(ders...), 0o600); err != nil {
		t.Fatalf("writing %s: %v", filepath.Base(path), err)
	}
}

// writeCRLDER writes one DER CRL to a file and returns its path.
func writeCRLDER(t testing.TB, name string, der []byte) string {
	t.Helper()
	return writeFile(t, name, der)
}

func writeFile(t testing.TB, name string, contents []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// chainsFor builds the verified chain crypto/tls hands a verifier when the pool
// holds the issuing CA: it ends there, since Go stops at a trust anchor.
func (p *crlTestPKI) chainsFor(certs ...*x509.Certificate) [][]*x509.Certificate {
	chain := make([]*x509.Certificate, 0, len(certs)+1)
	chain = append(chain, certs...)
	if len(chain) > 0 && chain[len(chain)-1] != p.issCert {
		chain = append(chain, p.issCert)
	}
	return [][]*x509.Certificate{chain}
}

// chainsToRoot is chainsFor with the self-signed root appended.
func (p *crlTestPKI) chainsToRoot(certs ...*x509.Certificate) [][]*x509.Certificate {
	return [][]*x509.Certificate{append(p.chainsFor(certs...)[0], p.rootCert)}
}

func rawDER(t testing.TB, certs ...*x509.Certificate) [][]byte {
	t.Helper()
	raw := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		raw = append(raw, cert.Raw)
	}
	return raw
}

// requireAdmitted fails the test with why if the verifier refuses cert.
func (p *crlTestPKI) requireAdmitted(t *testing.T, v *CRLVerifier, cert *x509.Certificate, why string) error {
	t.Helper()
	return requireAdmitted(t, v, rawDER(t, cert), p.chainsFor(cert), why)
}

// requireRefused fails the test with why if the verifier admits cert.
func (p *crlTestPKI) requireRefused(t *testing.T, v *CRLVerifier, cert *x509.Certificate, why string) error {
	t.Helper()
	return requireRefused(t, v, rawDER(t, cert), p.chainsFor(cert), why)
}

// requireAdmitted fails the test with why if the verifier refuses the chain.
func requireAdmitted(t *testing.T, v *CRLVerifier, raw [][]byte, chains [][]*x509.Certificate, why string) error {
	t.Helper()

	err := v.VerifyClientCertificate(raw, chains)
	if err != nil {
		t.Fatalf("%s: %v", why, err)
	}
	return err
}

// requireRefused fails the test with why if the verifier admits the chain.
func requireRefused(t *testing.T, v *CRLVerifier, raw [][]byte, chains [][]*x509.Certificate, why string) error {
	t.Helper()

	err := v.VerifyClientCertificate(raw, chains)
	if err == nil {
		t.Fatal(why)
	}
	return err
}

// observeLogs swaps in a logger that records entries at level and above.
func observeLogs(t *testing.T, v *CRLVerifier, level zapcore.Level) *observer.ObservedLogs {
	t.Helper()

	core, logs := observer.New(level)
	previous := v.logger
	v.logger = zap.New(core)
	t.Cleanup(func() { v.logger = previous })

	return logs
}

// writeCRLPEMBytes encodes CRLs as a PEM bundle.
func writeCRLPEMBytes(ders ...[]byte) []byte {
	var out []byte
	for _, der := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: pemTypeCRL, Bytes: der})...)
	}
	return out
}

// newTestKey generates a fresh P-256 key.
func newTestKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	return key
}

// tlsCert assembles a certificate and key into what a tls.Config needs.
func tlsCert(t testing.TB, cert *x509.Certificate, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling the key: %v", err)
	}
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("assembling the client certificate: %v", err)
	}
	return pair
}

// handshake performs a TLS handshake over loopback and reports either side's
// error. crypto/tls reports a VerifyConnection failure to the peer as an alert,
// and under TLS 1.3 the client finishes first, so it is read back after Dial.
func handshake(server, client *tls.Config) error {
	listener, err := tls.Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		return err
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		tlsConn := conn.(*tls.Conn)
		err = tlsConn.Handshake()
		if err == nil {
			// keep reading so a TLS 1.3 refusal sent after the client finished is not lost
			if _, err = tlsConn.Read(make([]byte, 1)); errors.Is(err, io.EOF) {
				err = nil // orderly close
			}
		}
		serverErr <- err
		_ = tlsConn.Close()
	}()

	clientConn, err := tls.Dial("tcp", listener.Addr().String(), client)
	if err != nil {
		return errors.Join(err, <-serverErr)
	}
	defer clientConn.Close()

	// write so the server's read returns, then read until the peer hangs up
	_, _ = clientConn.Write([]byte{0})
	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var readErr error
	for {
		if _, err := clientConn.Read(make([]byte, 1)); err != nil {
			readErr = err
			break
		}
	}
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}

	// hang up, then collect the server's verdict with a deadline
	_ = clientConn.Close()
	select {
	case serr := <-serverErr:
		return errors.Join(serr, readErr)
	case <-time.After(10 * time.Second):
		return errors.Join(errors.New("the server never reported the outcome of its handshake"), readErr)
	}
}

// The helpers below build DER by hand; the nested context tags of RFC 5280
// are awkward to express with encoding/asn1 struct tags.

func derElement(tag byte, contents []byte) []byte {
	return append(append([]byte{tag}, derLength(len(contents))...), contents...)
}

func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var bytes []byte
	for ; n > 0; n >>= 8 {
		bytes = append([]byte{byte(n & 0xFF)}, bytes...)
	}
	return append([]byte{byte(0x80 | len(bytes))}, bytes...)
}

// derConstructed builds a constructed element with the tag and child elements given.
func derConstructed(tag byte, children ...[]byte) []byte {
	var contents []byte
	for _, child := range children {
		contents = append(contents, child...)
	}
	return derElement(tag, contents)
}

// derContext builds a context-specific [n] element.
func derContext(number int, constructed bool, contents []byte) []byte {
	tag := byte(0x80 | number)
	if constructed {
		tag |= 0x20
	}
	return derElement(tag, contents)
}

// mustDirectoryName wraps a DER name as the directoryName of a GeneralNames.
func mustDirectoryName(t testing.TB, rawSubject []byte) []byte {
	t.Helper()
	return derConstructed(0x30, derContext(4, true, rawSubject))
}

// mustIDPFullName encodes an issuingDistributionPoint with uri as its fullName,
// an implicit [0] replacing the SEQUENCE OF, as OpenSSL emits it.
func mustIDPFullName(t testing.TB, uri string) []byte {
	t.Helper()

	// uniformResourceIdentifier is [6] IA5String.
	name := derElement(0x86, []byte(uri))
	return derConstructed(0x30, derContext(0, true, derContext(0, true, name)))
}

// utf8SpellingOf encodes name with UTF8String values instead of the
// PrintableString Go picks: same rendering, different DER.
func utf8SpellingOf(t testing.TB, name pkix.Name) []byte {
	t.Helper()

	atv := func(oid []byte, value string) []byte {
		return derConstructed(0x30, derElement(0x06, oid), derElement(0x0C, []byte(value)))
	}
	var rdns [][]byte
	if len(name.Organization) > 0 {
		rdns = append(rdns, derConstructed(0x31, atv([]byte{0x55, 0x04, 0x0A}, name.Organization[0])))
	}
	rdns = append(rdns, derConstructed(0x31, atv([]byte{0x55, 0x04, 0x03}, name.CommonName)))
	return derConstructed(0x30, rdns...)
}

// renderedName is the string form of a DER name.
func renderedName(raw []byte) string {
	var seq pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		return "unparsable name"
	}
	var name pkix.Name
	name.FillFromRDNSequence(&seq)
	return name.String()
}

// assertNoCredentials fails if msg carries the secret or a masked form of it.
func assertNoCredentials(t testing.TB, msg, secret string) {
	t.Helper()
	for _, leak := range []string{secret, "reader@", "reader:xxx@", "reader:***@"} {
		if strings.Contains(msg, leak) {
			t.Errorf("the message leaks %q: %s", leak, msg)
		}
	}
}

// refusalLines counts log lines at level about unreadable lists naming about.
func refusalLines(logs *observer.ObservedLogs, about string, level zapcore.Level) int {
	const message = "a configured CRL source holds lists this module will not read"
	var n int
	for _, entry := range logs.FilterMessage(message).FilterLevelExact(level).All() {
		if strings.Contains(fmt.Sprint(entry.ContextMap()["refused"]), about) {
			n++
		}
	}
	return n
}

// heapAllocated is the live heap after a GC.
func heapAllocated() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// serviceNumbers returns the sorted cRLNumbers in service for issuer (nil: all).
func serviceNumbers(set *crlSet, issuer *x509.Certificate) []int64 {
	var lists []*parsedCRL
	if issuer == nil {
		for _, every := range set.byIssuer {
			lists = append(lists, every...)
		}
	} else {
		lists = set.byIssuer[string(issuer.RawSubject)]
	}
	var numbers []int64
	for _, crl := range lists {
		if crl.number != nil {
			numbers = append(numbers, crl.number.Int64())
		}
	}
	slices.Sort(numbers)
	return numbers
}
