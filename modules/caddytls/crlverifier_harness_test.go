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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// crlTestPKI is a throwaway CA for these tests: a root, an issuing CA signed by it, and
// whatever leaves and CRLs a test asks for.
type crlTestPKI struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	issCert  *x509.Certificate
	issKey   *ecdsa.PrivateKey

	// pool is what client_auth's trust pool holds: the root and the issuing CA, either of
	// which can terminate a chain.
	pool *x509.CertPool
}

// caPair is a certificate together with the key it was issued to, for signing with.
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

// serials hands out distinct serial numbers, since a test which mints two certificates in the
// same nanosecond must not give them the same one.
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

// leafWithCDP mints a client certificate which names crlURL as its distribution point, which is
// how a real certificate refers to the list which speaks for it.
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

// serverLeaf mints a certificate the handshake test can serve: it names the host the client dials,
// which none of the client certificates do.
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

// crlOptions describes a CRL to mint. The zero value is a valid, empty, current list for the
// issuing CA with a number and a nextUpdate, which is what a healthy CA publishes.
type crlOptions struct {
	// issuer and signer are whose list this is and whose key signs it; the default pair is the
	// issuing CA signing its own list. A mismatch between them is how a forged CRL is made.
	issuer *x509.Certificate
	signer *ecdsa.PrivateKey
	number int64

	// omitNumber leaves out the cRLNumber extension and noNextUpdate leaves out nextUpdate. RFC
	// 5280 makes both optional and real CAs do without them, but crypto/x509 always encodes them,
	// so asking for either writes the list by hand; see handmadeCRL.
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
		// ExtraExtensions and not Extensions: CreateRevocationList ignores the latter, so a test
		// which set it would silently mint a list carrying none of the extensions it asked for.
		ExtraExtensions: opts.exts,
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, opts.issuer, opts.signer)
	if err != nil {
		t.Fatalf("creating the CRL: %v", err)
	}
	return der
}

// hasEntryExtensions reports whether any entry carries anything of its own, which is taken by hand
// so that the test — not crypto/x509 — decides the exact DER. CreateRevocationList reads an
// entry's ExtraExtensions and writes a ReasonCode itself, but ignores RevocationListEntry.Extensions
// outright, and these tests name extensions by identifier.
func hasEntryExtensions(entries []x509.RevocationListEntry) bool {
	for _, entry := range entries {
		if len(entry.Extensions) > 0 || entry.ReasonCode != 0 {
			return true
		}
	}
	return false
}

// entryExtensions is what a list says about one revoked certificate: the reason code spelled out
// as an extension, which is how it is carried on the wire, plus anything else the entry names.
func entryExtensions(t testing.TB, entry x509.RevocationListEntry) []pkix.Extension {
	t.Helper()

	exts := entry.Extensions
	if entry.ReasonCode == 0 {
		return exts
	}
	// A revocation reason is carried as an ENUMERATED, which encoding/asn1 will not write for an
	// int whatever its params say; crypto/x509 refuses a list whose reasonCode is an INTEGER.
	value := derEnumeration(entry.ReasonCode)
	return append([]pkix.Extension{{Id: oidReasonCode, Value: value}}, exts...)
}

// handmadeCRL is a CRL written out element by element, for the shapes crypto/x509 will not mint:
// RFC 5280 leaves cRLNumber and nextUpdate optional and lets an entry carry extensions of its own,
// and CreateRevocationList ignores both template.Extensions and the Extensions of every entry. A
// verifier which is only ever fed what the standard library can produce is untested against what
// other implementations publish.
//
//	CertificateList ::= SEQUENCE {
//	     tbsCertList        TBSCertList,
//	     signatureAlgorithm AlgorithmIdentifier,
//	     signatureValue     BIT STRING }
//	TBSCertList ::= SEQUENCE {
//	     version                 INTEGER OPTIONAL,
//	     signature               AlgorithmIdentifier,
//	     issuer                  Name,
//	     thisUpdate              Time,
//	     nextUpdate              Time OPTIONAL,
//	     revokedCertificates     SEQUENCE OF SEQUENCE {
//	         userCertificate         CertificateSerialNumber,
//	         crlEntryExtensions      Extensions OPTIONAL } OPTIONAL,
//	     crlExtensions           [0] EXPLICIT Extensions OPTIONAL }
type handmadeCRL struct {
	issuer *x509.Certificate // its subject names the list and its key signs it
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

	// The version of an RFC 5280 CRL is one less than the profile it belongs to: a v2 certificate
	// carries what is numbered a v1 CRL, and that is the only value a conforming reader takes.
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

	// Read back what was written. A mistake in this encoder would otherwise be mistaken for a bug
	// in the module under test, and it is the module which would get the blame.
	parsed, err := x509.ParseRevocationList(list)
	if err != nil {
		t.Fatalf("the hand-written CRL cannot be parsed, so its encoding is wrong: %v", err)
	}
	if err := parsed.CheckSignatureFrom(h.issuer); err != nil {
		t.Fatalf("the hand-written CRL does not verify against its issuer: %v", err)
	}
	return list
}

// derOID encodes an object identifier; asn1.Marshal writes the whole element, tag included.
func derOID(t testing.TB, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	element, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("encoding the object identifier %v: %v", oid, err)
	}
	return element
}

// derInteger encodes an INTEGER, which is how a serial number and a CRL number are written.
func derInteger(t testing.TB, n *big.Int) []byte {
	t.Helper()
	element, err := asn1.Marshal(n)
	if err != nil {
		t.Fatalf("encoding the number %v: %v", n, err)
	}
	return element
}

// derGeneralizedTime encodes a time as RFC 5280 requires CRL times to be written.
func derGeneralizedTime(when time.Time) []byte {
	return derElement(0x18, []byte(when.UTC().Format("20060102150405Z")))
}

// derEnumeration writes an ENUMERATED. Reason codes are small, but this keeps the sign bit honest
// for any value so that a test cannot mint a list whose DER is wrong in a way no CA would produce.
func derEnumeration(value int) []byte {
	contents := big.NewInt(int64(value)).Bytes()
	if len(contents) == 0 || contents[0]&0x80 != 0 {
		contents = append([]byte{0}, contents...)
	}
	return derElement(0x0A, contents)
}

// derExtensions encodes an Extensions, which is a SEQUENCE of extension; the value of each is the
// DER of its own type wrapped in an OCTET STRING.
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

// crlSignedBy mints a current, empty CRL for an arbitrary CA, revoking serials if any are given.
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

// The revocation reason codes of RFC 5280 section 5.3.1. crypto/x509 has no names for these:
// RevocationListEntry.ReasonCode is a bare integer enum, so a test which sets one says which.
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

// writeCRLPEM writes DER CRLs to a file in the test's temporary directory as PEM objects and
// returns its path. Several objects in one file is a bundle, which is how CAs publish them.
func writeCRLPEM(t testing.TB, name string, ders ...[]byte) string {
	t.Helper()

	return writeFile(t, name, writeCRLPEMBytes(ders...))
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

// chainsFor builds what crypto/tls hands a verifier for a certificate which verified against a
// pool holding the issuing CA and its root: the chain ends at the issuing CA, because a trust
// anchor is where Go stops building — it does not append the self-signed root above an anchor.
func (p *crlTestPKI) chainsFor(certs ...*x509.Certificate) [][]*x509.Certificate {
	chain := make([]*x509.Certificate, 0, len(certs)+1)
	chain = append(chain, certs...)
	if len(chain) > 0 && chain[len(chain)-1] != p.issCert {
		chain = append(chain, p.issCert)
	}
	return [][]*x509.Certificate{chain}
}

// chainsToRoot is chainsFor for a pool which holds only the root, so that the chain reaches the
// self-signed certificate and every CA in it has to answer for the one below it.
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

// writeCRLPEMBytes is a CRL bundle in the PEM form a distribution point serves, without naming a
// file, for a test which rewrites the same path over and over.
func writeCRLPEMBytes(ders ...[]byte) []byte {
	var out []byte
	for _, der := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})...)
	}
	return out
}

// newTestKey makes a key which belongs to nothing else in the test.
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

// handshake performs a TLS handshake over a loopback listener and reports whichever side refused.
// crypto/tls surfaces a failed VerifyConnection to the peer as an alert rather than to the local
// Dial, and with TLS 1.3 the client believes it finished first, so the refusal has to be read back
// after connecting. Both sides are then hung up by the client: the server goroutine is waiting to
// hear from it before it reports its own verdict, and in TLS 1.3 the session tickets which make a
// later connection resume arrive over the same read as an alert would.
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
			// Read until the peer is done with us, so that a TLS 1.3 refusal which arrives after
			// the client's own handshake completed is not lost.
			if _, err = tlsConn.Read(make([]byte, 1)); errors.Is(err, io.EOF) {
				err = nil // an ordinary end to the conversation
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

	// Say something so the server is not left waiting for a first byte, then read until the
	// conversation ends. A failed write is not necessarily the story — a refusal may already be on
	// its way — and the deadline bounds a peer which simply stops talking.
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

	// Hang up before collecting the verdict, then wait for it with a deadline of our own rather
	// than trusting both ends to be polite at once.
	_ = clientConn.Close()
	select {
	case serr := <-serverErr:
		return errors.Join(serr, readErr)
	case <-time.After(10 * time.Second):
		return errors.Join(errors.New("the server never reported the outcome of its handshake"), readErr)
	}
}

// The helpers below build extension values out of raw DER, element by element. They are written
// this way because the tagging in RFC 5280 nests context tags inside context tags, which struct
// tags express awkwardly, and because a parser which is only fed the shapes it would have written
// itself proves nothing: these produce what OpenSSL produces, checked against its own decoder.

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

// derContext builds a context-specific element, which is the [n] of an extension's ASN.1.
func derContext(number int, constructed bool, contents []byte) []byte {
	tag := byte(0x80 | number)
	if constructed {
		tag |= 0x20
	}
	return derElement(tag, contents)
}

// mustDirectoryName encodes a DER name as the directoryName alternative of GeneralNames, which is
// how an indirect CRL entry names the issuer whose certificate it revokes. The extension value is
// the whole GeneralNames, and GeneralNames is a SEQUENCE.
func mustDirectoryName(t testing.TB, rawSubject []byte) []byte {
	t.Helper()
	return derConstructed(0x30, derContext(4, true, rawSubject))
}

// mustIDPFullName encodes an issuingDistributionPoint extension scoped to a URI. The module refuses
// a list carrying this extension whatever it holds — the point of the rule is that it does not read
// the declaration — so this mints the plainest form which real CAs publish. distributionPoint is [0]
// around a DistributionPointName CHOICE, and
// fullName is an implicit [0] over a SEQUENCE OF, so its tag replaces the SEQUENCE and the names
// are the contents themselves:
//
//	30 1A A0 18 A0 16 86 14 http://...
//
// That is what OpenSSL emits and reads back; leaving a SEQUENCE inside the inner [0], it prints
// the extension as undecoded bytes instead.
func mustIDPFullName(t testing.TB, uri string) []byte {
	t.Helper()

	// uniformResourceIdentifier is [6] IA5String.
	name := derElement(0x86, []byte(uri))
	return derConstructed(0x30, derContext(0, true, derContext(0, true, name)))
}

// utf8SpellingOf writes a distinguished name with every attribute value spelled as a UTF8String
// instead of the PrintableString Go's own marshaling picks. The rendering is then unchanged and
// the DER encoding is not, which is exactly what a CA which re-encodes its subject when signing a
// CRL produces — and it is why matching encodings cannot be the only way to find a list.
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

// renderedName is how a certificate would say the name these bytes encode, which is the form two
// different encodings of one name agree on.
func renderedName(raw []byte) string {
	var seq pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		return "unparsable name"
	}
	var name pkix.Name
	name.FillFromRDNSequence(&seq)
	return name.String()
}

// assertNoCredentials fails if a message carries either half of a distribution point's credentials,
// in the exact form or in the masked form Go's http client renders.
func assertNoCredentials(t testing.TB, msg, secret string) {
	t.Helper()
	for _, leak := range []string{secret, "reader@", "reader:xxx@", "reader:***@"} {
		if strings.Contains(msg, leak) {
			t.Errorf("the message leaks %q: %s", leak, msg)
		}
	}
}

// refusalLines counts log lines at a given level reporting lists a source holds which this module
// will not read, where about names the CA whose list is expected to be named in them. The level is
// part of the question on purpose: what is said once loudly is said again quietly for as long as it
// stays true, and only the loud telling is what an operator should have to page through.
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

// heapAllocated is live heap after a collection, which is what "what does this cost to hold" means for
// a loaded CRL: the transient allocations of parsing are gone by then. Peak resident size during a load
// is several times this, since parsing a large list allocates as it goes; that number belongs to the
// machine and the garbage collector more than to this module, so it is not reported here.
func heapAllocated() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}
