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
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

const (
	// crlClockSkew is the tolerated clock difference between this host
	// and the CA, applied to thisUpdate and nextUpdate.
	crlClockSkew = 5 * time.Minute
)

// parsedCRL is a CRL parsed and indexed for lookup.
type parsedCRL struct {
	crl        *x509.RevocationList
	issuerKey  string // DER-encoded subject of the CRL's issuer; the lookup key
	issuerName string // human-readable issuer name
	revoked    map[string]revocationInfo

	thisUpdate time.Time
	nextUpdate time.Time
	number     *big.Int

	// sigVerdicts caches the signature check per issuer certificate,
	// so a large CRL is hashed once per issuer instead of once per
	// handshake. A parsedCRL lives only as long as the set holding it,
	// so an entry cannot go stale.
	sigMu       sync.Mutex
	sigVerdicts map[string]signatureVerdict
}

// maxSigVerdicts bounds the cache; past it the answer is still computed.
const maxSigVerdicts = 16

// signatureVerdict is one cached answer from signatureCheck.
type signatureVerdict struct {
	result verifyResult
	why    string
}

type revocationInfo struct {
	at     time.Time
	reason string
}

// akiKey is the CRL's authority key identifier as hex, or empty.
func (c *parsedCRL) akiKey() string {
	return hex.EncodeToString(c.crl.AuthorityKeyId)
}

// contentDigest identifies this exact CRL by its bytes.
func (c *parsedCRL) contentDigest() [sha256.Size]byte {
	return sha256.Sum256(c.crl.Raw)
}

// verifyResult is the outcome of checking a CRL against an issuer.
type verifyResult int

const (
	// the CRL names this issuer but was not signed by it: refuse
	verifyFailed verifyResult = iota
	// the CRL cannot speak for this chain; another one may
	verifySkipped
	// the CRL is signed by this issuer
	verifyOK
)

// verifiesAgainst reports whether this CRL was signed by issuer, with a
// reason when it was not. Names are not compared here; lookup did that.
func (c *parsedCRL) verifiesAgainst(issuer *x509.Certificate) (verifyResult, string) {
	if issuer == nil {
		return verifySkipped, "the chain holds no issuer certificate"
	}

	// if both sides name a key, they must agree; this keeps an old CRL
	// from being applied to a re-keyed CA with the same subject. It is
	// checked every time, outside the cache, because it depends on which
	// issuer certificate is in hand.
	if len(c.crl.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 &&
		!bytes.Equal(c.crl.AuthorityKeyId, issuer.SubjectKeyId) {
		return verifySkipped, fmt.Sprintf("its authority key id %s is not the subject key id %s of %s",
			hex.EncodeToString(c.crl.AuthorityKeyId), hex.EncodeToString(issuer.SubjectKeyId), issuer.Subject)
	}

	// CheckSignatureFrom hashes the whole CRL, so its answer is cached
	// per issuer DER; a certificate built in memory has no DER and is
	// checked every time
	if len(issuer.Raw) == 0 {
		return c.signatureCheck(issuer)
	}
	key := string(issuer.Raw)

	c.sigMu.Lock()
	defer c.sigMu.Unlock()
	if remembered, ok := c.sigVerdicts[key]; ok {
		return remembered.result, remembered.why
	}
	result, why := c.signatureCheck(issuer)
	if len(c.sigVerdicts) < maxSigVerdicts {
		if c.sigVerdicts == nil {
			c.sigVerdicts = make(map[string]signatureVerdict, 2)
		}
		c.sigVerdicts[key] = signatureVerdict{result: result, why: why}
	}
	return result, why
}

// signatureCheck is the only place a CRL signature is checked.
func (c *parsedCRL) signatureCheck(issuer *x509.Certificate) (verifyResult, string) {
	if err := c.crl.CheckSignatureFrom(issuer); err != nil {
		return verifyFailed, fmt.Sprintf("its signature by %s is not valid: %v", issuer.Subject, err)
	}
	return verifyOK, ""
}

// expiredAt reports whether the CRL is past nextUpdate plus clock skew.
// A CRL with no nextUpdate never expires (RFC 5280 section 5.1.2.5).
func (c *parsedCRL) expiredAt(now time.Time) bool {
	return !c.nextUpdate.IsZero() && now.After(c.nextUpdate.Add(crlClockSkew))
}

func (c *parsedCRL) numberText() string {
	if c.number == nil {
		return ""
	}
	return c.number.String()
}

// errUnsupportedCRL marks a CRL this module declines on principle (a
// delta CRL or one scoped to a distribution point), as opposed to one
// that is damaged. A declined CRL costs only itself; a damaged one fails
// the whole source. Package-internal: errors reaching an operator do not
// unwrap to it.
var errUnsupportedCRL = errors.New("unsupported CRL")

// unsupportedCRLError is one declined CRL and the reason.
type unsupportedCRLError struct{ why string }

func (e unsupportedCRLError) Error() string { return errUnsupportedCRL.Error() + ": " + e.why }

func (e unsupportedCRLError) Unwrap() error { return errUnsupportedCRL }

// errTrailingData reports bytes after the first DER CRL. Go parses the
// first CertificateList and ignores the rest, so a concatenated DER file
// would silently cover only its first issuer.
var errTrailingData = errors.New("trailing data after the CRL in this source")

// errPEMHeaderOffALine reports a PEM header that pem.Decode would skip
// because it does not begin a line (indentation, a byte-order mark, or
// prose quoting the marker).
var errPEMHeaderOffALine = errors.New("a PEM header in this source does not begin a line (text, whitespace or a byte-order mark stands before it), so any object beginning there is skipped by the reader")

// parseCRLs parses every CRL in raw: each PEM block holding one, or the
// whole body as a single DER CRL if there are no PEM headers. CRLs
// declined on principle are returned in refused rather than as an error,
// since they say nothing about the other CRLs in the same source.
func parseCRLs(raw []byte) (parsed []*parsedCRL, refused []string, err error) {
	raw = bytes.TrimPrefix(raw, utf8BOM)

	// pem.Decode skips an object it cannot finish without saying so, so
	// count the headers up front and compare with what was read
	headers := countPEMHeaders(raw)
	blocks := 0

	rest := raw
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		blocks++
		rest = remainder
		switch block.Type {
		case pemTypeCRL, pemTypeCRLShort:
			crl, err := parseOneCRL(block.Bytes)
			if declined, ok := errors.AsType[unsupportedCRLError](err); ok {
				refused = append(refused, declined.why)
				continue
			}
			if err != nil {
				return nil, nil, err
			}
			parsed = append(parsed, crl)
		default:
			// bundles may hold certificates and the like; skip them
			continue
		}
	}
	if headers == 0 {
		// no PEM headers, so read the body as one DER CRL
		crl, err := parseOneCRL(raw)
		if err != nil {
			if bytes.Contains(raw, pemStartHeader) {
				// a PEM header mid-line; "malformed DER" would mislead
				return nil, nil, errPEMHeaderOffALine
			}
			if declined, ok := errors.AsType[unsupportedCRLError](err); ok {
				return nil, nil, fmt.Errorf("reading this source as a single DER CRL: %s", declined.why)
			}
			return nil, nil, fmt.Errorf("reading this source as a single DER CRL: %w", err)
		}
		return []*parsedCRL{crl}, nil, nil
	}
	if bytes.Count(raw, pemStartHeader) != headers {
		// a header mid-line hides every object before the next readable
		// one, and the object count below cannot see it
		return nil, nil, errPEMHeaderOffALine
	}
	if countPEMHeaders(rest) > 0 {
		// pem.Decode stopped at an object it could not finish, which is
		// what a truncated download looks like
		return nil, nil, errors.New("the source ends in a PEM object which is damaged or cut short")
	}
	if blocks < headers {
		// an object between two readable ones was skipped, or a BEGIN
		// line has no END
		return nil, nil, errors.New("a PEM object in this source is damaged, cut short, or not an object this reader can decode")
	}

	if len(parsed) == 0 {
		if len(refused) > 0 {
			return nil, nil, fmt.Errorf("no CRL in this source could be used: %s", strings.Join(refused, "; "))
		}
		// usually a certificate bundle given by mistake
		return nil, nil, fmt.Errorf("this source holds %d PEM object(s) and none of them is a CRL", blocks)
	}
	return parsed, refused, nil
}

// pem.Decode only recognizes a BEGIN marker at the start of a line.
var (
	pemStartHeader = []byte("-----BEGIN ")
	pemLineHeader  = append([]byte("\n"), pemStartHeader...)

	pemTypeCRL      = "X509 CRL"
	pemTypeCRLShort = "CRL"

	// utf8BOM is trimmed, as OpenSSL does, so a file saved with one is
	// not refused for a header that is off its line
	utf8BOM = []byte("\xef\xbb\xbf")
)

// countPEMHeaders counts the PEM headers which begin a line.
func countPEMHeaders(raw []byte) int {
	n := bytes.Count(raw, pemLineHeader)
	if bytes.HasPrefix(raw, pemStartHeader) {
		n++
	}
	return n
}

// parseOneCRL parses and vets a single DER-encoded CRL.
func parseOneCRL(der []byte) (*parsedCRL, error) {
	if len(der) == 0 {
		return nil, errors.New("empty CRL")
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, err
	}
	if len(crl.Raw) != len(der) {
		return nil, errTrailingData
	}

	for _, ext := range crl.Extensions {
		switch {
		case ext.Id.Equal(oidIssuingDistributionPoint):
			// a CRL scoped to a distribution point covers only part of
			// a CA's certificates; treating it as complete would be
			// silent un-revocation, and telling a scope from a mere
			// address means interpreting the whole extension, so any
			// CRL carrying it is declined
			return nil, unsupportedCRLError{why: fmt.Sprintf("the list for %s carries extension %s: CRLs which declare a distribution point are not supported",
				crl.Issuer, ext.Id)}
		case ext.Id.Equal(oidDeltaCRLIndicator):
			// a delta CRL lists only changes since a base we do not hold
			return nil, unsupportedCRLError{why: fmt.Sprintf("the list for %s carries extension %s: delta CRLs are not supported",
				crl.Issuer, ext.Id)}
		case ext.Id.Equal(oidFreshestCRL):
			// harmless on a base CRL unless critical
			if ext.Critical {
				return nil, fmt.Errorf("critical extension %s on the list for %s: a base CRL which insists on delta CRLs is not supported",
					ext.Id, crl.Issuer)
			}
		case ext.Id.Equal(oidAuthorityKeyIdentifier), ext.Id.Equal(oidCRLNumber),
			ext.Id.Equal(oidAuthorityInfoAccess):
			// understood, or informational only
		default:
			if ext.Critical {
				return nil, fmt.Errorf("unknown critical CRL extension %s", ext.Id)
			}
		}
	}

	revoked := make(map[string]revocationInfo, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber == nil {
			return nil, errors.New("CRL entry without a serial number")
		}

		reason := revocationReason(entry.ReasonCode)
		for _, ext := range entry.Extensions {
			switch {
			case ext.Id.Equal(oidCertificateIssuer):
				// an entry revoked on behalf of another CA (RFC 5280
				// section 5.3.3); deciding which CA a serial belongs
				// to is out of scope, so the whole CRL is refused
				return nil, fmt.Errorf("CRL entry for serial %s carries extension %s: lists which revoke on behalf of another CA are not supported",
					entry.SerialNumber, ext.Id)
			case ext.Id.Equal(oidInvalidityDate):
				// informational only
			case ext.Id.Equal(oidReasonCode):
				// already decoded into ReasonCode, even if marked critical
			case ext.Critical:
				return nil, fmt.Errorf("unknown critical CRL entry extension %s", ext.Id)
			}
		}
		revoked[serialKey(entry.SerialNumber)] = revocationInfo{at: entry.RevocationTime, reason: reason}
	}

	// the entries are only needed to build the index; signature checks
	// work from the raw bytes
	crl.RevokedCertificateEntries = nil
	crl.RevokedCertificates = nil //nolint:staticcheck // the standard library fills both; neither is read again

	return &parsedCRL{
		crl:        crl,
		issuerKey:  string(crl.RawIssuer),
		issuerName: crl.Issuer.String(),
		revoked:    revoked,
		thisUpdate: crl.ThisUpdate,
		nextUpdate: crl.NextUpdate,
		number:     crl.Number,
	}, nil
}

// CRL extension OIDs (RFC 5280 section 5.2 and 5.3).
var (
	oidCRLNumber                = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidReasonCode               = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidCertificateIssuer        = asn1.ObjectIdentifier{2, 5, 29, 29}
	oidInvalidityDate           = asn1.ObjectIdentifier{2, 5, 29, 24}
	oidAuthorityKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidFreshestCRL              = asn1.ObjectIdentifier{2, 5, 29, 46}
	oidAuthorityInfoAccess      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

// revocationReason names the reason codes of RFC 5280 section 5.3.1.
func revocationReason(code int) string {
	switch code {
	case 0:
		return ""
	case 1:
		return "key compromise"
	case 2:
		return "CA compromise"
	case 3:
		return "affiliation changed"
	case 4:
		return "superseded"
	case 5:
		return "cessation of operation"
	case 6:
		return "certificate hold"
	case 8:
		return "removed from CRL"
	case 9:
		return "privilege withdrawn"
	case 10:
		return "attribute authority compromise"
	default:
		// 7 is unassigned
		return fmt.Sprintf("reason code %d", code)
	}
}

// serialKey is the map key for a serial number: its minimal big-endian
// bytes, which are the same however the number was encoded.
func serialKey(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	return string(serial.Bytes())
}

func compareNumbers(a, b *big.Int) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	default:
		return a.Cmp(b)
	}
}
