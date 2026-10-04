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
	"time"
)

const (
	// crlClockSkew is how far in the future a CRL's thisUpdate may be before the list is
	// considered unusable, tolerating modest differences between clocks.
	crlClockSkew = 5 * time.Minute
)

// parsedCRL is a CRL which has been parsed and indexed for lookup. Serials are keyed by the
// minimal big-endian bytes of the number, so no comparison here can be defeated by a
// different rendering of the same serial.
type parsedCRL struct {
	crl        *x509.RevocationList
	issuerKey  string // DER-encoded subject of the CRL's issuer; the lookup key
	issuerName string // human-readable issuer name
	revoked    map[string]revocationInfo

	thisUpdate time.Time
	nextUpdate time.Time
	number     *big.Int
}

type revocationInfo struct {
	at     time.Time
	reason string
}

// akiKey is the authority key identifier of a list in a form usable as part of a map value, empty
// when the list does not carry one. EJBCA's issuing CRL does; most others do too.
func (c *parsedCRL) akiKey() string {
	return hex.EncodeToString(c.crl.AuthorityKeyId)
}

// contentDigest identifies this exact list by its bytes. It is computed rather than remembered, so
// that it cannot disagree with the list it describes, and because both of its uses — dropping a
// list which arrived twice, and recognising one this source has already accepted — happen on the
// reload path, where hashing a CRL is nothing beside fetching it.
func (c *parsedCRL) contentDigest() [sha256.Size]byte {
	return sha256.Sum256(c.crl.Raw)
}

// verifyResult is the outcome of asking whether a CRL was signed by a given certificate.
type verifyResult int

const (
	// verifyFailed means the list names that issuer but was not signed by it, which is a
	// reason to refuse a connection rather than to look elsewhere.
	verifyFailed verifyResult = iota
	// verifySkipped means the list cannot speak for this chain at all, so another one may.
	verifySkipped
	// verifyOK means the list is signed by that certificate.
	verifyOK
)

// verifiesAgainst reports whether this CRL was signed by issuer, where issuer is a certificate
// which chain verification has already accepted. The second result explains the outcome, and for
// a failure it is the reason an operator needs in the handshake error, since "the CRL does not
// verify" alone cannot tell a corrupted download apart from a CA certificate which is not
// permitted to sign CRLs.
//
// Nothing here compares names. lookup hands over only lists whose own issuer bytes are this
// certificate's subject, or one issuer's lists where the rendered name identifies no other loaded
// CA; either way what makes a list this CA's word is the signature below, which is asked in every
// case.
func (c *parsedCRL) verifiesAgainst(issuer *x509.Certificate) (verifyResult, string) {
	// No caller reaches this with a nil issuer: verifyChain never asks about a top which is not its
	// own issuer — it refuses one whose chain is just itself, and accepts the top of a longer chain
	// without looking for a list — so a list is never looked for with nothing to match it against.
	// The guard is here because the answer must never be an admission, whatever a future caller
	// passes.
	if issuer == nil {
		return verifySkipped, "the chain holds no issuer certificate"
	}
	// If the CRL names the key of the CA it is attributed to, and that CA says which key it
	// has, they must agree: this is what keeps a reissued CA certificate with the same subject
	// but a new key from being cleared by an old CRL. It is an additional check and never a
	// substitute for the one below — a list which omits its authority key id, and one which was
	// found by rendering its issuer's name rather than matching its bytes, are signature-checked
	// exactly like every other list. Two issuers with the same rendered name cannot clear each
	// other's certificates because they do not share a key, whatever either list says about it.
	if len(c.crl.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 &&
		!bytes.Equal(c.crl.AuthorityKeyId, issuer.SubjectKeyId) {
		return verifySkipped, fmt.Sprintf("its authority key id %s is not the subject key id %s of %s",
			hex.EncodeToString(c.crl.AuthorityKeyId), hex.EncodeToString(issuer.SubjectKeyId), issuer.Subject)
	}

	// CheckSignatureFrom asks whether the certificate is a CA which may sign CRLs and whether the
	// signature is valid; it does not compare names, so nothing here is relaxed for a list which
	// was found by rendering its issuer's name. This is one public-key operation per handshake,
	// against the private-key operation the handshake itself already pays for.
	if err := c.crl.CheckSignatureFrom(issuer); err != nil {
		return verifyFailed, fmt.Sprintf("its signature by %s is not valid: %v", issuer.Subject, err)
	}
	return verifyOK, "the signature verified"
}

// expiredAt reports whether this list is past the time by which its issuer said it would be
// replaced. RFC 5280 makes a CRL current only until its nextUpdate, so beyond that the CA has
// made no statement about anything and a certificate it covers has no established status. A list
// which carries no nextUpdate makes no promise to expire by, and RFC 5280 allows a client to treat
// it as current indefinitely; crlClockSkew tolerates drift between this clock and the issuer's,
// not a lapse in publishing, which is what the reload schedule exists to catch.
func (c *parsedCRL) expiredAt(now time.Time) bool {
	return !c.nextUpdate.IsZero() && now.After(c.nextUpdate.Add(crlClockSkew))
}

func (c *parsedCRL) numberText() string {
	if c.number == nil {
		return ""
	}
	return c.number.String()
}

// errUnsupportedCRL marks a list this module will not read at all, as against one which is
// damaged or unreadable. The difference decides how much of a source is lost with it: several lists
// from several CAs are usually shipped in one file, so a single delta or distribution-point list
// must not cost the operator every other list beside it, while a truncated download has to fail the
// whole source rather than be mistaken for a shorter one. Where the line falls is decided by whether
// the list can be read at all: an extension this module recognises and declines — an issuing
// distribution point, a delta indicator — says something about one CA and nothing about its
// neighbours, so it costs that one list; something this module cannot interpret — a critical
// freshestCRL, an unknown critical extension on the list or on one of its entries, an entry which
// revokes on behalf of another CA — means these bytes are not a list it can describe, and nothing
// undescribable is loaded. The marker is used inside this package only; no error which reaches an
// operator unwraps to it.
var errUnsupportedCRL = errors.New("unsupported CRL")

// errPEMHeaderOffALine reports a marker which pem.Decode will walk past because it does not begin a
// line. The gap between the two header counts cannot tell an object hidden this way from prose quoting
// the marker, and a single indented object is reported with the same words: all three are a file whose
// objects are not where the reader looks, which is worth refusing rather than guessing at.
var errPEMHeaderOffALine = errors.New("a PEM header in this source does not begin a line (text, whitespace or a byte-order mark stands before it), so any object beginning there is skipped by the reader")

// parseCRLs parses every CRL in raw: each PEM block which holds one, or — where no header in it begins
// a line, so that there is nothing for pem.Decode to read — the whole body as a single DER list. Lists which are present but
// refused on principle come back separately rather than as an error, because they say something
// about one CA and nothing about the others in the same source.
func parseCRLs(raw []byte) (parsed []*parsedCRL, refused []string, err error) {
	// A byte-order mark is not content, and it would otherwise put a first header off the line start
	// pem.Decode looks for. See utf8BOM for why that is trimmed rather than refused.
	raw = bytes.TrimPrefix(raw, utf8BOM)

	// pem.Decode walks past an object it cannot finish and returns the next one, leaving no record
	// of what it skipped. The PEM headers in the raw bytes are the only witness to how many objects
	// this source claims to hold, so they are counted before parsing and compared with what was
	// read.
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
		case "X509 CRL", "CRL":
			crl, err := parseOneCRL(block.Bytes)
			if errors.Is(err, errUnsupportedCRL) {
				refused = append(refused, strings.TrimPrefix(err.Error(), errUnsupportedCRL.Error()+": "))
				continue
			}
			if err != nil {
				return nil, nil, err
			}
			parsed = append(parsed, crl)
		default:
			// A bundle may hold other objects, such as the certificates some tools append;
			// they are not CRLs and are skipped rather than failing the whole source.
			continue
		}
	}
	if headers == 0 {
		// No header in this source begins a line, and pem.Decode reads nothing else, so the body is
		// read as one DER list — which is what a .crl downloaded from a distribution point is. Anything
		// after that one list — a second concatenated DER list, say — is refused by parseOneCRL rather
		// than left unread. This is tried before any PEM damage is claimed because PEM damage is only
		// worth claiming where there is a header to claim it about. A body in which no header begins a
		// line comes here too, and if it spells the marker anyway that is what gets said — Go's DER
		// error would describe an indented PEM object as a broken DER one.
		crl, err := parseOneCRL(raw)
		if err != nil {
			if bytes.Contains(raw, pemStartHeader) {
				// The body does spell a PEM header, only not at a line start: an object somebody
				// indented, or glued to the end of a line of text. Saying "malformed DER" about that
				// would send an operator off to regenerate a file whose only fault is whitespace.
				return nil, nil, errPEMHeaderOffALine
			}
			// The marker is a category for this package, not something an operator needs twice. The
			// wording says how the body was read rather than asserting that no CRL is there, because
			// two of the reasons reaching here — trailing data after a list which is there, and a list
			// carrying an extension this module refuses — describe a CRL rather than deny one.
			return nil, nil, fmt.Errorf("reading this source as a single DER CRL: %s",
				strings.TrimPrefix(err.Error(), errUnsupportedCRL.Error()+": "))
		}
		return []*parsedCRL{crl}, nil, nil
	}
	if bytes.Count(raw, pemStartHeader) != headers {
		// Some header in this source does not begin a line, and pem.Decode looks for the marker only at
		// a line start, so the object it names will never be returned. That is not a formatting
		// quibble: where a bundle holds more than one list, every list before the first readable one
		// is hidden — the source loads, logs what it loaded, and covers fewer issuers than it names.
		// The object count below cannot see it either, because a header off its line is not counted as
		// one, so this is the only place the two disagree in a way an operator can read.
		return nil, nil, errPEMHeaderOffALine
	}
	if countPEMHeaders(rest) > 0 {
		// pem.Decode stops at an object it cannot finish and leaves the rest of the body where it
		// stands, which is exactly what a download cut short looks like. Loading only what came
		// before it would serve a bundle missing its tail as though that were the whole file, so the
		// source fails rather than quietly covering fewer issuers than it names. Damage in the middle
		// of a bundle leaves nothing in the bytes left to read, which is what the count below is for.
		return nil, nil, errors.New("the source ends in a PEM object which is damaged or cut short")
	}
	if blocks < headers {
		// An object between two readable ones was skipped: pem.Decode handed back the next good
		// block and said nothing about the one it gave up on. The same count also fires on a header
		// which belongs to no object at all, such as a BEGIN line with no END after it — either way
		// this source names more objects than it can produce. Loading the rest would cover fewer
		// issuers than this source names, and the clients under the missing list would be refused as
		// uncovered — with advice to configure a CRL which is sitting in the file.
		return nil, nil, errors.New("a PEM object in this source is damaged, cut short, or not an object this reader can decode")
	}

	if len(parsed) == 0 {
		if len(refused) > 0 {
			// The source holds a CRL and none of it can be used, which is a configuration the
			// operator has to hear about: every certificate under those issuers will be refused as
			// uncovered, and nothing here was loaded by accident. The refusals are named in this
			// error rather than returned beside it as well: there are no other lists from this source
			// for a note about them to refer to.
			return nil, nil, fmt.Errorf("no CRL in this source could be used: %s", strings.Join(refused, "; "))
		}
		// Readable PEM objects, and not one of them a CRL — a bundle of certificates is the usual
		// shape of this mistake. Saying so plainly beats reading the text as DER and reporting what
		// Go made of that.
		return nil, nil, fmt.Errorf("this source holds %d PEM object(s) and none of them is a CRL", blocks)
	}
	return parsed, refused, nil
}

// A PEM object begins with this marker at the start of a line, which is what pem.Decode requires:
// the same bytes in the middle of a line name no object to it. Both spellings are counted, and a gap
// between the two counts means a marker stands where the reader will not look — an object hidden from
// it, or prose quoting the marker. The counts cannot tell those apart and neither belongs in a file
// this module is asked to load revocations from, so both are refused.
var (
	pemLineHeader  = []byte("\n-----BEGIN ")
	pemStartHeader = []byte("-----BEGIN ")

	// utf8BOM is the byte-order mark an editor sometimes writes before the first byte of a file. It is
	// not content, and it puts a first header off the line start pem.Decode looks for: without trimming
	// it, a single-object file is read as DER and refused, and a bundle is refused by the count below —
	// loudly either way, but for how the file was saved rather than for what is in it, and naming a
	// header the operator can see is fine in their editor. OpenSSL strips a byte-order mark; so does
	// this, before anything is counted or decoded.
	utf8BOM = []byte("\xef\xbb\xbf")
)

// countPEMHeaders counts the PEM objects raw claims to hold which this reader can see: those whose
// header begins a line. The first object of a file has no newline before its header, so it is counted
// apart from the ones the scan finds.
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
		// Go reads the first CertificateList and pays no attention to what follows it, so a file of
		// concatenated DER lists — or one with anything appended — would cover fewer issuers than
		// it holds. That is the same mistake as a bundle cut short, so it is refused the same way.
		return nil, errors.New("trailing data after the CRL in this source")
	}

	for _, ext := range crl.Extensions {
		switch {
		case ext.Id.Equal(oidIssuingDistributionPoint):
			// A list which names a distribution point declares that it speaks for part of a CA —
			// one point, a subset of the revocation reasons, only certificates holding a given
			// name — and is therefore not the whole story about the certificates it leaves out.
			// Treating it as the whole story is silent un-revocation, so any list carrying this
			// extension is refused rather than guessed at. Deciding whether the declaration is a
			// scope or merely an address means reading several ASN.1 structures and ruling on every
			// combination they allow; a CA which publishes the extension with no scope at all —
			// some do, marked critical — is refused with it, which is the cost of never deciding
			// wrongly in the direction of serving a certificate its CA has revoked. The refusal is
			// of that list alone: the other lists in the same file are loaded, and what this one
			// covered is refused as uncovered rather than quietly believed.
			return nil, fmt.Errorf("%w: the list for %s carries extension %s: CRLs which declare a distribution point are not supported",
				errUnsupportedCRL, crl.Issuer, ext.Id)
		case ext.Id.Equal(oidDeltaCRLIndicator):
			// A delta lists only what changed since a base list this module does not hold, so
			// treating it as complete clears every revocation it leaves out. RFC 5280 says the
			// indicator is always critical, but a hand-built or non-conforming list may leave the
			// bit off, and the cost of believing that one is silent un-revocation; so its presence
			// alone is enough to refuse, as it is for a list which declares where it speaks from.
			return nil, fmt.Errorf("%w: the list for %s carries extension %s: delta CRLs are not supported",
				errUnsupportedCRL, crl.Issuer, ext.Id)
		case ext.Id.Equal(oidFreshestCRL):
			// On a base CRL this merely points at where deltas would be published, which is
			// harmless to ignore; taken as critical it is a claim about the list's completeness
			// which this module cannot honour.
			if ext.Critical {
				return nil, fmt.Errorf("critical extension %s on the list for %s: a base CRL which insists on delta CRLs is not supported",
					ext.Id, crl.Issuer)
			}
		case ext.Id.Equal(oidAuthorityKeyIdentifier), ext.Id.Equal(oidCRLNumber),
			ext.Id.Equal(oidAuthorityInfoAccess):
			// Understood: parsed into the RevocationList, or informational only.
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
				// An entry revoked by some other CA (RFC 5280 section 5.3.3) is not this list's
				// word about this certificate, and that CA's certificate is not part of this
				// evaluation. Choosing between the two issuers would mean deciding which one a
				// serial belongs to, so the list is refused rather than partly believed: an entry
				// dropped on this reasoning is a revocation quietly forgotten.
				return nil, fmt.Errorf("CRL entry for serial %s carries extension %s: lists which revoke on behalf of another CA are not supported",
					entry.SerialNumber, ext.Id)
			case ext.Id.Equal(oidInvalidityDate):
				// Understood: it tells an operator when the key stopped being trustworthy, which
				// is not something a handshake needs.
			case ext.Id.Equal(oidReasonCode):
				// Go has already decoded this into ReasonCode. A CA which marks it critical is
				// unusual, but it says nothing which is not already known, so refusing a whole
				// list over it would put an operator's PKI out of service for no information.
			case ext.Critical:
				// An entry carrying an extension which cannot be interpreted makes the whole
				// list untrustworthy, since its meaning could apply to any of the entries.
				return nil, fmt.Errorf("unknown critical CRL entry extension %s", ext.Id)
			}
		}
		revoked[serialKey(entry.SerialNumber)] = revocationInfo{at: entry.RevocationTime, reason: reason}
	}

	// The parsed entries are only needed to build the index above; keeping them would double what
	// a large CRL costs, and the standard library fills the deprecated slice alongside the current
	// one. Signature checks work from the raw TBSCertList, not from either slice.
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

// The X.509 extension OIDs which matter for CRLs.
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

// revocationReason names the reason codes of RFC 5280 section 5.3.1 for logs and for the
// error which aborts a handshake.
func revocationReason(code int) string {
	switch code {
	case 0:
		// An entry with no reason code is complete on its own, so nothing is added to what the
		// peer and the log are told.
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
		// A code this module does not name is still a revocation, and an operator reading a log
		// line deserves to know which one the CA used. Code 7 in particular is unassigned by
		// RFC 5280 (hold release is not a reason for listing a certificate), so it arrives here.
		return fmt.Sprintf("reason code %d", code)
	}
}

// serialKey is the map key for a serial number: its minimal big-endian bytes, which are the
// same however the number was encoded.
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
