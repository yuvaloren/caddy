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
	"fmt"
	"slices"
	"strings"
)

type crlSet struct {
	// byIssuer maps the DER-encoded subject of an issuer to the CRLs which name that issuer,
	// newest first. The authoritative list for a certificate is therefore the first one which
	// can be relied on for it, and older ones are only fallbacks: revocations are deliberately
	// not unioned across them, so that removing a serial from a CRL actually removes it.
	byIssuer map[string][]*parsedCRL
}

// distinctLists keeps the first copy of each distinct set of bytes. The same list can be handed over
// more than once — an object repeated in a bundle, two sources pointing at one distribution point, or
// an earlier parse standing in beside the fresh copy of itself, which is what happens on every refresh
// while a refused list sits beside it. buildCRLSet drops duplicates when indexing, so admissions stay
// correct either way; this is about what gets *remembered*: lastGood is rebuilt from this list each
// time, and without it a source holding one stale sibling grows by a whole parsed CRL — its entries map
// and raw bytes included — on every retry, quietly, forever.
func distinctLists(crls []*parsedCRL) []*parsedCRL {
	seen := make(map[[sha256.Size]byte]bool, len(crls))
	out := make([]*parsedCRL, 0, len(crls))
	for _, crl := range crls {
		digest := crl.contentDigest()
		if seen[digest] {
			continue
		}
		seen[digest] = true
		out = append(out, crl)
	}
	return out
}

// buildCRLSet indexes CRLs by issuer, dropping duplicates and ordering each issuer's list
// newest first.
func buildCRLSet(crls []*parsedCRL) *crlSet {
	if len(crls) == 0 {
		return nil
	}
	set := &crlSet{byIssuer: make(map[string][]*parsedCRL)}
	seen := make(map[[sha256.Size]byte]bool, len(crls))
	for _, crl := range crls {
		// The same object can arrive twice — from two sources pointing at one distribution point,
		// or twice in one bundle — and a duplicate would be counted as a second list to rank.
		digest := crl.contentDigest()
		if seen[digest] {
			continue
		}
		seen[digest] = true
		set.byIssuer[crl.issuerKey] = append(set.byIssuer[crl.issuerKey], crl)
	}
	for _, list := range set.byIssuer {
		slices.SortStableFunc(list, func(a, b *parsedCRL) int {
			// cRLNumber is the CA's own statement of which list is later, so it comes first; a
			// list which carries none can only be ordered by when it says it took effect, and it
			// sorts after the numbered ones, which can be ordered with certainty. Two lists which
			// agree on both say the same thing about order, so their arrangement does not matter.
			if cmp := compareNumbers(a.number, b.number); cmp != 0 {
				return -cmp
			}
			return -a.thisUpdate.Compare(b.thisUpdate)
		})
	}
	return set
}

// lookup returns the CRLs which claim the issuer of cert, anchored on issuer. An empty result means
// no loaded CRL claims this certificate's issuer. A list whose issuer name is encoded differently
// from the certificate's is still found, as long as exactly one loaded CA renders that name; what
// ties such a list to its CA is the signature, checked by the caller.
func (s *crlSet) lookup(cert, issuer *x509.Certificate) []*parsedCRL {
	if issuer == nil || !bytes.Equal(cert.RawIssuer, issuer.RawSubject) {
		// Without the issuer certificate there is nothing to anchor a CRL on, so no list can
		// be relied on for this certificate even if one claims its name.
		return nil
	}
	if crls := s.byIssuer[string(issuer.RawSubject)]; len(crls) > 0 {
		return crls
	}
	// Some CAs re-encode the issuer name when signing a CRL, which is legal but means the DER
	// encodings differ. Fall back to the rendered name, and only where it identifies one CA:
	// guessing between two DNs which print the same is how a revocation gets attributed to the
	// wrong CA, so a name more than one loaded issuer answers to finds nothing.
	var found []*parsedCRL
	name := cert.Issuer.String()
	for _, crls := range s.byIssuer {
		if crls[0].issuerName != name {
			continue
		}
		if found != nil {
			return nil
		}
		found = crls
	}
	return found
}

// newest returns the loaded lists grouped by issuer — newest first within each group, the groups
// ordered by issuer name — for logging.
func (s *crlSet) newest() [][]*parsedCRL {
	lists := make([][]*parsedCRL, 0, len(s.byIssuer))
	for _, list := range s.byIssuer {
		lists = append(lists, list)
	}
	slices.SortFunc(lists, func(a, b []*parsedCRL) int {
		if cmp := strings.Compare(a[0].issuerName, b[0].issuerName); cmp != 0 {
			return cmp
		}
		// Two CAs whose names print the same but encode differently would otherwise trade places
		// between reloads, and the line about what changed would fire on nothing having changed.
		return strings.Compare(a[0].issuerKey, b[0].issuerKey)
	})
	return lists
}

// issuerNames lists the CAs which have a CRL loaded, for diagnostics.
func (s *crlSet) issuerNames() []string {
	names := make([]string, 0, len(s.byIssuer))
	for _, list := range s.byIssuer {
		names = append(names, list[0].issuerName)
	}
	slices.Sort(names)
	return names
}

// coveredBy words issuerNames for an error message, including the case where there is nothing to
// name. That case is reachable: a source whose last accepted list carried no number then serves a
// numbered one below its mark has nothing to stand in — an un-numbered list cannot be shown to be
// above anything — and with no other source contributing, the set in service is empty. A refusal
// ending in "loaded CRLs cover:" with nothing after it would read as a broken sentence rather than as
// the state being described.
func (s *crlSet) coveredBy() string {
	names := s.issuerNames()
	if len(names) == 0 {
		return "no CRL is loaded at all"
	}
	return "loaded CRLs cover: " + strings.Join(names, ", ")
}

// summary describes the loaded set compactly, so that a refresh can tell whether anything
// changed since the last one.
func (s *crlSet) summary() string {
	var sb strings.Builder
	for _, list := range s.newest() {
		// Every loaded list, not just the newest per issuer: where two sources carry lists for one
		// CA, a change in the one which is not authoritative still belongs in the line which says
		// what the module is holding.
		for _, crl := range list {
			fmt.Fprintf(&sb, "%s|number=%s|thisUpdate=%d|nextUpdate=%d\n",
				crl.issuerName, crl.numberText(), crl.thisUpdate.Unix(), crl.nextUpdate.Unix())
		}
	}
	return sb.String()
}
