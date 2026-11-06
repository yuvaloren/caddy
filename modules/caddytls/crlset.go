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

// crlSet is the loaded CRLs indexed by issuer.
type crlSet struct {
	// byIssuer maps the DER-encoded issuer subject to its CRLs, newest
	// first. Only the first usable one is consulted; revocations are
	// not unioned across CRLs.
	byIssuer map[string][]*parsedCRL
}

// distinctLists drops CRLs with identical bytes. The same CRL can arrive
// more than once (repeated in a bundle, or two sources for one URL), and
// lastGood is rebuilt from this list, so without this a source would grow
// by one parsed CRL per retry.
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

// buildCRLSet indexes CRLs by issuer, dropping duplicates and ordering
// each issuer's CRLs newest first.
func buildCRLSet(crls []*parsedCRL) *crlSet {
	if len(crls) == 0 {
		return nil
	}
	set := &crlSet{byIssuer: make(map[string][]*parsedCRL)}
	seen := make(map[[sha256.Size]byte]bool, len(crls))
	for _, crl := range crls {
		digest := crl.contentDigest()
		if seen[digest] {
			continue
		}
		seen[digest] = true
		set.byIssuer[crl.issuerKey] = append(set.byIssuer[crl.issuerKey], crl)
	}
	for _, list := range set.byIssuer {
		slices.SortStableFunc(list, func(a, b *parsedCRL) int {
			// cRLNumber first; a CRL without one sorts after the numbered ones
			if cmp := compareNumbers(a.number, b.number); cmp != 0 {
				return -cmp
			}
			return -a.thisUpdate.Compare(b.thisUpdate)
		})
	}
	return set
}

// lookup returns the CRLs claiming the issuer of cert. The caller still
// has to check the signature; this only matches names.
func (s *crlSet) lookup(cert, issuer *x509.Certificate) []*parsedCRL {
	if issuer == nil || !bytes.Equal(cert.RawIssuer, issuer.RawSubject) {
		return nil
	}
	if crls := s.byIssuer[string(issuer.RawSubject)]; len(crls) > 0 {
		return crls
	}
	// some CAs re-encode the issuer name when signing a CRL, so fall back
	// to the rendered name, but only if it identifies exactly one CA
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

// newest returns the loaded CRLs grouped by issuer, newest first, in a
// stable order for logging.
func (s *crlSet) newest() [][]*parsedCRL {
	lists := make([][]*parsedCRL, 0, len(s.byIssuer))
	for _, list := range s.byIssuer {
		lists = append(lists, list)
	}
	slices.SortFunc(lists, func(a, b []*parsedCRL) int {
		if cmp := strings.Compare(a[0].issuerName, b[0].issuerName); cmp != 0 {
			return cmp
		}
		// two CAs can print the same name with different encodings
		return strings.Compare(a[0].issuerKey, b[0].issuerKey)
	})
	return lists
}

// issuerNames lists the CAs which have a CRL loaded.
func (s *crlSet) issuerNames() []string {
	names := make([]string, 0, len(s.byIssuer))
	for _, list := range s.byIssuer {
		names = append(names, list[0].issuerName)
	}
	slices.Sort(names)
	return names
}

// coveredBy words issuerNames for an error message.
func (s *crlSet) coveredBy() string {
	names := s.issuerNames()
	if len(names) == 0 {
		return "no CRL is loaded at all"
	}
	return "loaded CRLs cover: " + strings.Join(names, ", ")
}

// summary describes the loaded set, so a reload can tell whether anything
// changed.
func (s *crlSet) summary() string {
	var sb strings.Builder
	for _, list := range s.newest() {
		for _, crl := range list {
			fmt.Fprintf(&sb, "%s|number=%s|thisUpdate=%d|nextUpdate=%d\n",
				crl.issuerName, crl.numberText(), crl.thisUpdate.Unix(), crl.nextUpdate.Unix())
		}
	}
	return sb.String()
}
