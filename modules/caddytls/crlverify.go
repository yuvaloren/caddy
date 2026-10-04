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
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// VerifyClientCertificate implements ClientCertificateVerifier.
//
// A client is admitted only when every verified chain is clean: for each of them, every
// certificate in scope is covered by a CRL which validates against that chain and does not list it
// as revoked. Refusing on any one chain is deliberate, though path validation usually asks only for
// one clean path. crypto/tls hands over every path it can find, and the shortest of them stops at
// the first certificate the pool already trusts — so on a trust pool holding a root together with
// its issuing CA, the chain which ends at that issuing CA is always clean, since nothing above it is
// in scope. Admitting on that chain would mean a root which revoked its own issuing CA could never
// close a connection made by a client which sends that CA, which is the revocation this module most
// exists to catch.
func (v *CRLVerifier) VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	set := v.current()
	if set == nil {
		// Provision guarantees a snapshot, so this can only mean the module was used
		// without being provisioned. Refusing is the only safe answer.
		return errors.New("no CRLs have been loaded")
	}

	// Not presenting a certificate is the client_auth mode's business, not ours.
	if len(rawCerts) == 0 {
		return nil
	}

	// A certificate with no verified chain has no trusted issuer to anchor a CRL on.
	// Allowing it would make this verifier inert exactly when it matters most, so the modes
	// which skip chain verification are incompatible with it by design.
	if len(verifiedChains) == 0 {
		return errors.New("a client certificate was presented but no chain could be verified, so its revocation status cannot be checked; use a mode which verifies chains, such as verify_if_given or require_and_verify")
	}

	var errs []error
	var revoked *revokedError
	seen := make(map[string]struct{}, len(verifiedChains))
	for _, chain := range verifiedChains {
		err := v.verifyChain(set, chain)
		if err == nil {
			continue
		}
		// Chains through one pool usually say the same thing about the same certificate, and a
		// refusal an operator has to read should say it once.
		if _, ok := seen[err.Error()]; ok {
			continue
		}
		seen[err.Error()] = struct{}{}
		errs = append(errs, err)

		var re *revokedError
		if errors.As(err, &re) && revoked == nil {
			revoked = re
		}
	}
	if len(errs) == 0 {
		return nil
	}

	// Only now is it known that the connection is being refused. Several chains can verify for one
	// certificate and any of them may be the one which noticed, so reporting inside the loop would
	// write one line per chain which objected — twice on the common deployment whose trust pool holds
	// a root and its issuing CA together.
	if revoked != nil {
		v.reportRevoked(revoked)
	}
	return errors.Join(errs...)
}

// verifyChain returns an error if a certificate in scope is revoked or its revocation status
// cannot be established. The scope is every certificate which has its issuer above it in this
// chain, which is exactly what a chain can answer: RFC 5280 path validation asks each issuer in
// the path whether it revoked the certificate below it, and never about the certificate at the top.
// One exception is made for a top which is its own issuer: an answer is available for it — its own
// list, signed by its own key — and a root which has revoked nothing should be able to say so rather
// than be accepted on no evidence at all. Every chain has to be clean for the certificate to be
// admitted; see VerifyClientCertificate.
func (v *CRLVerifier) verifyChain(set *crlSet, chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("an empty verified chain was presented")
	}
	for i := range chain {
		issuer := issuerOf(chain, i)
		if issuer == nil {
			if len(chain) == 1 {
				// The peer's own certificate is the whole verified chain, so it is trusted
				// directly and there is no issuer above it which could have revoked it. Revocation
				// is something an issuer says about a certificate it signed, so nothing can be
				// established about this one; refusing is the only answer consistent with refusing
				// every other certificate whose status is unknown.
				return v.notRevocable(chain[i], set)
			}
			// The top of a longer chain whose own issuer is not in it. A top which carries its own
			// name as issuer does not come this way — issuerOf takes it at its word, so its own list
			// is required (see the doc on verifyChain) — which leaves a CA the pool trusts directly
			// while the client's
			// chain ends at it: nothing in this chain can say whether it was revoked. Requiring a
			// list signed by an issuer which is not in the chain would refuse every client of such a
			// pool, so the chain is accepted at its top and recorded rather than passed over.
			v.logSkipTop(chain[i])
			continue
		}
		if err := v.verifyCert(set, chain[i], issuer); err != nil {
			return err
		}
	}
	return nil
}

// verifyCert evaluates one certificate against the CRLs which claim its issuer, anchored on
// issuer, which the caller guarantees is the certificate above cert in the verified chain.
func (v *CRLVerifier) verifyCert(set *crlSet, cert, issuer *x509.Certificate) error {
	candidates := set.lookup(cert, issuer)
	if len(candidates) == 0 {
		return v.notCovered(cert, set)
	}

	now := v.now()
	// A list which is not yet valid says nothing about now, but it does not follow that nothing
	// else can: an older list still inside its own lifetime does. Remembered in case there is
	// nothing else to say about this certificate either.
	var notYetValid *parsedCRL
	// Why the first list set aside was set aside. Reaching the end of the loop means every list
	// for this issuer was set aside, so an operator whose CA has been re-keyed needs this reason
	// in the refusal: without it the only thing they learn is that some CRLs are loaded and none
	// of them will do.
	var passedOver string
	for _, crl := range candidates {
		verdict, why := crl.verifiesAgainst(issuer)
		if verdict == verifyFailed {
			// Either the source is corrupted or someone is trying to make revocations be
			// ignored. Neither is a reason to admit a certificate.
			v.logUnusableReject(crl.issuerName, why)
			return fmt.Errorf("the CRL for %s does not verify against the verified chain (%s); refusing to rely on it", crl.issuerName, why)
		}
		if verdict == verifySkipped {
			if passedOver == "" {
				passedOver = why
			}
			continue
		}

		if crl.thisUpdate.After(now.Add(crlClockSkew)) {
			if notYetValid == nil {
				notYetValid = crl
			}
			// A publisher whose clock is a few minutes ahead would otherwise take every client
			// down for the overlap even with an in-date list sitting beside it.
			continue
		}

		if crl.expiredAt(now) {
			// RFC 5280 makes a CRL current only until its nextUpdate. Past that the CA has said
			// nothing about this certificate, which is a refusal rather than a silence — the same
			// as OpenSSL's "CRL has expired". A deployment which wants to stay up when its
			// publisher stops is served by fixing the publisher, not by trusting an old list.
			v.logUnusableReject(crl.issuerName, "it passed its nextUpdate of "+crl.nextUpdate.Format(time.RFC3339))
			return fmt.Errorf("the CRL for %s passed its nextUpdate of %s and says nothing about this certificate now",
				crl.issuerName, crl.nextUpdate.Format(time.RFC3339))
		}

		// The newest CRL which validates for an issuer is authoritative, and older ones are only
		// used if it cannot be: revocations are deliberately not unioned across lists, so that
		// removing a serial from a CRL actually removes it.
		return v.notRevoked(crl, cert)
	}

	// Nothing in this issuer's set was usable. A damaged list never enters the set and an expired
	// one has returned above, so what is left here is a set whose every list was set aside — or one
	// whose only remaining lists are not yet valid, which are remembered and answered just below.
	// A list which does not speak for this chain might say anything, and falling back to nothing
	// would let a stale list clear a revocation the current one carries.
	if notYetValid != nil {
		v.logUnusableReject(notYetValid.issuerName, "it is not valid until "+notYetValid.thisUpdate.Format(time.RFC3339))
		return fmt.Errorf("the CRL for %s is not valid until %s", notYetValid.issuerName, notYetValid.thisUpdate.Format(time.RFC3339))
	}
	v.logUnusableReject(cert.Issuer.String(), "every list for it was set aside: "+passedOver)
	return fmt.Errorf("the CRLs loaded for %s cannot be relied on for this certificate; the first of them was set aside because %s",
		cert.Issuer, passedOver)
}

// logSkipTop notes once per certificate that a chain was accepted at its top certificate, with no
// CRL in the chain to speak for it. That is the correct rule — nothing above it is in the chain —
// but an operator who expected this module to check their root should be able to see that it does
// not, so it is recorded rather than passed over in silence.
func (v *CRLVerifier) logSkipTop(cert *x509.Certificate) {
	level, ok := v.logOnceLevel("top\x00"+string(cert.RawSubject), zap.DebugLevel)
	if !ok {
		return
	}
	v.logger.Log(level, "accepting a chain at its top certificate, which no CRL in the chain covers",
		zap.String("subject", cert.Subject.String()))
}

// logUncoveredReject notes that a certificate is being turned away because nothing loaded speaks
// for its issuer. The refusal itself only travels back to Go, which ends the handshake and says
// nothing further — measured on a listener with one CRL too few, every client was refused and the
// log held no line about any of them. So the reason is recorded here rather than left for someone
// to reconstruct from an empty access log. It is keyed by issuer, not by certificate: only
// certificates which built a chain to the trust pool reach this point, so the issuers among them
// are bounded by that pool, while subjects and serials are whatever a caller presents.
func (v *CRLVerifier) logUncoveredReject(cert *x509.Certificate, reason string) {
	level, ok := v.logOnceLevel("uncovered\x00"+cert.Issuer.String(), zap.WarnLevel)
	if !ok {
		return
	}
	v.logger.Log(level, "rejecting a certificate which no configured CRL covers",
		zap.String("subject", cert.Subject.String()),
		zap.String("serial", cert.SerialNumber.String()),
		zap.String("issuer", cert.Issuer.String()),
		zap.String("reason", reason),
	)
}

// logUnusableReject notes that a list which does claim this certificate's issuer cannot be relied
// on: it expired, or is not valid yet, or does not verify against the verified chain, or every list
// for the issuer was set aside. Coverage then looks present from the loaded summary while every
// client under that CA is turned away, which is the outage shape this module has already been
// blamed for — the refusal itself only travels back to Go, which ends the handshake and says
// nothing further. Keyed by issuer and reason, so a publisher whose list expired is said once, and
// said again when what is wrong changes.
func (v *CRLVerifier) logUnusableReject(issuerName, reason string) {
	level, ok := v.logOnceLevel("unusable\x00"+issuerName+"\x00"+reason, zap.WarnLevel)
	if !ok {
		return
	}
	v.logger.Log(level, "rejecting a certificate whose CRL cannot be relied on",
		zap.String("issuer", issuerName),
		zap.String("reason", reason),
	)
}

// notCovered is the refusal of a certificate whose issuer no configured CRL claims. Having no
// evidence of revocation is not evidence that there is none; this is OpenSSL's "unable to get
// certificate CRL". Which issuers were loaded goes into the message because that is what an
// operator needs in order to find the list which is missing.
func (v *CRLVerifier) notCovered(cert *x509.Certificate, set *crlSet) error {
	v.logUncoveredReject(cert, "no configured CRL is issued by it")
	return fmt.Errorf("certificate %s (serial %s) is issued by %s, which no configured CRL covers; %s",
		cert.Subject, cert.SerialNumber, cert.Issuer, set.coveredBy())
}

// notRevocable is the refusal of a certificate which no CRL could ever name, because it is the whole
// verified chain and it does not claim to be its own issuer: it is trusted directly, so nothing above
// it exists in the chain to say anything about it. The only list which could speak for it would be
// one about itself, which is not how revocation works. A certificate which does make that claim — a
// self-signed one presented alone — is not refused here: issuerOf takes it at its word and its own
// list is required of it, like any other issuer's. What the two cases share is the rule beneath them:
// a certificate whose revocation status cannot be established is refused.
func (v *CRLVerifier) notRevocable(cert *x509.Certificate, set *crlSet) error {
	v.logUncoveredReject(cert, "it is trusted directly, so the verified chain has no issuer above it which could revoke it")
	return fmt.Errorf("certificate %s was presented and is trusted directly, so the verified chain has no issuer above it which could revoke it; issue client certificates from a CA and put that CA in the trust pool (%s)",
		cert.Subject, set.coveredBy())
}

// revokedError says that a certificate is listed in a CRL which validates for its issuer. It
// carries what an operator needs to act on, so that the report can be written once per connection
// rather than once per chain tried; see VerifyClientCertificate.
type revokedError struct {
	msg    string
	cert   *x509.Certificate
	issuer string
	at     time.Time
	reason string
}

func (e *revokedError) Error() string { return e.msg }

// reportRevoked writes a rejection to the log, once per refused connection. It is paced by the
// peer rather than by this module: whoever holds the revoked certificate can repeat it as fast as
// it can reconnect. That is deliberate — the retries are the signal, and a line deduplicated by
// serial would hide exactly the reconnect loop worth seeing.
func (v *CRLVerifier) reportRevoked(e *revokedError) {
	v.logger.Error("rejecting a revoked client certificate",
		zap.String("subject", e.cert.Subject.String()),
		zap.String("serial", e.cert.SerialNumber.String()),
		zap.String("issuer", e.issuer),
		zap.Time("revoked_at", e.at),
		zap.String("reason", e.reason),
	)
}

// notRevoked returns an error if cert is listed in crl, worded the way an operator wants to
// read it in a log line.
func (v *CRLVerifier) notRevoked(crl *parsedCRL, cert *x509.Certificate) error {
	info, revoked := crl.revoked[serialKey(cert.SerialNumber)]
	if !revoked {
		return nil
	}
	reason := ""
	if info.reason != "" {
		reason = ", reason: " + info.reason
	}
	return &revokedError{
		msg: fmt.Sprintf("certificate %s (serial %s) was revoked by %s at %s%s",
			cert.Subject, cert.SerialNumber, crl.issuerName, info.at.Format(time.RFC3339), reason),
		cert:   cert,
		issuer: crl.issuerName,
		at:     info.at,
		reason: info.reason,
	}
}

// issuerOf returns the certificate which would have signed a CRL covering chain[i]: the next
// certificate up the chain, or the certificate itself when it is the last one and self-issued.
// That last case is what a CA which re-keyed in place looks like once it is in the trust pool:
// the same name on both sides with a different key behind it, so its revocation status really is
// somebody's to state and this certificate is the only copy available to verify such a list
// against. Nil is returned when the chain ends at something which is trusted directly without being
// self-issued, because then there is no copy of any issuer's certificate to verify a list against at
// all. That includes a peer certificate presented as the whole chain — unless it carries its own name
// as issuer, in which case it is taken at its word — and verifyChain turns that nil into a refusal
// (notRevocable) rather than a pass.
func issuerOf(chain []*x509.Certificate, i int) *x509.Certificate {
	if i+1 < len(chain) {
		return chain[i+1]
	}
	if bytes.Equal(chain[i].RawSubject, chain[i].RawIssuer) {
		return chain[i]
	}
	return nil
}
