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

var (
	errNoCRLsLoaded = errors.New("no CRLs have been loaded")

	// in modes that verify chains, Go has already refused the handshake;
	// this is only reachable from a mode that skipped verification
	errNoVerifiedChain = errors.New("a client certificate was presented but no chain could be verified, so its revocation status cannot be checked; use a mode which verifies chains, such as verify_if_given or require_and_verify")

	errEmptyChain = errors.New("an empty verified chain was presented")
)

// VerifyClientCertificate implements ClientCertificateVerifier.
//
// Every verified chain must pass, not just one: with a root and its
// issuing CA both in the pool, the shorter chain ending at the issuing
// CA is always clean, and admitting on it would ignore a revocation of
// that CA on the root's CRL.
func (v *CRLVerifier) VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	set := v.current()
	if set == nil {
		// only possible if the module was never provisioned
		return errNoCRLsLoaded
	}

	// requiring a certificate is the client_auth mode's job, not ours
	if len(rawCerts) == 0 {
		return nil
	}

	if len(verifiedChains) == 0 {
		return errNoVerifiedChain
	}

	var errs []error
	var revoked *revokedError
	seen := make(map[string]struct{}, len(verifiedChains))
	for _, chain := range verifiedChains {
		err := v.verifyChain(set, chain)
		if err == nil {
			continue
		}
		// chains through one pool usually fail the same way; say it once
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

	// log once per refused connection, not once per objecting chain
	if revoked != nil {
		v.reportRevoked(revoked)
	}
	return errors.Join(errs...)
}

// verifyChain checks every certificate in chain whose issuer is above it
// (RFC 5280 asks each issuer about the certificate below it, never about
// the top one). A self-issued top is checked against its own CRL.
func (v *CRLVerifier) verifyChain(set *crlSet, chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errEmptyChain
	}
	for i := range chain {
		issuer := issuerOf(chain, i)
		if issuer == nil {
			if len(chain) == 1 {
				// the peer's certificate is trusted directly, so no CRL
				// can speak for it; refuse rather than admit on silence
				return v.notRevocable(chain[i], set)
			}
			// a trusted CA that nothing in the chain signed; no CRL can
			// cover it, so accept the chain here
			v.logSkipTop(chain[i])
			continue
		}
		if err := v.verifyCert(set, chain[i], issuer); err != nil {
			return err
		}
	}
	return nil
}

// verifyCert checks one certificate against the CRLs claiming its issuer,
// which the caller guarantees is the certificate above cert in the chain.
func (v *CRLVerifier) verifyCert(set *crlSet, cert, issuer *x509.Certificate) error {
	candidates := set.lookup(cert, issuer)
	if len(candidates) == 0 {
		return v.notCovered(cert, set)
	}

	now := v.now()
	// a CRL that is not yet valid says nothing about now, but an older
	// one still within its lifetime might; remember the first in case
	// nothing else covers this certificate
	var notYetValid *parsedCRL
	// why the first CRL was skipped, for the error message
	var passedOver string
	for _, crl := range candidates {
		verdict, why := crl.verifiesAgainst(issuer)
		if verdict == verifyFailed {
			// corrupted, or an attempt to make revocations be ignored
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
			continue
		}

		if crl.expiredAt(now) {
			// past nextUpdate plus clock skew the CA has said nothing;
			// refuse, like OpenSSL's "CRL has expired"
			clause := "passed its nextUpdate of " + crl.nextUpdate.Format(time.RFC3339)
			v.logUnusableReject(crl.issuerName, "it "+clause)
			return fmt.Errorf("the CRL for %s %s and says nothing about this certificate now",
				crl.issuerName, clause)
		}

		// the newest valid CRL for an issuer is authoritative; revocations
		// are not unioned across CRLs, so removing a serial actually removes it
		return v.notRevoked(crl, cert)
	}

	if notYetValid != nil {
		clause := "is not valid until " + notYetValid.thisUpdate.Format(time.RFC3339)
		v.logUnusableReject(notYetValid.issuerName, "it "+clause)
		return fmt.Errorf("the CRL for %s %s", notYetValid.issuerName, clause)
	}
	clause := "was set aside because " + passedOver
	v.logUnusableReject(cert.Issuer.String(), "every list for it "+clause)
	return fmt.Errorf("the CRLs loaded for %s cannot be relied on for this certificate; the first of them %s",
		cert.Issuer, clause)
}

// logSkipTop notes, once per certificate, that a chain was accepted at a
// top certificate which no CRL covers.
func (v *CRLVerifier) logSkipTop(cert *x509.Certificate) {
	level, ok := v.logOnceLevel(logKey{kind: logChainTop, who: string(cert.RawSubject)}, zap.DebugLevel)
	if !ok {
		return
	}
	v.logger.Log(level, "accepting a chain at its top certificate, which no CRL in the chain covers",
		zap.String("subject", cert.Subject.String()))
}

// logUncoveredReject notes, once per issuer, that certificates are being
// refused because no loaded CRL covers that issuer. Go ends the handshake
// without logging the verifier's error, so this is the only trace.
func (v *CRLVerifier) logUncoveredReject(cert *x509.Certificate, reason string) {
	level, ok := v.logOnceLevel(logKey{kind: logUncoveredIssuer, who: cert.Issuer.String()}, zap.WarnLevel)
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

// logUnusableReject notes, once per issuer and reason, that the CRL for
// an issuer cannot be relied on (expired, not yet valid, or unverified).
func (v *CRLVerifier) logUnusableReject(issuerName, reason string) {
	level, ok := v.logOnceLevel(logKey{kind: logUnusableCRL, who: issuerName, detail: reason}, zap.WarnLevel)
	if !ok {
		return
	}
	v.logger.Log(level, "rejecting a certificate whose CRL cannot be relied on",
		zap.String("issuer", issuerName),
		zap.String("reason", reason),
	)
}

// notCovered refuses a certificate whose issuer no configured CRL claims,
// like OpenSSL's "unable to get certificate CRL".
func (v *CRLVerifier) notCovered(cert *x509.Certificate, set *crlSet) error {
	v.logUncoveredReject(cert, "no configured CRL is issued by it")
	return fmt.Errorf("certificate %s (serial %s) is issued by %s, which no configured CRL covers; %s",
		cert.Subject, cert.SerialNumber, cert.Issuer, set.coveredBy())
}

// notRevocable refuses a directly trusted leaf, which no CRL could name.
func (v *CRLVerifier) notRevocable(cert *x509.Certificate, set *crlSet) error {
	clause := "is trusted directly, so the verified chain has no issuer above it which could revoke it"
	v.logUncoveredReject(cert, "it "+clause)
	return fmt.Errorf("certificate %s was presented and %s; issue client certificates from a CA and put that CA in the trust pool (%s)",
		cert.Subject, clause, set.coveredBy())
}

// revokedError reports a certificate listed in a valid CRL for its issuer.
type revokedError struct {
	msg    string
	cert   *x509.Certificate
	issuer string
	at     time.Time
	reason string
}

func (e *revokedError) Error() string { return e.msg }

// reportRevoked logs a rejection, once per refused connection. It is not
// deduplicated by serial: a client retrying in a loop is worth seeing.
func (v *CRLVerifier) reportRevoked(e *revokedError) {
	v.logger.Error("rejecting a revoked client certificate",
		zap.String("subject", e.cert.Subject.String()),
		zap.String("serial", e.cert.SerialNumber.String()),
		zap.String("issuer", e.issuer),
		zap.Time("revoked_at", e.at),
		zap.String("reason", e.reason),
	)
}

// notRevoked returns an error if cert is listed in crl.
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

// issuerOf returns the certificate a CRL covering chain[i] would be
// signed by: the next one up the chain, or chain[i] itself when it is
// the last and self-issued. Nil means nothing in the chain signed it.
func issuerOf(chain []*x509.Certificate, i int) *x509.Certificate {
	if i+1 < len(chain) {
		return chain[i+1]
	}
	if bytes.Equal(chain[i].RawSubject, chain[i].RawIssuer) {
		return chain[i]
	}
	return nil
}
