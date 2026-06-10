// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package tpmquote

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/provabl/evidence/providers/nitrotpm"
	"github.com/provabl/evidence/trust"
)

// Verifier implements nitrotpm.Verifier. It checks that the signed TPMS_ATTEST in
// raw was produced by the trusted attestation key whose PUBLIC key is carried in
// root.Material (DER-encoded PKIX), and that the quote's structure is sound. It
// does NOT check the nonce or PCR policy — those are the kernel appraiser's job
// (the appraiser binds nonce via TPMQuote.Nonce and applies expected_pcr params).
//
// What this verifies:
//   - the signature over the TPMS_ATTEST blob is valid for the trusted AK pubkey,
//   - the blob carries the TPM_GENERATED magic and is a quote (TPMS_QUOTE_INFO).
//
// NitroTPM trust note: root.Material is a public key, not a CA certificate, because
// AWS publishes no NitroTPM root CA — see this package's doc comment.
type Verifier struct{}

// NewVerifier returns a NitroTPM quote verifier.
func NewVerifier() *Verifier { return &Verifier{} }

func (v *Verifier) Verify(_ context.Context, raw []byte, root trust.Root) (bool, error) {
	var rq rawQuote
	if err := json.Unmarshal(raw, &rq); err != nil {
		return false, fmt.Errorf("decode raw quote: %w", err)
	}
	if len(rq.Attest) == 0 || len(rq.Sig) == 0 {
		return false, fmt.Errorf("raw quote missing attest or signature")
	}

	akPub, err := parsePublicKey(root.Material)
	if err != nil {
		return false, fmt.Errorf("trust root %q: %w", root.Name, err)
	}

	// Decode the TPMS_ATTEST and confirm it is a well-formed quote. DecodeAttestationData
	// already rejects a bad TPM_GENERATED magic.
	ad, err := legacy.DecodeAttestationData(rq.Attest)
	if err != nil {
		return false, fmt.Errorf("decode TPMS_ATTEST: %w", err)
	}
	if ad.AttestedQuoteInfo == nil {
		return false, fmt.Errorf("attestation is not a quote (no TPMS_QUOTE_INFO)")
	}

	// Decode the TPMT_SIGNATURE and verify it over the attest blob with the AK pubkey.
	sig, err := legacy.DecodeSignature(bytes.NewBuffer(rq.Sig))
	if err != nil {
		return false, fmt.Errorf("decode TPMT_SIGNATURE: %w", err)
	}
	if err := verifySig(akPub, rq.Attest, sig); err != nil {
		return false, fmt.Errorf("quote signature: %w", err)
	}
	return true, nil
}

// verifySig checks the TPM signature over data (the raw TPMS_ATTEST bytes) against
// pub. v1 supports RSASSA (the AK template client.AttestationKeyRSA produces).
func verifySig(pub crypto.PublicKey, data []byte, sig *legacy.Signature) error {
	if sig.RSA == nil {
		return fmt.Errorf("unsupported signature algorithm (want RSA)")
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("trusted key is %T, want *rsa.PublicKey", pub)
	}
	hashAlg, err := sig.RSA.HashAlg.Hash()
	if err != nil {
		return fmt.Errorf("signature hash alg: %w", err)
	}
	h := hashAlg.New()
	h.Write(data)
	digest := h.Sum(nil)
	if err := rsa.VerifyPKCS1v15(rsaPub, hashAlg, digest, sig.RSA.Signature); err != nil {
		return fmt.Errorf("RSASSA verify failed: %w", err)
	}
	return nil
}

// parsePublicKey parses a DER PKIX public key (what `aws ec2 get-instance-tpm-ek-pub
// --key-format der` returns, and what the producer records for the AK).
func parsePublicKey(der []byte) (crypto.PublicKey, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("empty trusted public key")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	return pub, nil
}

// Root wraps a DER PKIX public key (the trusted attestation-key public area) as the
// kernel trust.Root the nitrotpm appraiser resolves. Material is the public key, not
// a CA certificate — see the package doc on the NitroTPM trust model.
func Root(akPubDER []byte) trust.Root {
	return trust.Root{Name: nitrotpm.RootName, Material: akPubDER}
}
