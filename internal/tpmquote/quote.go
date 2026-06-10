// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package tpmquote produces and verifies AWS NitroTPM attestation quotes and
// adapts them to the provabl/evidence nitrotpm provider's injected Source and
// Verifier interfaces. All TPM 2.0 specifics live here so the evidence kernel
// stays stdlib-only.
//
// Trust model (important — NitroTPM differs from Nitro Enclaves):
//
// AWS Nitro Enclaves ship a COSE document with an X.509 chain to a published AWS
// root CA. AWS NitroTPM does NOT publish a root CA. Instead you retrieve the
// instance's endorsement-key (EK) PUBLIC KEY out-of-band from the EC2 control
// plane (`aws ec2 get-instance-tpm-ek-pub`), and trust is anchored there. So the
// kernel trust.Root this package uses carries a trusted PUBLIC KEY (the attestation
// key's public area), not a CA certificate — the evidence kernel treats Root.Material
// as opaque bytes, so no kernel change is needed.
//
// v1 scope: this proves "a TPM on this instance signed these PCRs with this nonce,
// against a recorded AK public key." Cryptographically binding that AK to the
// AWS-vouched EK (TPM2_ActivateCredential) is v2 — see README. We do not overclaim.
package tpmquote

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/provabl/evidence/providers/nitrotpm"
)

// rawQuote is the self-describing serialization carried in nitrotpm.TPMQuote.Raw.
// It holds exactly what the Verifier needs to re-check the quote offline: the
// signed TPMS_ATTEST blob and the TPMT_SIGNATURE over it. The producer marshals
// it; the Verifier unmarshals it. (PCRs and Nonce travel in the kernel TPMQuote
// fields, not here, so the appraiser binds the nonce and applies PCR policy.)
type rawQuote struct {
	// Attest is the TPM2 quote, encoded as a TPMS_ATTEST (pb.Quote.Quote).
	Attest []byte `json:"attest"`
	// Sig is the TPM2 signature over Attest, encoded as a TPMT_SIGNATURE
	// (pb.Quote.RawSig).
	Sig []byte `json:"sig"`
}

// fromPB adapts a go-tpm-tools *pb.Quote (the output of client.Key.Quote) into the
// kernel's nitrotpm.TPMQuote. nonce is the challenge the quote was taken over; it
// is echoed into the kernel field so the appraiser can bind it (the appraiser also
// re-derives it from the attest blob via the Verifier path — both must agree).
func fromPB(q *pb.Quote, nonce []byte) (nitrotpm.TPMQuote, error) {
	if q == nil {
		return nitrotpm.TPMQuote{}, fmt.Errorf("nil quote")
	}
	raw, err := json.Marshal(rawQuote{Attest: q.GetQuote(), Sig: q.GetRawSig()})
	if err != nil {
		return nitrotpm.TPMQuote{}, fmt.Errorf("marshal raw quote: %w", err)
	}
	return nitrotpm.TPMQuote{
		Nonce: nonce,
		PCRs:  pcrsHex(q.GetPcrs()),
		Raw:   raw,
	}, nil
}

// pcrsHex renders the quoted PCR bank as index-string → lowercase hex, the shape
// nitrotpm.TPMQuote.PCRs expects. A nil bank yields an empty map.
func pcrsHex(p *pb.PCRs) map[string]string {
	out := map[string]string{}
	if p == nil {
		return out
	}
	for idx, v := range p.GetPcrs() {
		out[fmt.Sprintf("%d", idx)] = hex.EncodeToString(v)
	}
	return out
}

// pcrDigestSHA256 recomputes the composite digest a TPMS_QUOTE_INFO commits to:
// SHA-256 over the concatenation of the selected PCR values in ascending index
// order. Used by the Verifier to confirm the quoted PCRs match the signed digest.
func pcrDigestSHA256(p *pb.PCRs) []byte {
	h := sha256.New()
	// PCR indices must be concatenated in ascending order to match the TPM's
	// composite-hash construction.
	for i := 0; i < 24; i++ {
		if v, ok := p.GetPcrs()[uint32(i)]; ok {
			h.Write(v)
		}
	}
	return h.Sum(nil)
}
