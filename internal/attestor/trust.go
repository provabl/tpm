// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package attestor

import (
	"crypto/ed25519"
	"fmt"

	"github.com/provabl/evidence/trust"
)

const amKeyID = "tpm-am-ephemeral"

// ephemeralAM is the per-run attestation-manager key for the kernel's SIG
// built-in, mirroring nitro/vet/qualify: in-process Run-then-Appraise, so an
// ephemeral key is sufficient and avoids a key-management surface. The durable
// artifact is the lowered attestation.json, never the evidence bundle.
type ephemeralAM struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

func newEphemeralAM() (*ephemeralAM, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("tpm: generate AM key: %w", err)
	}
	return &ephemeralAM{priv: priv, pub: pub, keyID: amKeyID}, nil
}

func (a *ephemeralAM) Sign(msg []byte) ([]byte, string, error) {
	return ed25519.Sign(a.priv, msg), a.keyID, nil
}

// trustStore serves the AM signing key (the kernel SIG-spine check) and the
// aws-tpm root the nitrotpm appraiser resolves for the Verifier. Unlike nitro's
// embedded CA root, the NitroTPM root is the per-instance AK public key. It is held
// by POINTER and read at Root() call time: with --device the AK pubkey is not known
// until the source has run (during cvm.Run), and Root() is called during Appraise
// (after Run), so the pointer is populated by then.
type trustStore struct {
	am       *ephemeralAM
	rootName string
	akPubDER *[]byte
}

func newTrustStore(am *ephemeralAM, rootName string, akPubDER *[]byte) *trustStore {
	return &trustStore{am: am, rootName: rootName, akPubDER: akPubDER}
}

func (s *trustStore) Verify(keyID string, msg, sig []byte) (bool, error) {
	if keyID != s.am.keyID {
		return false, nil
	}
	return ed25519.Verify(s.am.pub, msg, sig), nil
}

func (s *trustStore) Root(name string) (trust.Root, bool) {
	if name != s.rootName || s.akPubDER == nil || len(*s.akPubDER) == 0 {
		return trust.Root{}, false
	}
	return trust.Root{Name: s.rootName, Material: *s.akPubDER}, true
}
