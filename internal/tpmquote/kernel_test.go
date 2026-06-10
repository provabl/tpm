// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package tpmquote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/provabl/evidence/asp"
	"github.com/provabl/evidence/cvm"
	"github.com/provabl/evidence/lower"
	"github.com/provabl/evidence/providers/nitrotpm"
	"github.com/provabl/evidence/term"
	"github.com/provabl/evidence/trust"
)

// quoteSource serves a pre-built fixture quote, echoing the run's nonce the way a
// real TPM embeds qualifyingData — so the kernel appraiser's native nonce binding
// is exercised end to end against this producer's Verifier.
type quoteSource struct {
	makeRaw func(nonce []byte) []byte
	pcrs    map[string]string
}

func (s quoteSource) Fetch(_ context.Context, _ term.Target, nonce []byte) (nitrotpm.TPMQuote, error) {
	return nitrotpm.TPMQuote{Nonce: nonce, PCRs: s.pcrs, Raw: s.makeRaw(nonce)}, nil
}

// amSigner / memTrust mirror the evidence test harness: an ephemeral AM key plus a
// trust store that serves the aws-tpm root (here the AK public key, per NitroTPM).
type amSigner struct {
	priv  ed25519.PrivateKey
	keyID string
}

func (s amSigner) Sign(msg []byte) ([]byte, string, error) {
	return ed25519.Sign(s.priv, msg), s.keyID, nil
}

type memTrust struct {
	pub  ed25519.PublicKey
	root trust.Root
}

func (t memTrust) Verify(keyID string, msg, sig []byte) (bool, error) {
	return ed25519.Verify(t.pub, msg, sig), nil
}
func (t memTrust) Root(name string) (trust.Root, bool) {
	if name == nitrotpm.RootName {
		return t.root, true
	}
	return trust.Root{}, false
}

// TestKernelRoundTrip runs the real nitrotpm provider (this producer's Source +
// Verifier) through the CVM and appraiser, proving the full path: the quote is
// fetched with the run's nonce, the Verifier validates the signature, and the
// appraiser binds the nonce and emits platform.tpm_attested=true.
func TestKernelRoundTrip(t *testing.T) {
	// One stable AK; re-sign a fresh quote per kernel-issued nonce so the signature
	// covers the actual challenge. The trust root (AK pubkey) stays constant.
	ak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	base := newFixtureWithKey(t, []byte("init"), ak)
	makeRaw := func(nonce []byte) []byte {
		return newFixtureWithKey(t, nonce, ak).quote.Raw
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := memTrust{pub: pub, root: base.root}

	reg := asp.NewRegistry()
	if err := reg.Register(nitrotpm.Provider(
		quoteSource{makeRaw: makeRaw, pcrs: map[string]string{"0": "aa", "7": "dd"}},
		NewVerifier(),
	)); err != nil {
		t.Fatal(err)
	}
	c := cvm.New(reg, amSigner{priv, "provabl-am-v1"}, ts, nil)

	protocol := term.Seq(
		term.Nonce(),
		term.Seq(term.Meas(term.Self, nitrotpm.ID, "tpm://self", term.Params{"expected_pcr0": "aa"}), term.Sig()),
	)
	bundle, ch, err := c.Run(context.Background(), protocol)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	v, err := c.Appraise(context.Background(), bundle, ch)
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if !v.Pass {
		t.Fatalf("expected pass, reason: %s", v.Reason)
	}
	attrs := lower.ToAttributes(v)
	if attrs["platform.tpm_attested"].Value != "true" {
		t.Errorf("platform.tpm_attested = %q, want true", attrs["platform.tpm_attested"].Value)
	}
	if attrs["platform.tpm_nonce_verified"].Value != "true" {
		t.Errorf("platform.tpm_nonce_verified = %q, want true", attrs["platform.tpm_nonce_verified"].Value)
	}
	if attrs["platform.tpm_signature_valid"].Value != "true" {
		t.Errorf("platform.tpm_signature_valid = %q, want true", attrs["platform.tpm_signature_valid"].Value)
	}
}
