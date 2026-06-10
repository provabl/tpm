// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package tpmquote

import (
	"context"
	"os"
	"testing"
)

// real-quote.bin and real-quote.akpub are a genuine NitroTPM quote + attestation-key
// public key captured from a real m6i.large instance (us-west-2) while validating
// this producer for evidence#6. They pin the producer against real hardware output:
// FileSource must parse the captured nitrotpm.TPMQuote, and the Verifier must
// validate the quote signature against the real AK public key.
//
// Note: this is a SIGNATURE-validity test, deliberately independent of the kernel's
// fresh-nonce binding. A captured quote binds the nonce of its original device run,
// so re-appraising it through the kernel correctly fails freshness (a replayed quote
// is not fresh) — that path is covered by kernel_test.go with a per-run-signed quote.
func TestVerify_RealCapturedQuote(t *testing.T) {
	raw, err := os.ReadFile("testdata/real-quote.bin")
	if err != nil {
		t.Skipf("no real-quote fixture: %v", err)
	}
	akPub, err := os.ReadFile("testdata/real-quote.akpub")
	if err != nil {
		t.Fatalf("read AK pubkey fixture: %v", err)
	}

	// FileSource parses the captured quote into the kernel shape.
	q, err := FileSource{Path: "testdata/real-quote.bin"}.Fetch(context.Background(), "tpm://self", nil)
	if err != nil {
		t.Fatalf("FileSource.Fetch real quote: %v", err)
	}
	if len(q.Raw) == 0 || len(q.PCRs) == 0 {
		t.Fatal("parsed real quote has no Raw or PCRs")
	}
	if len(q.Nonce) == 0 {
		t.Error("real quote carries no nonce (qualifyingData)")
	}

	// The Verifier validates the real signature against the real AK public key.
	ok, err := NewVerifier().Verify(context.Background(), q.Raw, Root(akPub))
	if err != nil {
		t.Fatalf("Verify real quote signature: %v", err)
	}
	if !ok {
		t.Fatal("expected the real captured quote's signature to verify against its AK")
	}

	// Sanity: verifying against bytes that are not the recorded AK must fail
	// (guards against an accidentally-trivial Verify). Use the raw quote bytes as a
	// non-key — ParsePKIXPublicKey will reject them.
	if ok, _ := NewVerifier().Verify(context.Background(), q.Raw, Root(raw[:64])); ok {
		t.Fatal("expected verification against a non-key to fail")
	}
}
