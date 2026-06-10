// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package tpmquote

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"os"
	"testing"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/provabl/evidence/providers/nitrotpm"
	"github.com/provabl/evidence/trust"
)

// fixture builds a quote the way a real TPM would, but signed by a software RSA
// key — no hardware. It returns the kernel TPMQuote (as a producer would emit it),
// the trust.Root carrying the AK public key, and the key for tamper cases.
type fixture struct {
	quote nitrotpm.TPMQuote
	root  trust.Root
	akKey *rsa.PrivateKey
}

func newFixture(t *testing.T, nonce []byte) fixture {
	t.Helper()
	ak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return newFixtureWithKey(t, nonce, ak)
}

// newFixtureWithKey builds a fixture quote bound to the given nonce, signed by a
// caller-supplied AK — so a kernel round-trip can re-sign per issued challenge with
// a stable key (the trust root must keep matching).
func newFixtureWithKey(t *testing.T, nonce []byte, ak *rsa.PrivateKey) fixture {
	t.Helper()

	// A well-formed TPMS_ATTEST quote with the run's nonce as ExtraData.
	ad := legacy.AttestationData{
		Magic:           0xff544347, // TPM_GENERATED_VALUE
		Type:            legacy.TagAttestQuote,
		ExtraData:       nonce,
		FirmwareVersion: 0x2000000000000,
		AttestedQuoteInfo: &legacy.QuoteInfo{
			PCRSelection: legacy.PCRSelection{Hash: legacy.AlgSHA256, PCRs: []int{0, 7}},
			PCRDigest:    tpmutil.U16Bytes{0xab, 0xcd}, // opaque to the verifier (digest check is the appraiser's concern)
		},
	}
	attest, err := ad.Encode()
	if err != nil {
		t.Fatalf("encode TPMS_ATTEST: %v", err)
	}

	// Sign the attest blob the way the TPM does: RSASSA over SHA-256(attest).
	h := crypto.SHA256.New()
	h.Write(attest)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, ak, crypto.SHA256, h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	sig := legacy.Signature{
		Alg: legacy.AlgRSASSA,
		RSA: &legacy.SignatureRSA{HashAlg: legacy.AlgSHA256, Signature: sigBytes},
	}
	sigEnc, err := sig.Encode()
	if err != nil {
		t.Fatalf("encode signature: %v", err)
	}

	raw, err := json.Marshal(rawQuote{Attest: attest, Sig: sigEnc})
	if err != nil {
		t.Fatal(err)
	}
	akDER, err := x509.MarshalPKIXPublicKey(&ak.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	return fixture{
		quote: nitrotpm.TPMQuote{
			Nonce: nonce,
			PCRs:  map[string]string{"0": "aa", "7": "dd"},
			Raw:   raw,
		},
		root:  Root(akDER),
		akKey: ak,
	}
}

func TestVerify_GoodQuotePasses(t *testing.T) {
	f := newFixture(t, []byte("a-32-byte-challenge-nonce-value!"))
	ok, err := NewVerifier().Verify(context.Background(), f.quote.Raw, f.root)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected the good quote to verify")
	}
}

func TestVerify_TamperedAttestFails(t *testing.T) {
	f := newFixture(t, []byte("a-32-byte-challenge-nonce-value!"))
	var rq rawQuote
	if err := json.Unmarshal(f.quote.Raw, &rq); err != nil {
		t.Fatal(err)
	}
	rq.Attest[len(rq.Attest)-1] ^= 0xff // flip a byte the signature covers
	tampered, _ := json.Marshal(rq)

	ok, err := NewVerifier().Verify(context.Background(), tampered, f.root)
	if ok {
		t.Fatal("expected a tampered attest blob to fail signature verification")
	}
	if err == nil {
		t.Fatal("expected an error for the tampered quote")
	}
}

func TestVerify_WrongKeyFails(t *testing.T) {
	f := newFixture(t, []byte("a-32-byte-challenge-nonce-value!"))
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)

	ok, err := NewVerifier().Verify(context.Background(), f.quote.Raw, Root(otherDER))
	if ok || err == nil {
		t.Fatal("expected verification against the wrong AK public key to fail")
	}
}

func TestVerify_EmptyRootFails(t *testing.T) {
	f := newFixture(t, []byte("a-32-byte-challenge-nonce-value!"))
	if ok, err := NewVerifier().Verify(context.Background(), f.quote.Raw, trust.Root{Name: nitrotpm.RootName}); ok || err == nil {
		t.Fatal("expected verification with no trusted key to fail")
	}
}

// FileSource round-trips a captured quote: marshal the fixture TPMQuote to disk,
// read it back, and confirm it still verifies — the offline producer path.
func TestFileSource_RoundTrip(t *testing.T) {
	f := newFixture(t, []byte("a-32-byte-challenge-nonce-value!"))
	path := t.TempDir() + "/quote.json"
	b, _ := json.Marshal(f.quote)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := FileSource{Path: path}.Fetch(context.Background(), "tpm://self", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got.Nonce) != string(f.quote.Nonce) {
		t.Errorf("nonce round-trip mismatch")
	}
	if ok, err := NewVerifier().Verify(context.Background(), got.Raw, f.root); !ok || err != nil {
		t.Fatalf("round-tripped quote failed verification: ok=%v err=%v", ok, err)
	}
}
