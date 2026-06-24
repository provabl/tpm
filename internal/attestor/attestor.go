// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package attestor runs the provabl/evidence nitrotpm provider against a TPM quote
// source and turns the verdict into the suite's durable outputs: a
// .tpm/attestation.json file (read by attest as context.platform.*) and an
// attest:boot-attested IAM principal tag (checked by ground's SCP — distinct from
// the enclave producer's attest:enclave-attested, since the two prove different
// properties at different trust strengths).
package attestor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/provabl/evidence/asp"
	"github.com/provabl/evidence/cvm"
	"github.com/provabl/evidence/lower"
	"github.com/provabl/evidence/providers/nitrotpm"
	"github.com/provabl/evidence/term"
)

// TagBootAttested is the IAM principal tag ground's SCP checks for BOOT-chain
// attestation: it asserts the principal BOOTED a measured, known-good OS (proven
// via a NitroTPM TPM 2.0 quote over the boot PCRs). It is deliberately distinct
// from nitro's attest:enclave-attested (running inside a verified Nitro Enclave) —
// a tag names what was proven, not which tool proved it, and the two are different
// trust strengths (no conflation). See provabl ADR 0003 and the canonical attest:*
// registry (attest-tags-schema.json, writer "tpm").
const TagBootAttested = "attest:boot-attested"

// PlatformResult is the .tpm/attestation.json artifact. Its json tags match
// attest's context.platform.* contract (a JSON shape, not a shared Go type, so the
// two version independently). Keys use the tpm_* namespace the nitrotpm provider
// emits, distinct from the enclave provider's.
type PlatformResult struct {
	TPMAttested    bool              `json:"tpm_attested"`
	NonceVerified  bool              `json:"tpm_nonce_verified"`
	SignatureValid bool              `json:"tpm_signature_valid"`
	PCRs           map[string]string `json:"tpm_pcrs"`
}

// IAMTagger writes tags to an IAM role. Implemented by the AWS IAM client in
// production; mocked in tests.
type IAMTagger interface {
	TagRole(ctx context.Context, roleName string, tags map[string]string) error
}

// Attestor produces attestation outputs from a TPM quote source. akPubDER is the
// trusted attestation-key public key (DER PKIX) the Verifier anchors to — for
// NitroTPM this stands in for a CA root (none is published; see internal/tpmquote).
type Attestor struct {
	src      nitrotpm.Source
	ver      nitrotpm.Verifier
	akPubDER *[]byte
	tagger   IAMTagger
	tpmDir   string
}

// New builds an Attestor. tpmDir defaults to ".tpm". tagger may be nil. akPubDER
// points to the trusted AK public key (DER); it becomes the kernel trust root the
// Verifier resolves. A pointer because with --device the key is not known until the
// source runs — the trust store reads it at appraisal time (see trust.go).
func New(src nitrotpm.Source, ver nitrotpm.Verifier, akPubDER *[]byte, tagger IAMTagger, tpmDir string) *Attestor {
	if tpmDir == "" {
		tpmDir = ".tpm"
	}
	return &Attestor{src: src, ver: ver, akPubDER: akPubDER, tagger: tagger, tpmDir: tpmDir}
}

// Result is the outcome of an attestation run.
type Result struct {
	Platform   PlatformResult
	Reason     string
	WrotePath  string
	TaggedRole string
}

// Attest runs the nitrotpm provider through the evidence kernel, lowers the
// verdict, writes .tpm/attestation.json, and — when attested and a roleARN is
// given — writes the attest:boot-attested tag to that role.
func (a *Attestor) Attest(ctx context.Context, roleARN string, expectedPCRs map[string]string) (*Result, error) {
	reg := asp.NewRegistry()
	if err := reg.Register(nitrotpm.Provider(a.src, a.ver)); err != nil {
		return nil, fmt.Errorf("register nitrotpm provider: %w", err)
	}
	am, err := newEphemeralAM()
	if err != nil {
		return nil, err
	}
	store := newTrustStore(am, nitrotpm.RootName, a.akPubDER)
	c := cvm.New(reg, am, store, nil)

	params := term.Params{}
	for idx, want := range expectedPCRs {
		params["expected_pcr"+idx] = want
	}

	protocol := term.Seq(
		term.Nonce(),
		term.Seq(
			term.Meas(term.Self, nitrotpm.ID, term.Target("tpm://self"), params),
			term.Sig(),
		),
	)
	bundle, ch, err := c.Run(ctx, protocol)
	if err != nil {
		return nil, fmt.Errorf("run attestation: %w", err)
	}
	verdict, err := c.Appraise(ctx, bundle, ch)
	if err != nil {
		return nil, fmt.Errorf("appraise: %w", err)
	}

	attrs := lower.ToAttributes(verdict)
	res := &Result{Platform: platformFromAttrs(attrs, verdict.Pass), Reason: verdict.Reason}

	path, err := a.write(res.Platform)
	if err != nil {
		return nil, err
	}
	res.WrotePath = path

	if res.Platform.TPMAttested && roleARN != "" && a.tagger != nil {
		roleName := roleNameFromARN(roleARN)
		if roleName == "" {
			return nil, fmt.Errorf("could not extract role name from ARN: %s", roleARN)
		}
		if err := a.tagger.TagRole(ctx, roleName, map[string]string{TagBootAttested: "true"}); err != nil {
			return nil, fmt.Errorf("tag role %s: %w", roleName, err)
		}
		res.TaggedRole = roleName
	}
	return res, nil
}

// platformFromAttrs maps lowered kernel attributes into the artifact. Absent
// platform.* attributes (CollectFailed) default to zero/false — fail-closed.
func platformFromAttrs(attrs map[string]lower.Attr, pass bool) PlatformResult {
	b := func(k string) bool { return attrs["platform."+k].Value == "true" }
	pcrs := map[string]string{}
	for k, v := range attrs {
		if idx, ok := strings.CutPrefix(k, "platform.tpm_pcr"); ok {
			pcrs[idx] = v.Value
		}
	}
	return PlatformResult{
		TPMAttested:    pass && b("tpm_attested"),
		NonceVerified:  b("tpm_nonce_verified"),
		SignatureValid: b("tpm_signature_valid"),
		PCRs:           pcrs,
	}
}

func (a *Attestor) write(p PlatformResult) (string, error) {
	if err := os.MkdirAll(a.tpmDir, 0o750); err != nil {
		return "", fmt.Errorf("create %s: %w", a.tpmDir, err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal attestation: %w", err)
	}
	path := filepath.Join(a.tpmDir, "attestation.json")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// roleNameFromARN extracts the role name from an IAM role ARN.
func roleNameFromARN(arn string) string {
	const sep = ":role/"
	i := strings.LastIndex(arn, sep)
	if i == -1 {
		return ""
	}
	return arn[i+len(sep):]
}
