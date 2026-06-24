// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Command tpm produces an AWS NitroTPM boot-chain attestation and writes the
// suite's durable outputs: .tpm/attestation.json (read by attest as
// context.platform.*) and, optionally, the attest:boot-attested IAM tag (checked
// by ground's SCP).
//
// Trust model: NitroTPM publishes no root CA. Verification anchors to the
// attestation key's PUBLIC key — read live from the device on --device, or supplied
// with --ak-pub for a captured --quote. Binding the AK to the AWS-vouched
// endorsement key (TPM2_ActivateCredential) is future work; see README.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/spf13/cobra"

	"github.com/provabl/evidence/providers/nitrotpm"
	"github.com/provabl/evidence/term"
	"github.com/provabl/tpm/internal/attestor"
	"github.com/provabl/tpm/internal/goldenpcr"
	"github.com/provabl/tpm/internal/preflight"
	"github.com/provabl/tpm/internal/tpmquote"
)

var version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "tpm",
		Short:   "AWS NitroTPM boot-chain attestation producer for the Provabl suite",
		Version: version,
	}
	cmd.AddCommand(attestCmd(), preflightCmd())
	return cmd
}

// preflightCmd verifies the calling principal holds the IAM actions tpm needs.
func preflightCmd() *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Verify the calling principal holds the IAM permissions tpm needs",
		Long: `Check that the calling AWS principal can perform tpm's AWS-touching actions
(iam:TagRole to write attest:boot-attested, and ec2:GetInstanceTpmEkPub for the
NitroTPM trust anchor) via read-only iam:SimulatePrincipalPolicy against the
caller — it evaluates, it does not act. A denied action prints a remediation and
the command exits non-zero. See docs/required-permissions.md.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPreflight(preflight.CheckCallerPermissions(cmd.Context(), region))
		},
	}
	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region")
	return cmd
}

// runPreflight renders preflight results and returns a non-nil error if any failed.
func runPreflight(results []preflight.Result) error {
	failures := 0
	for _, r := range results {
		if r.Status {
			fmt.Printf("  ✓ %s\n", r.Name)
			continue
		}
		failures++
		fmt.Printf("  ✗ %s: %s\n", r.Name, r.Detail)
		if r.Remediation != "" {
			fmt.Printf("      Remediation: %s\n", r.Remediation)
		}
	}
	fmt.Println()
	if failures > 0 {
		return fmt.Errorf("preflight failed: %d required permission(s) missing", failures)
	}
	fmt.Println("✓ All required permissions present")
	return nil
}

func attestCmd() *cobra.Command {
	var (
		quotePath     string
		akPubPath     string
		capturePath   string
		useDevice     bool
		roleARN       string
		tpmDir        string
		region        string
		expectedPCR0  string
		expectedPCR7  string
		expectFromAMI bool
	)
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Produce a NitroTPM attestation and write .tpm/attestation.json",
		Long: `Produce an AWS NitroTPM boot-chain attestation, writing the lowered result
to .tpm/attestation.json for attest's context.platform.* and, when --role-arn is
given and the quote is attested, the attest:boot-attested IAM tag ground's SCP checks.

On a NitroTPM instance, use --device to read a fresh quote from /dev/tpmrm0 (requires
a binary built with -tags tpm). Off-instance, supply a captured quote with --quote and
the trusted attestation-key public key with --ak-pub (DER PKIX).`,
		RunE: func(_ *cobra.Command, _ []string) error {
			if (quotePath == "") == !useDevice {
				return fmt.Errorf("specify exactly one of --quote (a captured quote + --ak-pub) or --device (read /dev/tpmrm0)")
			}
			ctx := context.Background()

			var tagger attestor.IAMTagger
			if roleARN != "" {
				t, err := newIAMTagger(ctx, region)
				if err != nil {
					return err
				}
				tagger = t
			}

			var src nitrotpm.Source
			var akPubDER []byte
			subject := quotePath
			if useDevice {
				subject = "/dev/tpmrm0"
				// The device run emits the AK public key it quoted with; capture it
				// as the trust material the verifier anchors to.
				src = tpmquote.DeviceSource{AKPubOut: &akPubDER}
				// --capture persists the fetched quote (and the AK pubkey) for later
				// offline appraisal with --quote/--ak-pub.
				if capturePath != "" {
					src = &capturingSource{inner: src, quotePath: capturePath, akPubPath: capturePath + ".akpub", akPub: &akPubDER}
				}
			} else {
				if akPubPath == "" {
					return fmt.Errorf("--quote requires --ak-pub (the trusted attestation-key public key, DER PKIX)")
				}
				pub, err := os.ReadFile(akPubPath) // #nosec G304 — operator-supplied key path
				if err != nil {
					return fmt.Errorf("read --ak-pub %q: %w", akPubPath, err)
				}
				akPubDER = pub
				src = tpmquote.FileSource{Path: quotePath}
			}

			expected := map[string]string{}
			if expectFromAMI {
				golden, err := resolveGoldenPCRs(ctx, region)
				if err != nil {
					return fmt.Errorf("--expected-from-ami: %w", err)
				}
				if len(golden) == 0 {
					return fmt.Errorf("--expected-from-ami: source AMI carries no attest:pcr* golden tags (run 'vet ami-reference' first)")
				}
				for idx, v := range golden {
					expected[idx] = v
				}
			}
			// Explicit --expected-pcrN flags override the AMI-derived values.
			if expectedPCR0 != "" {
				expected["0"] = expectedPCR0
			}
			if expectedPCR7 != "" {
				expected["7"] = expectedPCR7
			}

			a := attestor.New(src, tpmquote.NewVerifier(), &akPubDER, tagger, tpmDir)
			res, err := a.Attest(ctx, roleARN, expected)
			if err != nil {
				return err
			}

			p := res.Platform
			fmt.Printf("NitroTPM attestation: %s\n\n", subject)
			fmt.Printf("  context.platform.tpm_attested       = %v\n", p.TPMAttested)
			fmt.Printf("  context.platform.tpm_nonce_verified = %v\n", p.NonceVerified)
			fmt.Printf("  context.platform.tpm_signature_valid= %v\n", p.SignatureValid)
			for idx, v := range p.PCRs {
				fmt.Printf("  context.platform.tpm_pcr%-3s        = %s\n", idx, v)
			}
			fmt.Printf("\n✓ Written to %s\n", res.WrotePath)
			if res.TaggedRole != "" {
				fmt.Printf("✓ Tagged role %s: %s=true\n", res.TaggedRole, attestor.TagBootAttested)
			}
			if !p.TPMAttested {
				fmt.Printf("\n✗ Not attested: %s\n", res.Reason)
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&quotePath, "quote", "", "path to a captured quote (JSON; requires --ak-pub)")
	cmd.Flags().StringVar(&akPubPath, "ak-pub", "", "trusted attestation-key public key, DER PKIX (for --quote)")
	cmd.Flags().BoolVar(&useDevice, "device", false, "read a fresh quote from /dev/tpmrm0 (NitroTPM instance; requires -tags tpm)")
	cmd.Flags().StringVar(&capturePath, "capture", "", "with --device: also write the fetched quote (JSON) here and the AK pubkey to <path>.akpub")
	cmd.Flags().StringVar(&roleARN, "role-arn", "", "IAM role ARN to tag attest:boot-attested=true when attested")
	cmd.Flags().StringVar(&tpmDir, "tpm-dir", ".tpm", "output directory for attestation.json")
	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region for IAM tagging")
	cmd.Flags().StringVar(&expectedPCR0, "expected-pcr0", "", "require this PCR0 (UEFI firmware) hex value")
	cmd.Flags().StringVar(&expectedPCR7, "expected-pcr7", "", "require this PCR7 (secure-boot policy) hex value")
	cmd.Flags().BoolVar(&expectFromAMI, "expected-from-ami", false, "load expected PCRs from this instance's source-AMI attest:pcr* tags (read on the live instance via IMDS + DescribeImages); --expected-pcrN overrides")
	return cmd
}

// resolveGoldenPCRs reads the golden boot PCRs recorded on this instance's source
// AMI (the attest:pcr* tags vet ami-reference writes), keyed by index → hex. Only
// meaningful when tpm runs on the live instance.
func resolveGoldenPCRs(ctx context.Context, region string) (map[string]string, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return goldenpcr.Resolve(ctx, imds.NewFromConfig(cfg), ec2.NewFromConfig(cfg))
}

// capturingSource wraps a nitrotpm.Source and persists the fetched quote (as the
// nitrotpm.TPMQuote JSON that FileSource reads) plus the AK public key, so a live
// device run can produce a reusable offline fixture. It is a pass-through otherwise.
type capturingSource struct {
	inner     nitrotpm.Source
	quotePath string
	akPubPath string
	akPub     *[]byte
}

func (c *capturingSource) Fetch(ctx context.Context, target term.Target, nonce []byte) (nitrotpm.TPMQuote, error) {
	q, err := c.inner.Fetch(ctx, target, nonce)
	if err != nil {
		return q, err
	}
	b, err := json.Marshal(q)
	if err != nil {
		return q, fmt.Errorf("marshal captured quote: %w", err)
	}
	if err := os.WriteFile(c.quotePath, b, 0o600); err != nil {
		return q, fmt.Errorf("write captured quote: %w", err)
	}
	if c.akPub != nil && len(*c.akPub) > 0 {
		if err := os.WriteFile(c.akPubPath, *c.akPub, 0o600); err != nil {
			return q, fmt.Errorf("write captured AK pubkey: %w", err)
		}
	}
	return q, nil
}

// awsIAMTagger adapts the AWS IAM client to attestor.IAMTagger.
type awsIAMTagger struct{ client *iam.Client }

func newIAMTagger(ctx context.Context, region string) (*awsIAMTagger, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &awsIAMTagger{client: iam.NewFromConfig(cfg)}, nil
}

func (t *awsIAMTagger) TagRole(ctx context.Context, roleName string, tags map[string]string) error {
	in := &iam.TagRoleInput{RoleName: aws.String(roleName)}
	for k, v := range tags {
		in.Tags = append(in.Tags, iamtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	_, err := t.client.TagRole(ctx, in)
	return err
}
