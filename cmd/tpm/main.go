// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Command tpm produces an AWS NitroTPM boot-chain attestation and writes the
// suite's durable outputs: .tpm/attestation.json (read by attest as
// context.platform.*) and, optionally, the attest:nitro-attested IAM tag (checked
// by ground's SCP).
//
// Trust model: NitroTPM publishes no root CA. Verification anchors to the
// attestation key's PUBLIC key — read live from the device on --device, or supplied
// with --ak-pub for a captured --quote. Binding the AK to the AWS-vouched
// endorsement key (TPM2_ActivateCredential) is future work; see README.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/spf13/cobra"

	"github.com/provabl/evidence/providers/nitrotpm"
	"github.com/provabl/tpm/internal/attestor"
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
	cmd.AddCommand(attestCmd())
	return cmd
}

func attestCmd() *cobra.Command {
	var (
		quotePath    string
		akPubPath    string
		useDevice    bool
		roleARN      string
		tpmDir       string
		region       string
		expectedPCR0 string
		expectedPCR7 string
	)
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Produce a NitroTPM attestation and write .tpm/attestation.json",
		Long: `Produce an AWS NitroTPM boot-chain attestation, writing the lowered result
to .tpm/attestation.json for attest's context.platform.* and, when --role-arn is
given and the quote is attested, the attest:nitro-attested IAM tag ground's SCP checks.

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
				fmt.Printf("✓ Tagged role %s: %s=true\n", res.TaggedRole, attestor.TagNitroAttested)
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
	cmd.Flags().StringVar(&roleARN, "role-arn", "", "IAM role ARN to tag attest:nitro-attested=true when attested")
	cmd.Flags().StringVar(&tpmDir, "tpm-dir", ".tpm", "output directory for attestation.json")
	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region for IAM tagging")
	cmd.Flags().StringVar(&expectedPCR0, "expected-pcr0", "", "require this PCR0 (UEFI firmware) hex value")
	cmd.Flags().StringVar(&expectedPCR7, "expected-pcr7", "", "require this PCR7 (secure-boot policy) hex value")
	return cmd
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
