# Changelog

All notable changes to tpm will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`tpm preflight`** (provabl#16): verifies the calling principal holds the IAM actions tpm needs
  (`iam:TagRole` to write `attest:nitro-attested`, and `ec2:GetInstanceTpmEkPub` for the NitroTPM
  trust anchor) via read-only `iam:SimulatePrincipalPolicy` against the caller ARN. Renders ✓/✗ per
  action with remediation; exits non-zero on any deny; fail-closed on an un-callable check. New
  `internal/preflight` (mock-driven tests). Mirrors attest/ground. See `docs/required-permissions.md`.
- **Initial NitroTPM attestation producer** — the boot-chain counterpart to `nitro`, filling the
  deferred producer half of the evidence kernel's `nitrotpm` provider (evidence#6). Implements the
  kernel's injected `Source` and `Verifier`:
  - `internal/tpmquote` — `FileSource` (captured quote, always-compiled/testable) and `DeviceSource`
    (`//go:build linux && tpm`, reads `/dev/tpmrm0` via `go-tpm-tools` `client.AttestationKeyRSA` +
    `Key.Quote`); a `Verifier` that checks the TPM quote signature against the trusted attestation-key
    public key and confirms the TPMS_ATTEST is a well-formed quote.
  - `internal/attestor` — runs the `nitrotpm` provider through the kernel, lowers to
    `.tpm/attestation.json` (`context.platform.tpm_*`), and writes the `attest:nitro-attested` IAM tag.
  - `cmd/tpm attest` — `--device` (live `/dev/tpmrm0`) or `--quote` + `--ak-pub` (offline), with
    `--expected-pcr*`, `--role-arn`/`--region`, and `--capture` to persist a fetched quote (+ AK
    pubkey) for later offline appraisal.
- **Trust model documented honestly**: AWS NitroTPM publishes no root CA, so verification anchors to
  the EK/AK **public key** (from `aws ec2 get-instance-tpm-ek-pub` / the device run), carried in the
  kernel `trust.Root.Material`. v1 proves "a TPM on this instance signed these PCRs with this nonce
  against a recorded AK pubkey"; binding the AK to the AWS-vouched EK (`TPM2_ActivateCredential`) is
  v2 — see README.
- Hardware-free fixture tests (software-AK quote: good verifies, tampered/wrong-key/empty-root fail)
  plus a kernel round-trip test through the real `nitrotpm` provider; a real captured-quote fixture
  from NitroTPM hardware validation.
- **SLSA L3 release workflow** (provabl#5): `release.yml` from the start uses the
  `slsa-framework/slsa-github-generator` reusable workflow (isolated, non-falsifiable builder) —
  cosign keyless signatures, an attested SBOM, and L3 provenance over the combined artifact hashes.
  The L3 proof is produced on the first tag.
