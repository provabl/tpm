# Changelog

All notable changes to tpm will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Bump indirect `golang.org/x/crypto` v0.45.0 → v0.52.0** (suite-wide x/crypto sweep). Raises the
  dependency-graph floor past the 8 HIGH SSH/knownhosts CVEs (CVE-2026-39827/39828/39829/39830/39835,
  -42508, -46595/46597) — the same family fixed in attest. The vulnerable code is **not reachable**
  from tpm (govulncheck: 0 affected), so this is defense-in-depth / tidiness, not a reachable fix; the
  bump is stable under `go mod tidy`. Build + full test suite green.

### Changed

- **tpm now writes `attest:boot-attested`** (was the conflated `attest:nitro-attested`), per
  provabl ADR 0003 / provabl#30 (tpm#4). The boot producer and the enclave producer (`nitro`)
  previously wrote the same `attest:nitro-attested` tag, but they prove different properties at
  different trust strengths — tpm proves a measured, known-good OS boot (NitroTPM PCRs), nitro
  proves a verified Nitro Enclave. The conflated tag is split per property: `nitro` now writes
  `attest:enclave-attested`, tpm writes `attest:boot-attested`. A tag names what was proven, not
  which tool proved it. A writer-scoped conformance test (`schema_conformance_test.go`, embedding
  the canonical `attest-tags-schema.json` v3) locks tpm's constant to the registry's `writer:"tpm"`
  row and fails if the pre-split tag reappears.

### Added


- **Added a `Security Scan` workflow** (`.github/workflows/security.yml`): govulncheck + Trivy filesystem (dependency) + Trivy IaC scans on every push/PR and weekly, blocking on HIGH/CRITICAL. Trivy pinned to `v0.36.0`. Brings this repo in line with the rest of the suite — every Provabl tool now self-scans, fitting a security/compliance suite. The standalone govulncheck job moved out of `ci.yaml` into this workflow (no longer duplicated).
- **`tpm attest --expected-from-ami`** (provabl#13): on the live instance, auto-loads the expected
  PCRs from the source AMI's `attest:pcr<N>` golden tags (the ones `vet ami-reference` writes) instead
  of the operator hand-copying hex into `--expected-pcrN`. Reads the source AMI id from IMDS
  (`ami-id`) and the tags via `ec2:DescribeImages`, feeding them to the `expected_pcr<N>` appraiser
  check — so an instance whose measured boot diverges from the vetted image's golden reference fails
  attestation. Explicit `--expected-pcrN` flags override the AMI-derived values; a source AMI with no
  `attest:pcr*` tags is an error (fail-closed, not an unenforced check). The golden tags are locked to
  the vetter by ground's lockdown SCP, so an instance cannot rewrite its own reference. New
  `internal/goldenpcr` (IMDS + DescribeImages behind interfaces; fake-driven tests). Closes the
  runtime-binding loop's last manual seam.
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
