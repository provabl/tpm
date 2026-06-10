# tpm — Project Rules

## Overview

tpm is the **AWS NitroTPM** attestation producer in the Provabl suite — the boot-chain counterpart
to [nitro](https://github.com/provabl/nitro) (which does Nitro **Enclaves**). It runs the
`provabl/evidence` `nitrotpm` provider in-process and writes the durable outputs the suite consumes:
`.tpm/attestation.json` (read by attest as `context.platform.tpm_*`) and the `attest:nitro-attested`
IAM tag (checked by ground's SCP — the same tag nitro writes; both mean "the runtime is attested").

## Hard rules

1. **The evidence kernel is a dependency, never the reverse.** This tool imports
   `provabl/evidence/providers/nitrotpm` and supplies its injected `Source` + `Verifier`. The kernel
   stays stdlib-only; the real TPM libs (`google/go-tpm`, `google/go-tpm-tools`) live here.
2. **The `/dev/tpmrm0` device read is NitroTPM-instance-only.** It lives behind `//go:build linux &&
   tpm` with a stub for every other build, is compile-checked (`make build-tpm`) but never *run* in
   CI, and must never be in the default build path. The offline path is `--quote` + a captured-quote
   fixture, exercised by the tests.
3. **Trust anchors to a public key, not a CA.** AWS publishes no NitroTPM root CA; the verifier
   anchors to the AK/EK **public key** (from `aws ec2 get-instance-tpm-ek-pub` / the device run),
   carried in the kernel's `trust.Root.Material`. Do not invent an embedded root.
4. **Don't overclaim v1.** v1 proves "a TPM on this instance signed these PCRs with this nonce vs a
   recorded AK pubkey." The AK→EK binding (`TPM2_ActivateCredential`) is v2 — state the boundary
   plainly in user-facing output and docs.
5. **The producer never appraises.** Nonce binding, PCR policy, and `platform.tpm_*` claim emission
   are the kernel appraiser's job. The Source gathers; the Verifier only checks the signature.

## Layout

```
cmd/tpm/               CLI: tpm attest --device | --quote
internal/tpmquote/     the producer — Source (file/device), Verifier, quote adapter
  source_device.go       //go:build linux && tpm — reads /dev/tpmrm0 via go-tpm-tools
  source_device_stub.go  //go:build !(linux && tpm) — errs loudly off-device
internal/attestor/     runs the kernel term, lowers to .tpm/attestation.json, writes the IAM tag
```

## Conventions

Go 1.26.4; Apache-2.0; SPDX headers; keepachangelog/semver; cosign keyless + SLSA L3 releases
(provabl#5 pattern). `make check` is the gate; `make build-tpm` is the device compile-check.
