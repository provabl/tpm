# tpm — required AWS permissions

`tpm preflight` verifies the calling AWS principal holds these actions, using
read-only `iam:SimulatePrincipalPolicy` against the caller ARN (from
`sts:GetCallerIdentity`). It **evaluates, it never acts** — running preflight changes
nothing. A denied action prints a remediation and the command exits non-zero.

Most of what `tpm` does is **on-instance and needs no AWS at all**: reading the TPM 2.0
quote from `/dev/tpmrm0` (`--device`), appraising it through the evidence `nitrotpm`
provider, and writing the lowered verdict to `.tpm/attestation.json`. The `--quote`
offline path (a captured quote + `--ak-pub`) is likewise fully local. The AWS-touching
paths are the ones below.

| Action | Needed by | Status |
|--------|-----------|--------|
| `sts:GetCallerIdentity` | preflight itself (resolves the caller ARN to simulate) | live |
| `iam:SimulatePrincipalPolicy` | preflight itself (the permission self-check) | live |
| `iam:TagRole` | `tpm attest --role-arn` — write the `attest:boot-attested` IAM role tag on the attested principal's role (ground's SCP gates on it) once the quote verifies | live |
| `ec2:GetInstanceTpmEkPub` | the NitroTPM trust anchor — fetch the instance's EK/AK **public key** (`aws ec2 get-instance-tpm-ek-pub`), because AWS publishes no NitroTPM root CA | live |

`iam:TagRole` is exercised only when you pass `--role-arn`; without it, `tpm` still
verifies the quote and writes `.tpm/attestation.json` locally, but tags nothing.

## Why preflight checks every action

The check is read-only, and simulating an action the current invocation will not use
costs nothing. Listing all four lets an operator confirm the `tpm` principal is ready
for both the tagging path (`--role-arn`) and the trust-anchor fetch
(`ec2:GetInstanceTpmEkPub`) **before** a run, rather than discovering a missing grant
mid-attestation. To scope a principal to only the local verify path today, grant
`sts:GetCallerIdentity` + `iam:SimulatePrincipalPolicy` (preflight) and nothing else —
the `--device`/`--quote` appraisal and the `.tpm/attestation.json` write need no AWS.

## Boundary

`tpm` **proves a boot chain and writes evidence; it never decides access** (attest does,
via the Cedar PDP reading `context.platform.tpm_*`) and never enforces the tag itself
(ground's SCP does). Trust anchors to the EK/AK **public key** fetched from the EC2
control plane — **not** an X.509 chain to a published root CA, which is `nitro`'s model
for enclaves, not NitroTPM's. The `attest:boot-attested` tag is the boot-chain
(measured-OS) signal, deliberately **not** conflated with `nitro`'s
`attest:enclave-attested` (provabl ADR 0003). See the [README](../README.md) trust model
and provabl ADR 0003.
