# tpm

**AWS NitroTPM boot-chain attestation producer for the Provabl suite.**

Part of the [Provabl](https://provabl.dev) suite:
- **[ground](https://ground.provabl.dev)** — deploy correct AWS foundations
- **[attest](https://attest.provabl.dev)** — compile, enforce, and prove compliance
- **[qualify](https://qualify.provabl.dev)** — train and qualify researchers
- **[vet](https://vet.provabl.dev)** — verify the software supply chain
- **[nitro](https://github.com/provabl/nitro)** — attest the runtime: AWS Nitro **Enclave** integrity
- **tpm** — attest the runtime: AWS **NitroTPM** boot-chain integrity ← you are here

> Ground your infrastructure, attest your controls, qualify your people, vet your software.

---

## What tpm does

`tpm` is the NitroTPM counterpart to [`nitro`](https://github.com/provabl/nitro). Where `nitro`
attests an isolated Nitro **Enclave** (the workload image), `tpm` attests the **boot chain of an
ordinary EC2 instance** via a TPM 2.0 quote — "did this instance boot a known-good OS?". Both feed
the same evidence kernel and the same `context.platform.*` Cedar inputs.

```
NitroTPM /dev/tpmrm0  ──►  tpm  ──►  .tpm/attestation.json   (read by attest → context.platform.tpm_*)
                                └─►  attest:nitro-attested tag (checked by ground's SCP)
```

It runs the [`provabl/evidence`](https://github.com/provabl/evidence) `nitrotpm` provider in-process:
the appraiser binds the challenge nonce (the quote's qualifyingData) and applies the PCR policy; this
tool supplies the real `Source` (a TPM2_Quote over the boot PCRs) and `Verifier` (the quote signature
against the attestation key).

## Trust model — read this

NitroTPM is **not** like Nitro Enclaves, and the difference matters:

- **Nitro Enclaves** ship a signed document with an X.509 chain to a **published AWS root CA**.
  `nitro` embeds that root and verifies the chain.
- **AWS NitroTPM publishes no root CA.** You retrieve the instance's endorsement-key (EK) **public
  key** out-of-band from the EC2 control plane — `aws ec2 get-instance-tpm-ek-pub` — and trust is
  anchored there. So `tpm`'s verifier anchors to a **public key**, not a certificate chain.

**v1 scope (this release).** `tpm` proves: *a TPM on this instance signed these PCRs with this
nonce, verifiable against a recorded attestation-key (AK) public key.* The trust anchor is the
EK/AK public key you obtained from AWS.

**v2 (documented, not yet built).** Cryptographically binding the quoting AK to the AWS-vouched EK
via `TPM2_ActivateCredential` — proving the AK lives in the same TPM AWS vouches for. Until then,
the EK→AWS-API linkage is the trust root, and that boundary is stated honestly rather than hidden.

## Usage

```bash
# On a NitroTPM instance: read a fresh quote from /dev/tpmrm0 (binary built with -tags tpm)
tpm attest --device --expected-pcr7 9f8e7d…

# Tag a principal's role when attested (gated by ground's SCP)
tpm attest --device --role-arn arn:aws:iam::123456789012:role/Workload --region us-west-2

# Off-instance: verify a captured quote against a recorded AK public key
tpm attest --quote quote.json --ak-pub ak-pub.der --expected-pcr0 3d458c…
```

## Quote sources

| Source | When | Freshness |
|---|---|---|
| `--device` (`/dev/tpmrm0`) | on a NitroTPM instance | always fresh — the run's nonce is the quote's qualifyingData; the AK pubkey is captured from the same run |
| `--quote <file>` + `--ak-pub` | offline, from a captured quote | freshness judged by the appraiser against the nonce the quote carries |

The device source is compiled only under the `tpm` build tag (`make build-tpm`) and runs **only on a
NitroTPM instance**. CI compile-checks it but cannot exercise it.

## Development

```bash
make check       # gofmt + go vet + go test (the device read is excluded)
make build       # build bin/tpm
make build-tpm   # compile-check the NitroTPM-only /dev/tpmrm0 source
```

## License

Apache 2.0. Copyright 2026 Playground Logic LLC.
