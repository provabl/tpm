// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

//go:build linux && tpm

// This file is compiled only with the `tpm` build tag and only on Linux. It reads
// a live quote from the NitroTPM device (/dev/tpmrm0), which exists on a regular
// Nitro EC2 instance. Build the producer's device path with:
//   go build -tags tpm ./...
// The default build (and CI) uses the stub in source_device_stub.go and never
// touches the device.

package tpmquote

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/provabl/evidence/providers/nitrotpm"
	"github.com/provabl/evidence/term"
)

// tpmDevice is the TPM 2.0 resource-manager device present on a NitroTPM instance.
const tpmDevice = "/dev/tpmrm0"

// defaultQuotePCRs is the boot-chain PCR set quoted by default: 0 (UEFI firmware),
// 4 (bootloader), 7 (secure-boot policy). Callers can widen this later.
var defaultQuotePCRs = []int{0, 4, 7}

// DeviceSource reads a fresh quote from the NitroTPM device, embedding the run's
// challenge nonce as the quote's qualifyingData so the kernel appraiser can bind it.
type DeviceSource struct {
	// AKPubOut, if non-nil, receives the attestation key's DER PKIX public key —
	// the trust material a verifier needs. The caller records/publishes it (and, in
	// v2, binds it to the AWS-vouched EK via TPM2_ActivateCredential).
	AKPubOut *[]byte
}

// Fetch implements nitrotpm.Source.
func (s DeviceSource) Fetch(_ context.Context, _ term.Target, nonce []byte) (nitrotpm.TPMQuote, error) {
	rwc, err := tpm2.OpenTPM(tpmDevice)
	if err != nil {
		return nitrotpm.TPMQuote{}, fmt.Errorf("open %s (is NitroTPM enabled on this instance?): %w", tpmDevice, err)
	}
	defer func() { _ = rwc.Close() }()

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		return nitrotpm.TPMQuote{}, fmt.Errorf("load attestation key: %w", err)
	}
	defer ak.Close()

	if s.AKPubOut != nil {
		der, err := x509.MarshalPKIXPublicKey(ak.PublicKey())
		if err != nil {
			return nitrotpm.TPMQuote{}, fmt.Errorf("marshal AK public key: %w", err)
		}
		*s.AKPubOut = der
	}

	q, err := ak.Quote(tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: defaultQuotePCRs}, nonce)
	if err != nil {
		return nitrotpm.TPMQuote{}, fmt.Errorf("TPM2_Quote: %w", err)
	}
	return fromPB(q, nonce)
}
