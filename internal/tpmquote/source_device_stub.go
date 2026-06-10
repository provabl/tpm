// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && tpm)

// Stub DeviceSource for every build that is not the device path (no `tpm` tag, or
// not Linux). It keeps the package building everywhere and fails loudly if a caller
// tries to read the TPM outside a device build. The real reader is in
// source_device.go (build with -tags tpm on a NitroTPM Linux instance).

package tpmquote

import (
	"context"
	"fmt"

	"github.com/provabl/evidence/providers/nitrotpm"
	"github.com/provabl/evidence/term"
)

// DeviceSource is the non-device stub.
type DeviceSource struct {
	// AKPubOut matches the real DeviceSource's field so callers compile unchanged.
	AKPubOut *[]byte
}

// Fetch always errors: the TPM device read is compiled only with `-tags tpm` on
// Linux. Use FileSource (a captured quote) otherwise.
func (DeviceSource) Fetch(_ context.Context, _ term.Target, _ []byte) (nitrotpm.TPMQuote, error) {
	return nitrotpm.TPMQuote{}, fmt.Errorf("tpm device source not available: build with -tags tpm and run on a NitroTPM Linux instance, or use --quote")
}
