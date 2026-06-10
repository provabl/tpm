// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package tpmquote

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/provabl/evidence/providers/nitrotpm"
	"github.com/provabl/evidence/term"
)

// CapturedQuote is the on-disk form of a quote captured from a device, so the
// file source and the device source converge on the same kernel TPMQuote. It is
// the full nitrotpm.TPMQuote, JSON-encoded — Nonce, PCRs, and the Raw envelope
// (TPMS_ATTEST + signature). `tpm attest --device` can write one of these for
// later offline appraisal, and the test fixtures are exactly this shape.
type CapturedQuote = nitrotpm.TPMQuote

// FileSource reads a captured quote (a JSON-encoded nitrotpm.TPMQuote) from disk
// and adapts it to nitrotpm.Source. The nonce argument (the run's challenge) is
// not used: a file source cannot re-mint the quote, so freshness is judged by the
// kernel appraiser against whatever nonce the captured quote carries (a quote
// minted for a different challenge will correctly fail nonce binding).
type FileSource struct {
	Path string
}

// Fetch implements nitrotpm.Source.
func (s FileSource) Fetch(_ context.Context, _ term.Target, _ []byte) (nitrotpm.TPMQuote, error) {
	raw, err := os.ReadFile(s.Path) // #nosec G304 — operator-supplied quote path
	if err != nil {
		return nitrotpm.TPMQuote{}, fmt.Errorf("read captured quote %q: %w", s.Path, err)
	}
	var q nitrotpm.TPMQuote
	if err := json.Unmarshal(raw, &q); err != nil {
		return nitrotpm.TPMQuote{}, fmt.Errorf("decode captured quote %q: %w", s.Path, err)
	}
	if len(q.Raw) == 0 {
		return nitrotpm.TPMQuote{}, fmt.Errorf("captured quote %q has no raw attest/signature", s.Path)
	}
	return q, nil
}
