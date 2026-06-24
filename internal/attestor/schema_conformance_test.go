// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package attestor

import (
	_ "embed"
	"encoding/json"
	"testing"
)

// canonicalTagsSchemaJSON is the byte-identical copy of the suite's canonical
// attest:* tag registry (source of truth: provabl/attest pkg/schema, mirrored in
// qualify). Per provabl ADR 0003, each writer repo locks ITS OWN rows to the
// registry so a tag rename fails that writer's CI rather than silently in
// production. tpm is the writer of attest:boot-attested.
//
//go:embed attest-tags-schema.json
var canonicalTagsSchemaJSON []byte

type tagRow struct {
	Key    string `json:"key"`
	Writer string `json:"writer"`
	Type   string `json:"type"`
}

type tagRegistry struct {
	Tags []tagRow `json:"tags"`
}

// TestBootTagMatchesRegistry locks tpm's tag constant to the canonical registry's
// tpm-writer row. If the registry renames the tag (or tpm's const drifts), this
// fails — the writer-scoped conformance guard from ADR 0003.
func TestBootTagMatchesRegistry(t *testing.T) {
	var reg tagRegistry
	if err := json.Unmarshal(canonicalTagsSchemaJSON, &reg); err != nil {
		t.Fatalf("parse canonical registry: %v", err)
	}

	var tpmRows []tagRow
	for _, r := range reg.Tags {
		if r.Writer == "tpm" {
			tpmRows = append(tpmRows, r)
		}
	}

	// tpm writes exactly one tag today: attest:boot-attested.
	if len(tpmRows) != 1 {
		t.Fatalf("registry has %d writer=tpm rows, want 1: %+v", len(tpmRows), tpmRows)
	}
	if tpmRows[0].Key != TagBootAttested {
		t.Errorf("registry tpm tag = %q, but TagBootAttested = %q — they must match (ADR 0003)",
			tpmRows[0].Key, TagBootAttested)
	}
	if tpmRows[0].Type != "bool" {
		t.Errorf("attest:boot-attested type = %q, want bool", tpmRows[0].Type)
	}

	// Guard against the pre-split conflated tag reappearing.
	for _, r := range reg.Tags {
		if r.Key == "attest:nitro-attested" {
			t.Error("registry still contains attest:nitro-attested — it was split into enclave/boot-attested (ADR 0003)")
		}
	}
}
