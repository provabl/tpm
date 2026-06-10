# SPDX-FileCopyrightText: 2026 Playground Logic LLC
# SPDX-License-Identifier: Apache-2.0

# tpm — AWS NitroTPM attestation producer.
#
# The default targets run everywhere (the TPM device read is excluded — it requires
# the `tpm` build tag and a NitroTPM-enabled instance with /dev/tpmrm0). `build-tpm`
# is the manual target that compile-checks the device Source on a machine that has no
# TPM; it is run by CI as a compile-only gate, never executed.

GOFLAGS := -trimpath
VERSION ?= dev

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

.PHONY: check
check: fmt vet test ## fmt + vet + test (the default gate)

.PHONY: fmt
fmt: ## gofmt the tree (check-only)
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: test
test: ## run tests (device read excluded — no tpm tag)
	go test ./...

.PHONY: build
build: ## build the tpm CLI
	go build $(GOFLAGS) -ldflags="-s -w -X main.version=$(VERSION)" -o bin/tpm ./cmd/tpm

.PHONY: build-tpm
build-tpm: ## compile-check the /dev/tpmrm0 device Source (NitroTPM-instance-only; never run here)
	GOOS=linux go build -tags tpm ./...

.PHONY: vuln
vuln: ## govulncheck
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: clean
clean: ## remove build artifacts
	rm -rf bin/ dist/
