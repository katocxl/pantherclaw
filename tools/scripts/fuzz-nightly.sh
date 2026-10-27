#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
set -euo pipefail

# Fixed, reviewed security parser targets; ordinary tests run separately.
# Go writes a minimized failing input under the package's testdata/fuzz.
while read -r package target; do
  go test -run '^$' -fuzz "^${target}$" -fuzztime "${PC_FUZZ_TIME:-30s}" \
    -fuzzminimizetime 5s -parallel 2 "$package"
done <<'TARGETS'
./internal/actionir FuzzParse
./internal/actionir FuzzNormalizePath
./internal/authn/credential FuzzParse
./internal/identity/pap FuzzProofVerify
./internal/definitions/manifest FuzzManifest
./internal/definitions/mapping FuzzCanonicalMapping
./internal/grants/domain FuzzGrantBounds
./internal/approvals/domain FuzzUntrustedBlock
./internal/evidence/bundle FuzzBundle
./internal/evidence/bundle FuzzDataDocuments
./internal/evidence/pack FuzzPack
TARGETS
