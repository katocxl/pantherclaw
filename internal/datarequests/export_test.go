// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package datarequests

import (
	"errors"
	"testing"
)

func TestHR390_ExportFileCountIsBoundedBeforeAllocatingArchive(t *testing.T) {
	b := archiveBuilder{manifest: &ExportManifest{Files: make([]ExportFile, maxExportFiles)}}
	if err := b.add(t.Context(), "tables/agents/000001.jsonl", nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("file cap was not enforced before archive creation: %v", err)
	}
	if b.zip != nil || b.buf.Len() != 0 {
		t.Fatal("oversized manifest allocated archive data")
	}
}
