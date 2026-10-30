// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Covers: F123

// TestHR434_ReplayServesTheRecordedSensitiveReads (G0 M16 D73): a replay
// serves the run tree's recorded sensitive reads, classes and ids only; a
// recording made before the read has none (no class was recorded then),
// and a read for another run is a gap, never a guess.
func TestHR434_ReplayServesTheRecordedSensitiveReads(t *testing.T) {
	ctx := context.Background()
	org := ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000a1")
	run, txn := ids.NewV7(), ids.NewV7()
	at := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

	old := recording.NewReader(org, &recording.Recording{}, recording.Served{})
	if got, err := old.SensitiveReads(ctx, org, run); err != nil || got != nil {
		t.Fatalf("an older recording: %v %v", got, err)
	}

	rec := &recording.Recording{Reads: recording.Reads{Sensitive: &recording.Sensitive{
		Run: run.String(), Reads: []recording.SensitiveRead{{Transaction: txn.String(), Run: run.String(), Operation: "crm.contact.get", Class: "pii", At: at}},
	}}}
	r := recording.NewReader(org, rec, recording.Served{})
	got, err := r.SensitiveReads(ctx, org, run)
	if err != nil || len(got) != 1 || got[0] != (pipeline.SensitiveRead{TransactionID: txn, RunID: run, Operation: "crm.contact.get", Class: "pii", At: at}) {
		t.Fatalf("replayed: %+v %v", got, err)
	}
	if _, err := r.SensitiveReads(ctx, org, ids.NewV7()); !errors.Is(err, recording.ErrNotRecorded) || len(r.Gaps()) != 1 {
		t.Fatalf("another run: %v, gaps %v", err, r.Gaps())
	}
	raw, err := recording.Encode(rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"content", "body", "value"} {
		if strings.Contains(string(raw), `"`+field+`":`) {
			t.Fatalf("the recorded read history has a %q member: %s", field, raw)
		}
	}
}
