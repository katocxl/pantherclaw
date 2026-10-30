// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package datarequests

import (
	"context"
	"errors"
	"testing"
)

type fakePush struct {
	parts    int
	bytes    int64
	manifest string
	aborted  bool
	failOn   int
}

func (f *fakePush) Write(ctx context.Context, part []byte, keepAlive func(context.Context) error) error {
	f.parts++
	f.bytes += int64(len(part))
	if err := keepAlive(ctx); err != nil {
		return err
	}
	if f.failOn != 0 && f.parts == f.failOn {
		return errors.New("the destination went away")
	}
	return nil
}

func (f *fakePush) Finish(_ context.Context, manifest string, _ func(context.Context) error) error {
	f.manifest = manifest
	return nil
}

func (f *fakePush) Abort() { f.aborted = true }

func noKeepAlive(context.Context) error { return nil }

// TestHR516_AStreamedExportHasNoStoredCap: with a push taking the parts the
// 2 GiB and 64-part caps of a stored export do not apply; without one they
// still do (downloads keep the cap).
// Covers: F517
func TestHR516_AStreamedExportHasNoStoredCap(t *testing.T) {
	over := func(b *archiveBuilder) error {
		b.total = MaxExportBytes
		b.manifest.Parts = make([]ExportPart, maxParts)
		if err := b.add(t.Context(), "tables/agents/000001.jsonl", []byte("{}\n")); err != nil {
			return err
		}
		return b.flush(t.Context())
	}
	stored := archiveBuilder{manifest: &ExportManifest{}}
	if err := over(&stored); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("stored: %v", err)
	}
	sink := &fakePush{}
	streamed := archiveBuilder{manifest: &ExportManifest{}, sink: sink, keepAlive: noKeepAlive}
	if err := over(&streamed); err != nil {
		t.Fatalf("streamed: %v", err)
	}
	if sink.parts != 1 || len(streamed.manifest.Parts) != maxParts+1 {
		t.Fatalf("%d parts sent, %d in the manifest", sink.parts, len(streamed.manifest.Parts))
	}
	if got := streamed.manifest.Parts[maxParts].Number; got != maxParts+1 {
		t.Fatalf("part number %d", got)
	}
}
