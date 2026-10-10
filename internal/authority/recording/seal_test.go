// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func recorded(t testing.TB) (*pipelinetest.Scenario, *recording.Recording) {
	t.Helper()
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	req := refund(s, s.Run(g.ID, s.Alice), "ch_1", "30.00")
	rec := recording.NewRecorder(s.W, req)
	if _, err := (&pipeline.Pipeline{}).EvaluateWith(t.Context(), rec, req); err != nil {
		t.Fatal(err)
	}
	r, err := rec.Recording()
	if err != nil {
		t.Fatal(err)
	}
	return s, r
}

// TestHR062_ReplayInputsAreSealedToTheirRow: the sealed inputs open only
// for their own org, transaction and evaluation, under the
// evaluation_inputs purpose, and carry the plaintext's digest.
func TestHR062_ReplayInputsAreSealedToTheirRow(t *testing.T) {
	s, r := recorded(t)
	sealer := recording.NewSealer(pccrypto.NewEnvelope(pipelinetest.TestDEKs{}))
	txn := ids.NewV7()
	sealed, err := sealer.Seal(t.Context(), s.Org, txn, 1, r)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := recording.Encode(r)
	if sealed.Truncated || sealed.Inputs == nil || bytes.Contains(sealed.Inputs, []byte("payments")) {
		t.Fatalf("sealed = %+v", sealed)
	}
	if sealed.Format != recording.FormatVersion || sealed.Pipeline != pipeline.Version {
		t.Fatalf("versions = %d, %d", sealed.Format, sealed.Pipeline)
	}
	opened, err := sealer.Open(t.Context(), s.Org, txn, 1, *sealed)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := recording.Encode(opened); !bytes.Equal(again, plain) {
		t.Fatal("the opened recording differs")
	}
	other := ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000b2")
	for name, open := range map[string]func() error{
		"another evaluation":  func() error { _, err := sealer.Open(t.Context(), s.Org, txn, 2, *sealed); return err },
		"another transaction": func() error { _, err := sealer.Open(t.Context(), s.Org, ids.NewV7(), 1, *sealed); return err },
		"another org":         func() error { _, err := sealer.Open(t.Context(), other, txn, 1, *sealed); return err },
		"another digest": func() error {
			c := *sealed
			c.Digest[0] ^= 1
			_, err := sealer.Open(t.Context(), s.Org, txn, 1, c)
			return err
		},
		"a flipped byte": func() error {
			c := *sealed
			c.Inputs = bytes.Clone(c.Inputs)
			c.Inputs[len(c.Inputs)-1] ^= 1
			_, err := sealer.Open(t.Context(), s.Org, txn, 1, c)
			return err
		},
	} {
		if err := open(); !errors.Is(err, recording.ErrUnreadable) {
			t.Errorf("%s: err = %v, want ErrUnreadable", name, err)
		}
	}
}

// TestReplayInputsOverTheCapAreTruncated: a recording over 32 KiB
// compressed keeps only its digest, and opening it says so.
func TestReplayInputsOverTheCapAreTruncated(t *testing.T) {
	s, r := recorded(t)
	// Incompressible facts the size of the cap.
	var b strings.Builder
	for i := range 3000 {
		b.WriteString(ids.NewV7().String()[i%8:])
	}
	r.Reads.Runs[0].TaskRef = b.String()
	sealer := recording.NewSealer(pccrypto.NewEnvelope(pipelinetest.TestDEKs{}))
	txn := ids.NewV7()
	sealed, err := sealer.Seal(t.Context(), s.Org, txn, 1, r)
	if err != nil {
		t.Fatal(err)
	}
	if !sealed.Truncated || sealed.Inputs != nil {
		t.Fatalf("sealed = truncated %v, %d bytes", sealed.Truncated, len(sealed.Inputs))
	}
	if _, err := sealer.Open(t.Context(), s.Org, txn, 1, *sealed); !errors.Is(err, recording.ErrTruncated) {
		t.Fatalf("open: %v, want ErrTruncated", err)
	}
}

// TestRecordingFormatIsVersioned: a recording of another format is refused
// as such, and unknown members are refused.
func TestRecordingFormatIsVersioned(t *testing.T) {
	_, r := recorded(t)
	raw, _ := recording.Encode(r)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["format"] = 2
	newer, _ := json.Marshal(m)
	if _, err := recording.Decode(newer); !errors.Is(err, recording.ErrFormat) {
		t.Fatalf("format 2: %v", err)
	}
	m["format"], m["extra"] = 1, true
	unknown, _ := json.Marshal(m)
	if _, err := recording.Decode(unknown); !errors.Is(err, recording.ErrInvalid) {
		t.Fatalf("unknown member: %v", err)
	}
	dup := bytes.Replace(raw, []byte(`{"format":1,`), []byte(`{"format":1,"format":1,`), 1)
	if _, err := recording.Decode(dup); err == nil {
		t.Fatal("a duplicate member decoded")
	}
}

// TestTamperedRecordingHoldsNoReads: the inputs of a tampering denial are
// the request and the stored action hash, nothing read.
func TestTamperedRecordingHoldsNoReads(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	req := refund(s, s.Run(g.ID, s.Alice), "ch_1", "30.00")
	r := recording.NewTampered(req, strings.Repeat("ab", 32))
	raw, err := recording.Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	back, err := recording.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.Tampered == nil || back.Tampered.StoredActionHash != strings.Repeat("ab", 32) || back.Reads.Containment != nil {
		t.Fatalf("tampered = %+v", back)
	}
}
