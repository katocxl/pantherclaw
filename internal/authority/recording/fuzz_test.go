// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"bytes"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/recording"
)

// FuzzRecordingDecode: any bytes either fail to decode or decode to a
// recording whose encoding decodes to the same encoding; the decoder never
// panics, and neither does Unpack on any compressed input.
func FuzzRecordingDecode(f *testing.F) {
	_, r := recorded(f)
	raw, err := recording.Encode(r)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"format":1}`))
	f.Add([]byte(`{"format":1,"pipeline":1,"request":{"action":{},"instance":"","agent":"","attestation":0,"gateway":""},"reads":{}}`))
	f.Add([]byte{0x01, 0x00, 0x00, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = recording.Unpack(b, recording.Sealed{Format: recording.FormatVersion, Pipeline: 1})
		got, err := recording.Decode(b)
		if err != nil {
			return
		}
		enc, err := recording.Encode(got)
		if err != nil {
			t.Fatalf("a decoded recording does not encode: %v", err)
		}
		again, err := recording.Decode(enc)
		if err != nil {
			t.Fatalf("a re-encoded recording does not decode: %v\n%s", err, enc)
		}
		enc2, _ := recording.Encode(again)
		if !bytes.Equal(enc, enc2) {
			t.Fatalf("the encoding is not stable:\n%s\n%s", enc, enc2)
		}
	})
}
