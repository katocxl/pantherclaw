// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

const pngData = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

// placeholderOf is the omitted form the capture must hold for raw.
func placeholderOf(typ, raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return `{"type":"` + typ + `","omitted":true,"bytes":` + itoa(len(raw)) + `,"sha256":"` + hex.EncodeToString(sum[:]) + `"}`
}

// TestHR757_ImagesAndDocumentsAreOmittedFromCaptures: every image,
// document or screenshot block (Anthropic image and document at any depth,
// tool_result content included; Chat image_url; Responses input_image,
// input_file and computer_call_output.output; Bedrock image, document and
// video) is replaced by its type, omitted, its size and the SHA-256 of its
// raw JSON, and the text is kept.
func TestHR757_ImagesAndDocumentsAreOmittedFromCaptures(t *testing.T) {
	anthImage := `{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + pngData + `"}}`
	anthDoc := `{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"JVBERi0xLjQK"}}`
	chatImage := `{"type":"image_url","image_url":{"url":"data:image/png;base64,` + pngData + `"}}`
	respImage := `{"type":"input_image","image_url":"data:image/png;base64,` + pngData + `"}`
	respFile := `{"type":"input_file","filename":"a.pdf","file_data":"JVBERi0xLjQK"}`
	screenshot := `{"type":"computer_screenshot","image_url":"data:image/png;base64,` + pngData + `"}`
	bedImage := `{"image":{"format":"png","source":{"bytes":"` + pngData + `"}}}`
	bedVideo := `{"video":{"format":"mp4","source":{"bytes":"AAAA"}}}`
	for name, tc := range map[string]struct {
		body string
		want []string
	}{
		"anthropic": {
			`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"look at this"},` + anthImage + `,` + anthDoc + `]},` +
				`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"shot"},` + anthImage + `]}]}]}`,
			[]string{`"text":"look at this"`, `"text":"shot"`, placeholderOf("image", anthImage), placeholderOf("document", anthDoc)},
		},
		"chat": {
			`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"what is it"},` + chatImage + `]}]}`,
			[]string{`"text":"what is it"`, placeholderOf("image_url", chatImage)},
		},
		"responses": {
			`{"model":"m","input":[{"role":"user","content":[{"type":"input_text","text":"read"},` + respImage + `,` + respFile + `]},` +
				`{"type":"computer_call_output","call_id":"c1","output":` + screenshot + `}]}`,
			[]string{
				`"text":"read"`, `"call_id":"c1"`, placeholderOf("input_image", respImage), placeholderOf("input_file", respFile),
				`"output":` + placeholderOf("computer_screenshot", screenshot),
			},
		},
		"bedrock": {
			`{"messages":[{"role":"user","content":[{"text":"see"},` + bedImage + `,{"toolResult":{"toolUseId":"t","content":[` + bedVideo + `]}}]}]}`,
			[]string{`"text":"see"`, placeholderOf("image", bedImage), placeholderOf("video", bedVideo)},
		},
	} {
		out, ok := withoutImages([]byte(tc.body))
		if !ok {
			t.Fatalf("%s: not parsed", name)
		}
		s := string(out)
		if strings.Contains(s, pngData) || strings.Contains(s, "JVBERi0xLjQK") || strings.Contains(s, `"AAAA"`) {
			t.Errorf("%s: image data kept: %s", name, s)
		}
		for _, w := range tc.want {
			if !strings.Contains(s, w) {
				t.Errorf("%s: %s lacks %s", name, s, w)
			}
		}
		if !jsontext.Value(out).IsValid() {
			t.Errorf("%s: not JSON: %s", name, s)
		}
	}
}

// TestHR757_TextOnlyBodiesAreKeptAndUnparseableOnesAreNot: a body with no
// image is kept as it is, while a body that is not one JSON value is
// replaced by {"omitted":true,"bytes":N} in the capture.
func TestHR757_TextOnlyBodiesAreKeptAndUnparseableOnesAreNot(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}],"max_tokens":10}`
	out, ok := withoutImages([]byte(body))
	if !ok || string(out) != body {
		t.Fatalf("text body changed: %s", out)
	}
	for _, bad := range []string{`{"a":`, `{"a":1} {"b":2}`, "not json", `{"a":"` + pngData + `"`} {
		if _, ok := withoutImages([]byte(bad)); ok {
			t.Errorf("%q parsed", bad)
		}
	}

	conn := &control.Connection{
		GatewayConnection: &pb.GatewayConnection{Id: "c", Kind: KindModel, Model: &pb.ModelConfig{CapturePrompts: true}},
		Captures: []*pb.GatewayCaptureProfile{{
			Id: "p", Operations: []string{"model.messages.create"}, Request: true, ByteCap: 1 << 16,
			ExpireTime: timestamppb.New(time.Now().Add(time.Hour)),
		}},
	}
	bad := `{"messages":[{"type":"image","source":{"data":"` + pngData + `"}}]` // cut short
	caps := modelCaptures(conn, "model.messages.create", false, []byte(bad), nil, 0, nil, time.Now())
	if len(caps) != 1 || string(caps[0].GetContent()) != `{"omitted":true,"bytes":`+itoa(len(bad))+`}` {
		t.Fatalf("an unparseable body was captured: %+v", caps)
	}
	img := `{"messages":[{"role":"user","content":[{"type":"image","source":{"data":"` + pngData + `"}}]}]}`
	caps = modelCaptures(conn, "model.messages.create", false, []byte(img), nil, 0, nil, time.Now())
	if len(caps) != 1 || strings.Contains(string(caps[0].GetContent()), pngData) || !strings.Contains(string(caps[0].GetContent()), `"omitted":true`) {
		t.Fatalf("captured %+v", caps)
	}
}

// TestHR757_FileAudioAndContainerUploadsAreOmitted: Chat file and
// input_audio parts and Anthropic container_upload blocks are omitted like
// images (D1221 M4).
func TestHR757_FileAudioAndContainerUploadsAreOmitted(t *testing.T) {
	for typ, block := range map[string]string{
		"file":             `{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,JVBERi0xLjQK"}}`,
		"input_audio":      `{"type":"input_audio","input_audio":{"data":"UklGRiQAAABXQVZF","format":"wav"}}`,
		"container_upload": `{"type":"container_upload","file_id":"file_011CNha8iCJcU1wXNR6q4V8w"}`,
	} {
		body := `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"here"},` + block + `]}]}`
		out, ok := withoutImages([]byte(body))
		if !ok {
			t.Fatalf("%s: not parsed", typ)
		}
		want := `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"here"},` + placeholderOf(typ, block) + `]}]}`
		if string(out) != want {
			t.Errorf("%s: got %s, want %s", typ, out, want)
		}
	}
}

// allocs is the bytes f allocates.
func allocs(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestHR757_DeepBodiesAreOmittedInBoundedMemory: a 16 MiB body nested 5000
// deep is kept as omitted with reason too_deep, in memory under three times
// its size, and a large shallow body with an image is rewritten within the
// same bound (D1221 H1).
func TestHR757_DeepBodiesAreOmittedInBoundedMemory(t *testing.T) {
	const depth, size = 5000, 16 << 20
	open, closing := strings.Repeat(`{"a":`, depth), strings.Repeat(`}`, depth)
	deep := []byte(open + `"` + strings.Repeat("x", size-len(open)-len(closing)-2) + `"` + closing)
	var (
		out []byte
		ok  bool
	)
	if n := allocs(func() { out, ok = withoutImages(deep) }); n >= 3*uint64(len(deep)) {
		t.Errorf("deep body allocated %d bytes for %d", n, len(deep))
	}
	if want := `{"omitted":true,"bytes":` + itoa(len(deep)) + `,"reason":"too_deep"}`; !ok || string(out) != want {
		t.Fatalf("deep body kept as %.200s", out)
	}
	// Depth 64 is kept; 65 is not.
	at64 := strings.Repeat(`[`, 64) + strings.Repeat(`]`, 64)
	if out, ok := withoutImages([]byte(at64)); !ok || string(out) != at64 {
		t.Errorf("depth 64 changed: %s", out)
	}
	if out, _ := withoutImages([]byte(`[` + at64 + `]`)); !strings.Contains(string(out), `"too_deep"`) {
		t.Errorf("depth 65 kept: %s", out)
	}

	img := `{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + pngData + `"}}`
	text := strings.Repeat("y", size)
	shallow := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"` + text + `"},` + img + `]}]}`)
	if n := allocs(func() { out, ok = withoutImages(shallow) }); n >= 3*uint64(len(shallow)) {
		t.Errorf("shallow body allocated %d bytes for %d", n, len(shallow))
	}
	if !ok || strings.Contains(string(out), pngData) || !strings.Contains(string(out), placeholderOf("image", img)) || !strings.Contains(string(out), text) {
		t.Fatal("shallow body not rewritten")
	}

	conn := &control.Connection{
		GatewayConnection: &pb.GatewayConnection{Id: "c", Kind: KindModel, Model: &pb.ModelConfig{CapturePrompts: true}},
		Captures: []*pb.GatewayCaptureProfile{{
			Id: "p", Operations: []string{"model.messages.create"}, Request: true, ByteCap: 1 << 16,
			ExpireTime: timestamppb.New(time.Now().Add(time.Hour)),
		}},
	}
	caps := modelCaptures(conn, "model.messages.create", false, deep, nil, 0, nil, time.Now())
	if len(caps) != 1 || !strings.Contains(string(caps[0].GetContent()), `"reason":"too_deep"`) {
		t.Fatalf("deep body captured as %+v", caps)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
