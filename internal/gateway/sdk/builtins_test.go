// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sdk

import (
	"encoding/json/v2"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestHR200_TheFaceKnowsTheBuiltInsTheSDKsDo: the face's built-in tools are
// exactly the "builtins" of sdk/conformance/sdk_face.json, which the SDKs
// test against too, so no SDK observes a name the face denies or the
// reverse. Track S brings the file; on a branch without it there is
// nothing to compare yet.
func TestHR200_TheFaceKnowsTheBuiltInsTheSDKsDo(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "sdk", "conformance", "sdk_face.json"))
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("sdk/conformance/sdk_face.json comes with track S")
	} else if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Builtins []string `json:"builtins"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	face := make([]string, 0, len(builtIns))
	for name := range builtIns {
		face = append(face, name)
	}
	slices.Sort(face)
	want := slices.Sorted(slices.Values(vectors.Builtins))
	if !slices.Equal(face, want) {
		t.Fatalf("the face's built-ins %v, sdk_face.json's %v", face, want)
	}
	for name := range mcpResourceTools {
		if !builtIns[name] {
			t.Errorf("%s is denied as an MCP resource tool but is not built in", name)
		}
	}
}
