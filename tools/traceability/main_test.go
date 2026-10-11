// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"bytes"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func TestExpandRefs(t *testing.T) {
	got := expandRefs("HR-050..052; HR-062, HR-130..131 and T-003")
	want := []string{"HR-050", "HR-051", "HR-052", "HR-062", "HR-130", "HR-131"}
	if !slices.Equal(got, want) {
		t.Fatalf("expandRefs = %v, want %v", got, want)
	}
}

func TestMissing(t *testing.T) {
	rules := []Item{{ID: "HR-001", Due: "M1.5"}, {ID: "HR-004", Due: "M1"}, {ID: "HR-090", Due: "M3"}, {ID: "HR-130", Due: "M0"}}
	threats := []Item{
		{ID: "T-003", Due: "M1", Mitigate: []string{"HR-050"}},
		{ID: "T-040", Due: "M0", Mitigate: []string{"HR-130"}},
		{ID: "T-016", Due: "M1", Mitigate: []string{"HR-062"}},
	}
	tests := map[string]bool{"TestHR004": true, "TestHR130": true, "TestT003": true}
	got := Missing(rules, threats, tests, "M1")
	if len(got) != 1 || !strings.HasPrefix(got[0], "T-016") {
		t.Fatalf("Missing = %v, want only T-016 (HR-001 is due at M1.5, HR-090 at M3)", got)
	}
	if got := Missing(rules, threats, tests, "M1.5"); len(got) != 2 {
		t.Fatalf("through M1.5: %v", got)
	}
}

func TestDeliveryOrder(t *testing.T) {
	// ADR-0017: the range (M12) lands before the preview, so its rules are due
	// before those of M10; M14 lands before M13.
	rules := []Item{{ID: "HR-120", Due: "M12"}, {ID: "HR-200", Due: "M10"}}
	if got := Missing(rules, nil, map[string]bool{}, "M9"); len(got) != 0 {
		t.Fatalf("through M9: %v, want nothing due", got)
	}
	if got := Missing(rules, nil, map[string]bool{}, "M12"); len(got) != 1 || !strings.HasPrefix(got[0], "HR-120") {
		t.Fatalf("through M12: %v, want only HR-120", got)
	}
	if milestoneIndex("M14") >= milestoneIndex("M13") {
		t.Fatalf("M14 must come before M13")
	}
}

// TestCollectsSDKTests: the SDKs' Python and TypeScript tests count under
// the Go test names (G0 M8); other files and names do not.
func TestCollectsSDKTests(t *testing.T) {
	fsys := fstest.MapFS{
		"sdk/go/v_test.go":                      {Data: []byte("func TestHR202_Refuses(t *testing.T) {}")},
		"sdk/python/tests/test_client.py":       {Data: []byte("    def test_HR200_fails_closed(self) -> None:\n    def test_T080_bypass(self):\n")},
		"sdk/typescript/test/client.test.ts":    {Data: []byte("test(\"TestHR201_checks the hash\", async () => {});\ntest(`TestT081_replay`, () => {});\n")},
		"sdk/python/tests/helper.py":            {Data: []byte("def test_HR199_not_a_test_file(self):")},
		"sdk/python/tests/test_notes.py":        {Data: []byte("# def test_HR195_in_a_comment(self):\n    \"\"\"See def test_HR194_in_a_docstring.\"\"\"\n")},
		"sdk/typescript/test/notes.test.ts":     {Data: []byte("// test(\"TestHR193_in a comment\")\nconst s = 'test(\"TestHR192_in a string\")';\n")},
		"sdk/typescript/src/client.ts":          {Data: []byte(`test("TestHR198_not a test file")`)},
		"sdk/typescript/test/other.test.ts":     {Data: []byte(`it("TestHR197_not node:test test()")`)},
		"sdk/typescript/node_modules/x.test.ts": {Data: []byte(`test("TestHR196_dependency")`)},
	}
	got, err := collectTests(fsys)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"TestHR200", "TestHR201", "TestHR202", "TestT080", "TestT081"}
	keys := slices.Sorted(maps.Keys(got))
	if !slices.Equal(keys, want) {
		t.Fatalf("collected %v, want %v", keys, want)
	}
}

func TestRunAgainstRepository(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"-root", "../..", "-through", "M1"}, &out, &errb)
	if code != 0 {
		t.Fatalf("repository traceability through M1 failed (%d):\n%s%s", code, out.String(), errb.String())
	}
	if code := run([]string{"-root", "../..", "-through", "M99"}, &out, &errb); code != 2 {
		t.Fatalf("unknown milestone accepted")
	}
}
