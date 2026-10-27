// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package templates

import (
	"errors"
	"testing"
	"testing/fstest"
)

// TestLoad_ADefectIsAnErrorNotAPanic: a template that does not load is
// returned as an error to the start-up path (G0 M11 D120); nothing
// panics, and no template is served while it fails.
func TestLoad_ADefectIsAnErrorNotAPanic(t *testing.T) {
	if err := Load(); err != nil {
		t.Fatalf("the shipped templates: %v", err)
	}
	bad := fstest.MapFS{"broken.yaml": {Data: []byte("id: other\n")}}
	if _, err := load(bad); err == nil {
		t.Fatal("a defective template loaded")
	}

	defect := errors.New("templates: broken.yaml: defect")
	saved := library
	t.Cleanup(func() { library = saved })
	library = func() (map[string]*entry, error) { return nil, defect }
	if err := Load(); !errors.Is(err, defect) {
		t.Fatalf("Load = %v, want the defect", err)
	}
	if got := List(); len(got) != 0 {
		t.Errorf("List = %d templates while the library failed", len(got))
	}
	if _, ok := Get("bounded_task_launch"); ok {
		t.Error("Get found a template while the library failed")
	}
	if _, ok := Source("bounded_task_launch"); ok {
		t.Error("Source found a template while the library failed")
	}
	if _, _, err := Render("bounded_task_launch", nil); !errors.Is(err, defect) {
		t.Errorf("Render = %v, want the defect", err)
	}
}
