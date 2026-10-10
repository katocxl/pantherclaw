// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package migrations

import (
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// listerIn returns the last definition of pc.cross_org_list in the Up or
// Down section of a migration.
func listerIn(t *testing.T, file, section string) string {
	t.Helper()
	b, err := fs.ReadFile(FS, file)
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatalf("%s has no Down section", file)
	}
	s := up
	if section == "Down" {
		s = down
	}
	i := strings.LastIndex(s, "CREATE OR REPLACE FUNCTION pc.cross_org_list")
	if i < 0 {
		t.Fatalf("%s %s does not define the lister", file, section)
	}
	def, _, ok := strings.Cut(s[i:], "-- +goose StatementEnd")
	if !ok {
		t.Fatalf("%s %s: the lister definition is not closed", file, section)
	}
	return def
}

var purposePattern = regexp.MustCompile(`WHEN '([a-z_]+)' THEN`)

func purposes(def string) []string {
	var out []string
	for _, m := range purposePattern.FindAllStringSubmatch(def, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestM7B_CheckpointsKeepEveryListerPurposeAndDownRestoresIt: 00065 adds
// checkpoints_due and integrity_due to every purpose 00060 defined, and its
// Down migration restores 00060's lister exactly.
func TestM7B_CheckpointsKeepEveryListerPurposeAndDownRestoresIt(t *testing.T) {
	before := listerIn(t, "00060_effects.sql", "Up")
	after := listerIn(t, "00065_checkpoints.sql", "Up")
	if got, want := purposes(after), append(purposes(before), "checkpoints_due", "integrity_due"); !slices.Equal(got, want) {
		t.Errorf("00065 lister purposes = %v, want %v", got, want)
	}
	if down := listerIn(t, "00065_checkpoints.sql", "Down"); down != before {
		t.Error("00065's Down migration does not restore the lister of 00060 exactly")
	}
}
