// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"strings"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
)

// MaxTechniqueWhy bounds one technique_why line (G0 M28 D714).
const MaxTechniqueWhy = 200

// MaxTechniques bounds each of a file's atlas and attack lists.
const MaxTechniques = 16

// CheckTechniques checks the techniques of a library scenario or
// campaign (G0 M28 D714): each atlas id is in the pinned ATLAS catalog,
// each attack id in the pinned ATT&CK Enterprise catalog, each once, and
// technique_why gives every id, and nothing else, one line of at most 200
// characters that cites the id in parentheses, exactly like asi_why.
// techniques_none (D714b) replaces all three on a file that tests
// PantherClaw itself: one line of 1–200 characters. A file with neither
// parses; the closure test requires one of them on every library file.
func CheckTechniques(atlas, attack []string, why map[string]string, none string) error {
	if none != "" {
		switch {
		case len(atlas) > 0 || len(attack) > 0 || len(why) > 0:
			return invalid("techniques_none replaces atlas, attack and technique_why")
		case strings.TrimSpace(none) == "" || strings.ContainsAny(none, "\r\n") || utf8.RuneCountInString(none) > MaxTechniqueWhy:
			return invalid("techniques_none must be one line of at most %d characters", MaxTechniqueWhy)
		}
		return nil
	}
	if len(atlas) > MaxTechniques || len(attack) > MaxTechniques {
		return invalid("at most %d atlas and %d attack techniques", MaxTechniques, MaxTechniques)
	}
	seen := map[string]bool{}
	check := func(name string, ids []string, known func(string) bool) error {
		for _, id := range ids {
			if !known(id) {
				return invalid("%s: %q is not a technique of the pinned catalog", name, id)
			}
			if seen[id] {
				return invalid("%s: duplicate %q", name, id)
			}
			seen[id] = true
		}
		return nil
	}
	if err := check("atlas", atlas, catalog.KnownATLAS); err != nil {
		return err
	}
	if err := check("attack", attack, catalog.KnownATTACK); err != nil {
		return err
	}
	if len(why) != len(seen) {
		return invalid("technique_why must give one reason for each atlas and attack technique")
	}
	for id := range seen {
		w, ok := why[id]
		switch {
		case !ok:
			return invalid("technique_why gives no reason for %s", id)
		case strings.TrimSpace(w) == "" || strings.ContainsAny(w, "\r\n") || utf8.RuneCountInString(w) > MaxTechniqueWhy:
			return invalid("technique_why %s must be one line of at most %d characters", id, MaxTechniqueWhy)
		case !strings.Contains(w, "("+id+")"):
			return invalid("technique_why %s must cite the technique as (%s)", id, id)
		}
	}
	return nil
}
