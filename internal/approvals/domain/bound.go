// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"slices"
)

// BoundFact is one fact member an approval binds (HR-030 as the founder
// amended it on 2026-10-13, option B): a member a prerequisite declares in
// `binds`, such as a merge's github.pull.head.sha, by its value. An approval
// binds no other fact and never when a fact was observed: every other fact
// is read again, and decided on by the pipeline's steps 6 and 7, whenever
// the approval is used.
type BoundFact struct {
	Fact    string `json:"fact"`
	Subject string `json:"subject"`
	Member  string `json:"member"`
	Value   string `json:"value"`
}

// BoundFactsDigest is the digest of the bound fact members ("sha256:" and
// hex), in a fixed order; none have a digest too.
func BoundFactsDigest(bound []BoundFact) string {
	rows := slices.Clone(bound)
	if rows == nil {
		rows = []BoundFact{}
	}
	slices.SortFunc(rows, func(a, b BoundFact) int {
		return cmp.Or(cmp.Compare(a.Fact, b.Fact), cmp.Compare(a.Subject, b.Subject), cmp.Compare(a.Member, b.Member))
	})
	raw, _ := json.Marshal(rows, json.Deterministic(true))
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// boundValue is what a display shows of a fact: its bound members, or ""
// when the approval binds none of it (the page shows its current value).
func boundValue(bound []BoundFact, fact, subject string) string {
	var out string
	for _, b := range bound {
		if b.Fact == fact && b.Subject == subject {
			if out != "" {
				out += "; "
			}
			out += b.Member + ": " + b.Value
		}
	}
	return out
}
