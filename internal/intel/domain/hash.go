// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// ShingleWords is the number of words in one shingle (D1103).
const ShingleWords = 8

// MaxTextShingles bounds the shingles computed from one text, so a long body
// costs a bounded amount of work.
const MaxTextShingles = 8192

// Normalize is the text form every text hash is made from (D1103): Unicode
// NFC, every run of white space (Unicode White_Space) one ASCII space,
// trimmed, and lower-cased with Unicode simple case mapping
// (strings.ToLower). Nothing else is folded: confusables, invisible
// characters and punctuation stay as they are.
func Normalize(s string) string {
	s = norm.NFC.String(s)
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}

// Hash is the hex SHA-256 of s.
func Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ServerHash is the mcp_server hash of a server's reported name and version:
// sha256 of lower(name)@version (D1103). An empty name has none.
func ServerHash(name, version string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	return Hash(name + "@" + strings.TrimSpace(version))
}

// PackageHash is the mcp_server hash of a package reference and its
// version: sha256 of package_ref@version.
func PackageHash(ref, version string) string {
	if ref == "" {
		return ""
	}
	return Hash(ref + "@" + version)
}

// ImageHash is the mcp_server hash of an image digest ("sha256:<hex>"),
// lower-cased.
func ImageHash(digest string) string {
	digest = strings.ToLower(strings.TrimSpace(digest))
	if digest == "" {
		return ""
	}
	return Hash(digest)
}

// DescriptionHash is the tool_description hash: sha256 of the normalized
// text. An empty description has none.
func DescriptionHash(text string) string {
	n := Normalize(text)
	if n == "" {
		return ""
	}
	return Hash(n)
}

// Shingles are the hex SHA-256 of every run of ShingleWords consecutive
// words of the normalized text, words split at the single spaces Normalize
// leaves, sorted without repeats. A text of fewer words has one shingle,
// the whole normalized text; an empty text has none. At most
// MaxTextShingles are made, from the start of the text.
func Shingles(text string) []string {
	words := strings.Split(Normalize(text), " ")
	if len(words) == 1 && words[0] == "" {
		return nil
	}
	if len(words) < ShingleWords {
		return []string{Hash(strings.Join(words, " "))}
	}
	n := min(len(words)-ShingleWords+1, MaxTextShingles)
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, Hash(strings.Join(words[i:i+ShingleWords], " ")))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ContributionShingles are the shingles a contribution keeps: at most
// MaxShingles, spread evenly over the text's shingles in sorted order so
// the choice depends on the text alone.
func ContributionShingles(text string) []string {
	all := Shingles(text)
	if len(all) <= MaxShingles {
		return all
	}
	out := make([]string, 0, MaxShingles)
	for i := range MaxShingles {
		out = append(out, all[i*len(all)/MaxShingles])
	}
	return slices.Compact(out)
}

// Needed is how many of an injection_text indicator's n shingles a text
// must hold to match: min(3, n) (D1103).
func Needed(n int) int { return min(3, n) }
