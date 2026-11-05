// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package browsercompare

import (
	"hash/fnv"
	"html"
	"regexp"
	"strings"
)

// Slots is the number of min-hashes in a fingerprint (G0 M33 D986).
const Slots = 64

// shingleWords is the length of a shingle in words.
const shingleWords = 5

// seedStart is splitmix64's starting state for the min-hash seeds
// ("PCLAWS").
const seedStart uint64 = 0x50434C415753

// seeds are the first Slots outputs of splitmix64 from seedStart.
var seeds = func() [Slots]uint64 {
	var out [Slots]uint64
	state := seedStart
	for i := range out {
		state += 0x9e3779b97f4a7c15
		z := state
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		out[i] = z ^ (z >> 31)
	}
	return out
}()

var (
	comments = regexp.MustCompile(`(?s)<!--.*?-->`)
	// The content of these elements is never text (RE2 has no
	// backreferences, so one expression per element).
	hidden = []*regexp.Regexp{
		regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script\s*>`),
		regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style\s*>`),
		regexp.MustCompile(`(?is)<noscript\b[^>]*>.*?</noscript\s*>`),
		regexp.MustCompile(`(?is)<template\b[^>]*>.*?</template\s*>`),
	}
	tags = regexp.MustCompile(`(?s)<[^>]*>`)
)

// Text is a page's visible text as the compare reads it: script, style,
// noscript and template content and comments dropped, then tags,
// entities unescaped, lowercased, whitespace collapsed.
func Text(page []byte) string {
	s := comments.ReplaceAllString(string(page), " ")
	for _, re := range hidden {
		s = re.ReplaceAllString(s, " ")
	}
	s = tags.ReplaceAllString(s, " ")
	s = strings.ToLower(html.UnescapeString(s))
	return strings.Join(strings.Fields(s), " ")
}

// Fingerprint is a text's min-hash signature over word 5-shingles; ok is
// false for a text with no words.
type Fingerprint struct {
	Min [Slots]uint64
	OK  bool
}

// Sign returns text's fingerprint: for each slot i the least
// FNV-1a-64(shingle) XOR seed[i] over its shingles. A text of fewer than
// five words is one shingle.
func Sign(text string) Fingerprint {
	words := strings.Fields(text)
	var f Fingerprint
	if len(words) == 0 {
		return f
	}
	for i := range f.Min {
		f.Min[i] = ^uint64(0)
	}
	n := max(len(words)-shingleWords+1, 1)
	for start := range n {
		end := min(start+shingleWords, len(words))
		h := fnv.New64a()
		_, _ = h.Write([]byte(strings.Join(words[start:end], " ")))
		v := h.Sum64()
		for i := range f.Min {
			if x := v ^ seeds[i]; x < f.Min[i] {
				f.Min[i] = x
			}
		}
	}
	f.OK = true
	return f
}

// Similarity is the share of equal slots of a and b in permille (0..1000):
// equal slots / 64. Two texts with no words are alike; one is unlike any
// other.
func Similarity(a, b Fingerprint) int32 {
	switch {
	case !a.OK && !b.OK:
		return 1000
	case !a.OK || !b.OK:
		return 0
	}
	equal := 0
	for i := range a.Min {
		if a.Min[i] == b.Min[i] {
			equal++
		}
	}
	return int32(equal * 1000 / Slots)
}
