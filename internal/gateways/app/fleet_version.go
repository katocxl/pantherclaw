// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"strconv"
	"strings"
)

// Version is a parsed gateway version, vMAJOR.MINOR.PATCH[-pre] (G0 M18
// D151). The leading v is optional, as release builds report it without
// one. The zero Version is "unknown": what an unparseable report reads as,
// and never compliant with a minimum (HR-470).
type Version struct {
	Major, Minor, Patch uint64
	Pre                 string
	known               bool
}

// maxVersionLen matches the reported version's column limit (00186).
const maxVersionLen = 64

// ParseVersion parses s. ok is false, and the Version unknown, for anything
// else: "dev", build metadata, missing or leading-zero parts.
func ParseVersion(s string) (v Version, ok bool) {
	if len(s) > maxVersionLen {
		return Version{}, false
	}
	s = strings.TrimPrefix(s, "v")
	core, pre, hasPre := strings.Cut(s, "-")
	if hasPre && !validPre(pre) {
		return Version{}, false
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, false
	}
	var n [3]uint64
	for i, p := range parts {
		if !validNumber(p) {
			return Version{}, false
		}
		var err error
		if n[i], err = strconv.ParseUint(p, 10, 64); err != nil {
			return Version{}, false
		}
	}
	return Version{Major: n[0], Minor: n[1], Patch: n[2], Pre: pre, known: true}, true
}

func validNumber(p string) bool {
	if p == "" || (len(p) > 1 && p[0] == '0') {
		return false
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func validPre(pre string) bool {
	for id := range strings.SplitSeq(pre, ".") {
		if id == "" {
			return false
		}
		for _, c := range id {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Known reports whether v was parsed.
func (v Version) Known() bool { return v.known }

// String returns v as vMAJOR.MINOR.PATCH[-pre], or "unknown".
func (v Version) String() string {
	if !v.known {
		return "unknown"
	}
	s := "v" + strconv.FormatUint(v.Major, 10) + "." + strconv.FormatUint(v.Minor, 10) + "." + strconv.FormatUint(v.Patch, 10)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Compare returns -1, 0 or +1 as v is older than, equal to or newer than w,
// by semantic version precedence. Both must be known.
func (v Version) Compare(w Version) int {
	for _, d := range [3][2]uint64{{v.Major, w.Major}, {v.Minor, w.Minor}, {v.Patch, w.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	return comparePre(v.Pre, w.Pre)
}

// comparePre orders pre-releases: none ranks above any; identifiers compare
// numerically when both are numbers, numbers rank below words, and a longer
// list ranks above its prefix.
func comparePre(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, y := as[i], bs[i]
		if x == y {
			continue
		}
		xn, xerr := strconv.ParseUint(x, 10, 64)
		yn, yerr := strconv.ParseUint(y, 10, 64)
		switch {
		case xerr == nil && yerr == nil:
			if xn < yn {
				return -1
			}
			return 1
		case xerr == nil:
			return -1
		case yerr == nil:
			return 1
		case x < y:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

// Compliant reports whether reported meets minimum. Without a minimum every
// version complies; with one, an unknown version never does (HR-470).
func Compliant(reported, minimum Version) bool {
	if !minimum.known {
		return true
	}
	return reported.known && reported.Compare(minimum) >= 0
}
