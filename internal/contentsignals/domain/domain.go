// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the words of content signals (G0 M27 D503-D505, D507,
// D512; HR-647..652). A finding is a kind and a location, never a value. A
// flag only restricts, and no flags means "no known flags", never clean or
// safe (F789, F801).
package domain

import (
	"cmp"
	"regexp"
	"slices"
	"strings"

	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
)

// Mode is what an org does with content signals.
type Mode string

// Modes. No settings row is ModeOff.
const (
	ModeOff      Mode = "OFF"
	ModeWatching Mode = "WATCHING"
	ModeActive   Mode = "ACTIVE"
)

// Valid reports whether m is a mode.
func (m Mode) Valid() bool { return m == ModeOff || m == ModeWatching || m == ModeActive }

// Scans reports whether the gateway scans in this mode.
func (m Mode) Scans() bool { return m == ModeWatching || m == ModeActive }

// Finding kinds.
const (
	KindInjectionPhrase = "injection_phrase"
	KindSecretFormat    = "secret_format"
	KindHighEntropy     = "high_entropy"
	KindPIIEmail        = "pii_email"
	KindPIICard         = "pii_card"
	KindPIINationalID   = "pii_national_id"
	// KindClassifierFlag is whatever the out-of-process classifier flagged.
	KindClassifierFlag = "classifier_flag"
	// KindScanIncomplete is a scan that could not finish: its location is
	// one of the Incomplete reasons (D512, HR-650).
	KindScanIncomplete = "scan_incomplete"
)

// Why a scan could not finish, the location of a KindScanIncomplete.
const (
	IncompleteOverBound  = "over_bound"
	IncompleteClassifier = "classifier_unavailable"
	IncompleteBuiltin    = "builtin_failed"
)

const (
	// MaxBody bounds one scanned body (D507, HR-649). A longer one is a
	// scan_incomplete (D512).
	MaxBody = 64 << 10
	// MaxFindings caps the findings of one body or decision.
	MaxFindings = 16
	// MaxLocation bounds a location.
	MaxLocation = 128
)

// Finding is one flag: what kind and where, never the value (HR-649).
type Finding struct {
	Kind     string
	Location string
}

var (
	kinds = []string{
		KindInjectionPhrase, KindSecretFormat, KindHighEntropy, KindPIIEmail, KindPIICard,
		KindPIINationalID, KindClassifierFlag, KindScanIncomplete,
	}
	locationRe = regexp.MustCompile(`^[!-~]{1,128}$`)
)

// ValidKind reports whether k is a known finding kind.
func ValidKind(k string) bool { return slices.Contains(kinds, k) }

// Valid reports whether f may be accepted from a gateway or a classifier: a
// known kind, and a location of printable ASCII within the bound.
func (f Finding) Valid() bool { return ValidKind(f.Kind) && locationRe.MatchString(f.Location) }

// Reason is what f counts as in what WATCHING would have held (D512): its
// kind, or why the scan could not finish, so an org sees large results apart
// from a stopped classifier.
func (f Finding) Reason() string {
	if f.Kind == KindScanIncomplete {
		switch f.Location {
		case IncompleteOverBound, IncompleteClassifier, IncompleteBuiltin:
			return f.Location
		}
	}
	return f.Kind
}

// Pick sorts findings, drops repeats and keeps at most MaxFindings: the first
// location of every kind, then the rest by location, so one kind never hides
// another behind sixteen of its own.
func Pick(in []Finding) []Finding {
	all := slices.Clone(in)
	slices.SortFunc(all, compare)
	all = slices.Compact(all)
	if len(all) <= MaxFindings {
		return all
	}
	var first, rest []Finding
	for i, f := range all {
		if i == 0 || all[i-1].Kind != f.Kind {
			first = append(first, f)
		} else {
			rest = append(rest, f)
		}
	}
	slices.SortStableFunc(rest, func(a, b Finding) int { return strings.Compare(a.Location, b.Location) })
	out := append(first, rest...)[:MaxFindings]
	slices.SortFunc(out, compare)
	return out
}

func compare(a, b Finding) int {
	return cmp.Or(strings.Compare(a.Kind, b.Kind), strings.Compare(a.Location, b.Location))
}

// Wording a person reads (D504, HR-651). No string here or anywhere else in
// content signals says clean or safe.
const (
	// NoKnownFlags is a scanned body with no flags.
	NoKnownFlags = "no known flags"
	// NotInspected is a face the gateway cannot see into: the hook, the SDK
	// and delegated outcomes.
	NotInspected = "not inspected"
)

// ParseFlag reads the kinds and count of a stored pc.content.flag value; an
// empty or unreadable one has none.
func ParseFlag(raw []byte) ([]string, int64) {
	if len(raw) == 0 {
		return nil, 0
	}
	v, err := fdomain.DecodeValue(fdomain.TypeObject, raw)
	if err != nil {
		return nil, 0
	}
	list, _ := v.Object["kinds"].(string)
	n, _ := v.Object["count"].(int64)
	if list == "" {
		return nil, n
	}
	return strings.Split(list, ","), n
}

// NotInspectedFaces are the faces the gateway cannot see into (D504, D532).
var NotInspectedFaces = []string{"hook", "sdk", "local", "delegated"}

// NotScanned is what the settings say of them, plainly (D532).
const NotScanned = "Hook, SDK and local connections are not scanned, and delegated outcomes are not inspected: what comes through them is not inspected, never \"no known flags\"."
