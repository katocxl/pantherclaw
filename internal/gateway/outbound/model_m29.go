// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package outbound

import (
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"
)

// limits bound one scan.
type limits struct {
	// parts caps the strings scanned; decoded caps one base64 value's
	// decoded size and decodedTotal all of them.
	parts, decoded, decodedTotal int
	// countText: decodedTotal counts the strings themselves too (the model
	// path, G0 M29 D817).
	countText bool
}

// actionLimits are an action's: past them the scan reports scan_incomplete.
var actionLimits = limits{parts: MaxParts, decoded: MaxDecoded, decodedTotal: MaxDecodedTotal}

// Model-path limits (G0 M29 D817, HR-694): every string of a model request
// is scanned, up to MaxModelParts strings and MaxModelDecoded bytes of
// strings and base64 content together. Past them the request is not
// scannable and is refused, never passed with a partial scan.
const (
	MaxModelParts   = 1 << 20
	MaxModelDecoded = 32 << 20
	// maxLocation is the longest finding location the Authority accepts.
	maxLocation = 256
)

// ErrNotScannable: a model request is past the model-path limits
// (payload_not_scannable).
var ErrNotScannable = errors.New("outbound: the model request is past the scan limits")

var modelLimits = limits{parts: MaxModelParts, decoded: MaxModelDecoded, decodedTotal: MaxModelDecoded, countText: true}

// ScanModel checks a model request (G0 M29 D817): every string of its
// strictly parsed JSON body, member names included, at body:<pointer>, and
// the model id at target. A held secret refuses it; a known format is a
// finding. It returns ErrNotScannable when the body is past the model-path
// limits, so the caller refuses rather than decide on part of it.
func ScanModel(body []byte, model string, held [][]byte) (Result, error) {
	c := &collector{lim: modelLimits}
	valid := c.json("body:", body)
	if c.incompleteAt != "" || !valid {
		return Result{}, ErrNotScannable
	}
	c.parts = append(c.parts, part{location: "body", text: string(body), heldOnly: true})
	if !c.add("target", model) {
		return Result{}, ErrNotScannable
	}
	res := scanParts(c, held)
	for i := range res.Findings {
		res.Findings[i].Location = clip(redact(res.Findings[i].Location))
	}
	return res, nil
}

// Format names the first known credential format found anywhere in s, or ""
// (unanchored; pclaw's --env check, G0 M29 D823, D1214).
func Format(s string) string {
	for _, f := range formats {
		if f.re.MatchString(s) {
			return f.kind
		}
	}
	return ""
}

// redact replaces each pointer segment of a finding location that holds a
// credential format with <redacted>: a member name may be the credential
// itself, and a location reaches the decision, the approval and the receipt
// (G0 M29 D1214). A base64 member name, a segment ending "(base64)", is
// redacted when what it decodes to holds one (D1214a).
func redact(loc string) string {
	segs := strings.Split(loc, "/")
	for i, s := range segs {
		if Format(s) != "" || Format(decodedSegment(s)) != "" {
			segs[i] = "<redacted>"
		}
	}
	return strings.Join(segs, "/")
}

// decodedSegment is what a "(base64)" pointer segment decodes to, or "".
func decodedSegment(s string) string {
	s, ok := strings.CutSuffix(s, "(base64)")
	if !ok {
		return ""
	}
	s = strings.NewReplacer("~1", "/", "~0", "~").Replace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b)
		}
	}
	return ""
}

// clip cuts a location to maxLocation bytes on a rune boundary.
func clip(s string) string {
	if len(s) <= maxLocation {
		return s
	}
	s = s[:maxLocation]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
