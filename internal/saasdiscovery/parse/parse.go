// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package parse holds the pure parsers of SaaS agent discovery (G0 M26 D407):
// bytes in, a report out, with no I/O. One parser reads a recording an admin
// exported and the gateway's collector reads the vendor's live pages through
// the same record shapes, so both keep the same closed attributes.
//
// Each parser decodes only the fields named in its record types. Everything
// else in a document, instructions and conversations included, is skipped by
// the decoder and never reaches a finding (H3, F789, HR-635). Vendor text is
// untrusted: it stays text, cleaned and bounded, and nothing reads it as an
// instruction (HR-638). What could not be read in full is reported as not
// scanned, never as "none found" (HR-637).
package parse

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
)

// MaxRecording is the largest recording a parser reads.
const MaxRecording = 32 << 20

// MaxRecords is the most records of one list a report keeps.
const MaxRecords = 5000

var (
	// ErrTooLarge refuses a recording over MaxRecording.
	ErrTooLarge = errors.New("saas: the recording is over 32 MiB")
	// ErrShape refuses a document that is not a recording of its source, so
	// a wrong file never reads as "none found".
	ErrShape = errors.New("saas: this is not a recording of that source")
	// ErrTenant refuses a recording that names no usable tenant.
	ErrTenant = errors.New("saas: the recording names no usable tenant")
	// ErrSource refuses a source discovery does not read.
	ErrSource = errors.New("saas: unknown source")
)

// Recording parses an exported recording of source.
func Recording(source string, raw []byte) (*domain.Report, error) {
	if len(raw) > MaxRecording {
		return nil, ErrTooLarge
	}
	switch source {
	case domain.SourceCopilotStudio:
		return copilotRecording(raw)
	case domain.SourceChatGPTEnterprise:
		return chatGPTRecording(raw)
	}
	return nil, ErrSource
}

// idRe is a vendor record id: a key part, never shown as anything but text.
var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

// put sets a cleaned attribute unless it came out empty.
func put(attrs map[string]string, k, v string) {
	if v = domain.Text(v); v != "" {
		attrs[k] = v
	}
}

// joined is a sorted, de-duplicated list of cleaned values as one attribute,
// with how many did not fit in the attribute's bound.
func joined(values []string) (string, int) {
	cleaned := make([]string, 0, len(values))
	for _, v := range values {
		// A list's separator cannot sit inside one of its names.
		if v = strings.ReplaceAll(domain.Text(v), ",", " "); v != "" {
			cleaned = append(cleaned, v)
		}
	}
	slices.Sort(cleaned)
	cleaned = slices.Compact(cleaned)
	var b strings.Builder
	for i, v := range cleaned {
		if b.Len()+len(v)+1 > domain.MaxValue {
			return b.String(), len(cleaned) - i
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(v)
	}
	return b.String(), 0
}

// count is n as an attribute.
func count(n int) string { return strconv.Itoa(n) }
