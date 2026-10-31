// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the org's MCP server catalogue (G0 M24 D220, D221;
// F872, F873; HR-585): a server's statuses, the catalogue's modes and the
// exact match between a server and what is really running. Everything here
// is pure.
package domain

import (
	"regexp"
	"strings"
	"unicode/utf8"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// Status is where a server stands in the catalogue, as stored.
type Status string

// Statuses.
const (
	StatusProposed Status = "PROPOSED"
	StatusApproved Status = "APPROVED"
	StatusDenied   Status = "DENIED"
	StatusRevoked  Status = "REVOKED"
)

// Mode is what the catalogue does, as stored.
type Mode string

// Modes.
const (
	ModeOff     Mode = "OFF"
	ModeWatch   Mode = "WATCH"
	ModeEnforce Mode = "ENFORCE"
)

// DefaultMode is the mode of an org with no row (H3: Watching first).
const DefaultMode = ModeWatch

// Valid reports whether m is a mode.
func (m Mode) Valid() bool { return m == ModeOff || m == ModeWatch || m == ModeEnforce }

// Transports, as stored.
const (
	TransportHTTP      = "http"
	TransportStdio     = "stdio"
	TransportContainer = "container"
)

// Errors of a proposed server.
var (
	ErrName = pcerr.New(pcerr.InvalidArgument, "MCP_SERVER_NAME_INVALID",
		"a server name is 1 to 128 lower-case letters, digits, dots, dashes or underscores, starting with a letter or digit")
	ErrTitle     = pcerr.New(pcerr.InvalidArgument, "MCP_SERVER_TITLE_INVALID", "a title is 1 to 200 characters of plain text")
	ErrTransport = pcerr.New(pcerr.InvalidArgument, "MCP_SERVER_TRANSPORT_INVALID", "the transport is http, stdio or container")
	ErrNotes     = pcerr.New(pcerr.InvalidArgument, "MCP_SERVER_NOTES_INVALID", "notes are at most 2000 characters of plain text")
	ErrMatch     = pcerr.New(pcerr.InvalidArgument, "MCP_SERVER_MATCH_INVALID",
		"a server matches a URL host with an optional path prefix, a sha256 image digest or a package reference; "+
			"at least one is needed, and none takes a wildcard")
)

var (
	nameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	hostRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$`)
	ipv6RE   = regexp.MustCompile(`^\[[0-9a-f:.]{2,45}\](:[0-9]{1,5})?$`)
	imageRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	packRE   = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9@._/:+~-]{0,255}$`)
	prefixRE = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,511}$`)
)

// Proposal is a server as proposed.
type Proposal struct {
	Name, Title, Transport, Notes string
	Spec                          Spec
}

func plain(s string, maxRunes int) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) <= maxRunes &&
		!strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 && r != '\n' && r != '\t' })
}

// Check validates a proposal and returns it with its Spec normalized.
func (p Proposal) Check() (Proposal, error) {
	if !nameRE.MatchString(p.Name) {
		return Proposal{}, ErrName
	}
	if p.Title == "" || !plain(p.Title, 200) || strings.ContainsAny(p.Title, "\n\t") {
		return Proposal{}, ErrTitle
	}
	if !plain(p.Notes, 2000) {
		return Proposal{}, ErrNotes
	}
	if p.Transport != TransportHTTP && p.Transport != TransportStdio && p.Transport != TransportContainer {
		return Proposal{}, ErrTransport
	}
	s, err := p.Spec.Normalize()
	if err != nil {
		return Proposal{}, err
	}
	p.Spec = s
	return p, nil
}
