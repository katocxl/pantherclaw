// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds what a sealed credential is bound to (G0 M6 design
// decision 8, HR-060, HR-182). pclaw seals a credential to the broker key
// of a connection's gateway with HPKE (X-Wing); the info parameter binds
// the org, the connection, the version, the hosts it may be sent to, the
// broker key and the header and scheme it is placed with. The gateway
// rebuilds the same info from its own view (the org from its certificate,
// the rest from its configuration) before opening, so a blob copied to
// another connection, version, host or gateway does not open.
package domain

import (
	"encoding/binary"
	"errors"
	"slices"
	"strconv"
	"strings"
)

// Format limits of a sealed credential: version(1) ‖ len(enc)(2) ‖ enc ‖ ct.
const (
	sealedV1 = 0x01
	// EncLen is the X-Wing encapsulation size.
	EncLen = 1120
	// tagLen is the AES-256-GCM tag.
	tagLen = 16
	// MinSealed and MaxSealed bound a blob: at least one plaintext byte, at
	// most 64 KiB of credential.
	MinSealed = 3 + EncLen + tagLen + 1
	MaxSealed = 70_000
)

// AAD is the additional data of every sealed credential.
var AAD = []byte("pantherclaw sealed credential v1")

// ErrFormat reports a blob that is not a sealed credential.
var ErrFormat = errors.New("credentials: not a sealed credential")

// Binding is what a sealed credential is bound to.
type Binding struct {
	Org, Connection string
	Version         int32
	AllowedHosts    []string
	BrokerKey       string
	Header, Scheme  string
	// Kind is KindStatic (or empty) or KindGitHubApp; only a GitHub App
	// credential adds it to the info, so every credential sealed before
	// kinds existed still opens.
	Kind string
}

// Info is the canonical HPKE info of a binding: one line per field, in a
// fixed order, with the hosts sorted. No field can contain a line break
// (ids, hosts, header and scheme are all checked token strings).
func (b Binding) Info() []byte {
	hosts := slices.Clone(b.AllowedHosts)
	slices.Sort(hosts)
	var s strings.Builder
	s.WriteString("pantherclaw credential v1\n")
	s.WriteString("org=" + b.Org + "\n")
	s.WriteString("connection=" + b.Connection + "\n")
	s.WriteString("version=" + strconv.Itoa(int(b.Version)) + "\n")
	s.WriteString("hosts=" + strings.Join(hosts, ",") + "\n")
	s.WriteString("broker_key=" + b.BrokerKey + "\n")
	s.WriteString("header=" + b.Header + "\n")
	s.WriteString("scheme=" + b.Scheme + "\n")
	if b.Kind != "" && b.Kind != KindStatic {
		s.WriteString("kind=" + b.Kind + "\n")
	}
	return []byte(s.String())
}

// CheckFormat checks that a blob has the shape of a sealed credential. It
// cannot check that it opens: only the gateway holds the broker key.
func CheckFormat(sealed []byte) error {
	if len(sealed) < MinSealed || len(sealed) > MaxSealed || sealed[0] != sealedV1 ||
		binary.BigEndian.Uint16(sealed[1:3]) != EncLen {
		return ErrFormat
	}
	return nil
}
