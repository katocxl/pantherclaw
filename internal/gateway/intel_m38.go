// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"strings"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// Bounds of a reported serverInfo, as the server accepts it.
const (
	maxServerName    = 256
	maxServerVersion = 128
)

// serverInfo is the inventory report's serverInfo (G0 M38 D1104): the
// upstream server's UNTRUSTED word, reported only when it is printable
// UTF-8 within the bounds, so the server never has to cut it (HR-822).
func serverInfo(s *upstream.ServerInfo) *pb.UpstreamServerInfo {
	if s == nil || !printable(s.Name, maxServerName) || !printable(s.Version, maxServerVersion) || s.Name == "" {
		return nil
	}
	return &pb.UpstreamServerInfo{Name: s.Name, Version: s.Version}
}

func printable(v string, n int) bool {
	return len(v) <= n && utf8.ValidString(v) && !strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f })
}
