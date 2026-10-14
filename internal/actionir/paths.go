// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package actionir

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxPath bounds a path value.
const MaxPath = 4 << 10

// NormalizePath returns the canonical form of an absolute file-system path
// (HR-187), so that one directory has one spelling in ActionIR and in
// policy. It works lexically and never touches a file system: the caller
// resolves short names and links first where it can.
//
//   - Windows drive paths ("c:/x", "C:\x") get an upper-case drive letter,
//     "\" separators, and "." and ".." collapsed; ".." never climbs above
//     the drive root.
//   - UNC paths ("\\server\share\x") keep their server and share, which
//     ".." never climbs above.
//   - POSIX paths ("/x") get "/" separators, and "." and ".." collapsed.
//
// Refused, as ambiguous: relative and drive-relative paths ("x", "C:x"),
// device paths ("\?\", "\.\", also after extra separators), alternate
// data streams (a ":" after the drive), Windows segments ending in a dot or
// a space, UNC paths that name this machine's own disks (loopback servers,
// administrative shares; see localShare), POSIX paths whose first segment,
// once "." and ".." are collapsed, starts with "\" ("/./\x", which would
// read as UNC), and control, format or bidi characters.
//
// The result is a fixed point: NormalizePath accepts it and returns it
// unchanged.
func NormalizePath(p string) (string, error) {
	if p == "" || len(p) > MaxPath || !utf8.ValidString(p) {
		return "", ambiguous("path must be 1..%d bytes of UTF-8", MaxPath)
	}
	for _, r := range p {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r) || r == utf8.RuneError {
			return "", ambiguous("path contains a control, format or bidi character (HR-102)")
		}
	}
	switch {
	case len(p) >= 2 && p[1] == ':' && isLetter(p[0]):
		if len(p) == 2 || (p[2] != '\\' && p[2] != '/') {
			return "", ambiguous("drive-relative path %q", p)
		}
		segs, err := windowsSegments(p[3:])
		if err != nil {
			return "", err
		}
		return strings.ToUpper(p[:1]) + `:\` + strings.Join(segs, `\`), nil
	case strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//") || strings.HasPrefix(p, `\/`) || strings.HasPrefix(p, `/\`):
		// A server starting with "?" or "." would make the result a device
		// path, however many separators lead to it.
		parts := strings.FieldsFunc(p[2:], isSep)
		if len(parts) > 0 && (strings.HasPrefix(parts[0], "?") || strings.HasPrefix(parts[0], ".")) {
			return "", ambiguous("device paths are not supported")
		}
		if len(parts) < 2 {
			return "", ambiguous("a UNC path names a server and a share")
		}
		for _, s := range parts[:2] {
			if err := windowsSegment(s); err != nil || s == "." || s == ".." {
				return "", ambiguous("UNC server or share %q", s)
			}
		}
		if err := localShare(parts[0], parts[1]); err != nil {
			return "", err
		}
		segs, err := windowsSegments(strings.Join(parts[2:], `\`))
		if err != nil {
			return "", err
		}
		out := `\\` + parts[0] + `\` + parts[1]
		if len(segs) > 0 {
			out += `\` + strings.Join(segs, `\`)
		}
		return out, nil
	case p[0] == '/':
		var segs []string
		for _, s := range strings.Split(p, "/") {
			switch s {
			case "", ".":
			case "..":
				if len(segs) > 0 {
					segs = segs[:len(segs)-1]
				}
			default:
				segs = append(segs, s)
			}
		}
		// "/" followed by a backslash reads as UNC, as in "/\x" above: a
		// first segment starting with one, left by a collapsed "." or "..",
		// has no single spelling.
		if len(segs) > 0 && strings.HasPrefix(segs[0], `\`) {
			return "", ambiguous("POSIX path %q starts like a UNC path", p)
		}
		return "/" + strings.Join(segs, "/"), nil
	default:
		return "", ambiguous("path %q is not absolute", p)
	}
}

func isLetter(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }

// localShare refuses the UNC paths that are other spellings of this
// machine's own directories ("\\localhost\C$\x" is "C:\x"): a loopback
// server (localhost, 127.0.0.0/8 and 0.0.0.0 in any numeric form, ::1 as
// an ipv6-literal.net name), and the administrative disk shares (C$,
// ADMIN$) on any server, because a server name the gateway cannot tell is
// the developer's own machine (its host name or address, or a DNS name
// that resolves to loopback) reaches them too. A numeric IPv4 server not in
// dotted decimal is refused as another spelling of an address.
func localShare(server, share string) error {
	if strings.EqualFold(share, "ADMIN$") || (len(share) == 2 && isLetter(share[0]) && share[1] == '$') {
		return ambiguous("UNC share %q is an administrative disk share", share)
	}
	host := strings.ToLower(server)
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return ambiguous("UNC server %q is this machine", server)
	}
	if n, ok := numericIPv4(host); ok {
		if n>>24 == 127 || n == 0 {
			return ambiguous("UNC server %q is this machine", server)
		}
		if host != fmt.Sprintf("%d.%d.%d.%d", n>>24, n>>16&0xff, n>>8&0xff, n&0xff) {
			return ambiguous("UNC server %q is an IPv4 address not in dotted decimal", server)
		}
	}
	if literal, ok := strings.CutSuffix(host, ".ipv6-literal.net"); ok {
		literal, _, _ = strings.Cut(literal, "s") // the zone
		ip, err := netip.ParseAddr(strings.ReplaceAll(literal, "-", ":"))
		if err != nil {
			return ambiguous("UNC server %q is not an IPv6 literal", server)
		}
		if ip = ip.Unmap(); ip.IsLoopback() || ip.IsUnspecified() {
			return ambiguous("UNC server %q is this machine", server)
		}
	}
	return nil
}

// numericIPv4 reads s as Windows and inet_aton read an IPv4 address: one to
// four parts, each decimal, octal (a leading 0) or hexadecimal (0x), the
// last filling the remaining bytes ("127.1", "0x7f000001", "2130706433").
func numericIPv4(s string) (uint64, bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return 0, false
	}
	var n uint64
	for i, p := range parts {
		base := 10
		switch {
		case strings.HasPrefix(p, "0x"):
			base, p = 16, p[2:]
			if p == "" {
				p = "0"
			}
		case len(p) > 1 && p[0] == '0':
			base, p = 8, p[1:]
		}
		if p == "" || p[0] == '+' || p[0] == '-' {
			return 0, false
		}
		v, err := strconv.ParseUint(p, base, 32)
		if err != nil {
			return 0, false
		}
		bits := 8
		if i == len(parts)-1 {
			bits = 8 * (4 - i)
		}
		if v >= 1<<bits {
			return 0, false
		}
		n = n<<bits | v
	}
	return n, true
}

func isSep(r rune) bool { return r == '\\' || r == '/' }

// windowsSegments collapses the segments below a Windows root.
func windowsSegments(rest string) ([]string, error) {
	var segs []string
	for _, s := range strings.FieldsFunc(rest, isSep) {
		switch s {
		case ".":
		case "..":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
		default:
			if err := windowsSegment(s); err != nil {
				return nil, err
			}
			segs = append(segs, s)
		}
	}
	return segs, nil
}

// windowsSegment refuses alternate data streams and the trailing dots and
// spaces that Windows strips, so that "a." and "a" cannot be two spellings
// of one directory.
func windowsSegment(s string) error {
	if s == "." || s == ".." {
		return nil
	}
	switch {
	case strings.ContainsRune(s, ':'):
		return ambiguous("path segment %q names an alternate data stream", s)
	case strings.HasSuffix(s, ".") || strings.HasSuffix(s, " "):
		return ambiguous("path segment %q ends with a dot or a space", s)
	}
	return nil
}
