// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package actionir_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// TestHR187_PathsHaveOneSpelling: every spelling of a directory normalizes
// to one form, and the forms Windows treats specially are refused.
func TestHR187_PathsHaveOneSpelling(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Users\dev\repo`:              `C:\Users\dev\repo`,
		`c:/Users/dev/repo/`:             `C:\Users\dev\repo`,
		`c:\Users\.\dev\..\dev\\repo`:    `C:\Users\dev\repo`,
		`C:\..\..\Windows`:               `C:\Windows`,
		`C:/`:                            `C:\`,
		`C:\a b\c`:                       `C:\a b\c`,
		`\\fileserver\share\team\..\x`:   `\\fileserver\share\x`,
		`//fileserver/share`:             `\\fileserver\share`,
		`\\fileserver\share\..\..\data`:  `\\fileserver\share\data`,
		`/home/dev/./repo/../repo//src/`: `/home/dev/repo/src`,
		`/../..`:                         `/`,
		`/`:                              `/`,
		`C:\Users\Jürgen\répertoire`:     `C:\Users\Jürgen\répertoire`,
	} {
		got, err := actionir.NormalizePath(in)
		if err != nil || got != want {
			t.Errorf("NormalizePath(%q) = %q, %v; want %q", in, got, err, want)
		}
		if again, err := actionir.NormalizePath(got); err != nil || again != got {
			t.Errorf("NormalizePath is not idempotent on %q: %q, %v", got, again, err)
		}
	}
	for _, in := range []string{
		"", "repo", `.\repo`, `C:repo`, `C:`,
		`\\?\C:\Windows`, `\\.\PhysicalDrive0`, `//?/C:/x`, `\\server`, `\\server\`, `\\server\..\x`,
		`C:\repo\file.txt:hidden`, `C:\repo\x::$DATA`,
		`C:\repo.\x`, `C:\repo \x`, `C:\repo\...`, `\\server\share.\x`,
		"/home/dev\x00/x", "C:\\a\nb", "/a\u202eb", "/a\u200bb",
		"/" + strings.Repeat("a", actionir.MaxPath),
		"/a\xffb",
	} {
		if got, err := actionir.NormalizePath(in); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("NormalizePath(%q) = %q, %v; want ambiguous", in, got, err)
		}
	}
}

// TestHR187_UNCPathsToThisMachineAreRefused: a UNC path that names this
// machine's own disks is another spelling of a drive path, so it is
// refused: loopback servers in every spelling, and administrative disk
// shares on any server, since the gateway cannot tell which names are the
// developer's own machine. Other servers and shares keep their form.
func TestHR187_UNCPathsToThisMachineAreRefused(t *testing.T) {
	for _, in := range []string{
		`\\localhost\C$\secret`, `\\LOCALHOST\c$\secret`, `//localhost/c$/secret`, `\/localhost\C$\secret`, `\\localhost\Users\dev`,
		`\\dev.localhost\share`, `\\localhost.\C$\secret`,
		`\\127.0.0.1\C$\secret`, `\\127.0.0.1\Users\dev`, `\\127.1.2.3\share`, `\\127.1\share`, `\\2130706433\share`,
		`\\0x7f000001\share`, `\\0X7F.1\share`, `\\0177.0.0.1\share`, `\\127.000.000.001\share`, `\\0.0.0.0\share`, `\\0\share`,
		`\\0--1.ipv6-literal.net\C$\secret`, `\\0-0-0-0-0-0-0-1.IPV6-LITERAL.NET\share`, `\\--1s1.ipv6-literal.net\share`,
		`\\--ffff-7f00-1.ipv6-literal.net\share`, `\\--.ipv6-literal.net\share`, `\\zz--1.ipv6-literal.net\share`,
		`\\[::1]\C$`, `\\::1\share`,
		`\\fileserver\C$\data`, `\\fileserver\d$`, `\\buildhost.example.test\ADMIN$\System32`, `\\10.0.0.5\admin$`,
		`\\10.1\share`, `\\167772161\share`,
		`\\?\UNC\localhost\C$\secret`, `\\.\UNC\localhost\C$\secret`, `\\.\C:\secret`, `\\?\C:\secret`,
	} {
		if got, err := actionir.NormalizePath(in); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("NormalizePath(%q) = %q, %v; want ambiguous", in, got, err)
		}
	}
	for in, want := range map[string]string{
		`\\fileserver\share\x`:                 `\\fileserver\share\x`,
		`\\fileserver\home$\dev`:               `\\fileserver\home$\dev`,
		`\\10.0.0.5\share`:                     `\\10.0.0.5\share`,
		`\\localhostess\share`:                 `\\localhostess\share`,
		`\\fe80--1s4.ipv6-literal.net\share`:   `\\fe80--1s4.ipv6-literal.net\share`,
		`\\files.example.test\C$share\x`:       `\\files.example.test\C$share\x`,
		`\\files.example.test\dept\C$\reports`: `\\files.example.test\dept\C$\reports`,
	} {
		if got, err := actionir.NormalizePath(in); err != nil || got != want {
			t.Errorf("NormalizePath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// fixedPoint fails t unless NormalizePath refuses p as ambiguous, or
// accepts it and accepts its normal form unchanged.
func fixedPoint(t *testing.T, p string) {
	t.Helper()
	n, err := actionir.NormalizePath(p)
	if err != nil {
		if !errors.Is(err, actionir.ErrAmbiguous) {
			t.Fatalf("NormalizePath(%q): %v, want ambiguous", p, err)
		}
		return
	}
	if again, err := actionir.NormalizePath(n); err != nil || again != n {
		t.Fatalf("NormalizePath(%q) = %q, which normalizes to %q, %v", p, n, again, err)
	}
}

// TestHR187_NormalizingIsAFixedPoint: the normal form of every accepted
// path is accepted and normalizes to itself, so a directory has exactly one
// spelling. It tries every path of up to six characters over the
// characters the parser treats specially, and the spellings where a
// collapsed "." or ".." or an extra separator used to leave a prefix that
// reads as another kind of path. Those are refused, as the prefix they
// leave is.
func TestHR187_NormalizingIsAFixedPoint(t *testing.T) {
	for _, p := range []string{
		`/./\x`, `/./\srv\share`, `/a/../\x`, `/.//\srv\share\x`, `/\x`,
		`\\\?\C:\x`, `\\/?x\share`, `///.x/share`, `\\\.foo\share`, `\\?x\share`, `\\.foo\share`,
	} {
		if got, err := actionir.NormalizePath(p); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("NormalizePath(%q) = %q, %v; want ambiguous", p, got, err)
		}
	}
	for in, want := range map[string]string{
		`/a/\x`: `/a/\x`, `/a\..\b`: `/a\..\b`, `\\\server\share`: `\\server\share`, `//srv/sh/../.x`: `\\srv\sh\.x`,
	} {
		if got, err := actionir.NormalizePath(in); err != nil || got != want {
			t.Errorf("NormalizePath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	const alphabet = `/\.:?aC `
	var walk func(prefix []byte)
	walk = func(prefix []byte) {
		if len(prefix) > 0 {
			fixedPoint(t, string(prefix))
		}
		if len(prefix) == 6 {
			return
		}
		for i := range len(alphabet) {
			walk(append(prefix, alphabet[i]))
		}
	}
	walk(make([]byte, 0, 6))
}

// FuzzNormalizePath: whatever NormalizePath accepts, it accepts again
// unchanged, and whatever it refuses, it refuses as ambiguous (HR-187).
func FuzzNormalizePath(f *testing.F) {
	for _, s := range []string{
		`C:\Users\dev\repo`, `c:/a/./b/../c/`, `\\server\share\x`, `//server/share/..`, `/home/dev/./repo`,
		`/./\x`, `/./\srv\share`, `\\\?\x\y`, `\\/.x/y`, `/a\..\b`, `C:\a.\b`, "/a\u202eb",
	} {
		f.Add(s)
	}
	f.Fuzz(fixedPoint)
}
