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
