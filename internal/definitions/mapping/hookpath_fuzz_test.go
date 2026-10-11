// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"unicode"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// hookCwd maps a shell hook call in cwd and returns its normalized cwd.
func hookCwd(t *testing.T, m *Mapper, cwd string) (string, actionir.Parsed, error) {
	t.Helper()
	in, err := json.Marshal(map[string]string{"shell": "powershell", "command": "Get-ChildItem", "cwd": cwd, "call": "toolu_01"})
	if err != nil {
		return "", actionir.Parsed{}, err
	}
	p, err := m.Hook(context.Background(), tc, "shell", in)
	if err != nil {
		if !errors.Is(err, actionir.ErrAmbiguous) {
			t.Fatalf("cwd %q: an error outside ErrAmbiguous: %v", cwd, err)
		}
		return "", p, err
	}
	var params struct {
		Cwd string `json:"cwd"`
	}
	if err := json.Unmarshal(p.Action.Params, &params, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	return params.Cwd, p, nil
}

// isWindowsPath reports whether a normalized path is a drive or UNC path.
func isWindowsPath(p string) bool {
	return isDrivePath(p) || strings.HasPrefix(p, `\\`)
}

func isDrivePath(p string) bool {
	return len(p) >= 2 && p[1] == ':' && ('a' <= p[0] && p[0] <= 'z' || 'A' <= p[0] && p[0] <= 'Z')
}

// FuzzHookPath (G0 M6, HR-187, T-069): no working directory panics the
// hook mapping. A directory it accepts reaches ActionIR in its one
// spelling: a fixed point of the normalization, absolute, without device
// prefix, alternate data stream, dot segment, Windows segment ending in a
// dot or space, or control, format or bidi character; and the other
// spellings of that directory (the other separator, the drive letter's
// case, a trailing "." segment) are the same action.
func FuzzHookPath(f *testing.F) {
	m := shellMapper(f)
	for _, s := range []string{
		`C:\Users\dev\repo`, `c:/Users/dev/./repo/`, `\\fileserver\share\team\..\x`, `//fileserver/share`, `/home/dev/./repo/../repo//src/`,
		`\\?\C:\Windows`, `\\.\PhysicalDrive0`, `C:\repo\x::$DATA`, `C:\repo.\x`, `C:\repo \x`, `C:\PROGRA~1\x`, `C:`, `C:repo`,
		`/\server\share`, `/a/\b`, "/a" + string(rune(0x202e)) + "b", "C:\\a\x00b", `\/srv/share\..\..\x`, `/`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cwd string) {
		got, first, err := hookCwd(t, m, cwd)
		if err != nil {
			return
		}
		if again, err := actionir.NormalizePath(got); err != nil || again != got {
			t.Fatalf("cwd %q reached ActionIR as %q, which normalizes to %q (%v)", cwd, got, again, err)
		}
		bad := strings.ContainsFunc(got, func(r rune) bool {
			return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r)
		})
		switch {
		case strings.HasPrefix(got, `\\?`) || strings.HasPrefix(got, `\\.`):
			bad = true
		case isWindowsPath(got):
			rest := strings.TrimPrefix(got, `\\`)
			if !strings.HasPrefix(got, `\\`) {
				rest = got[2:]
			}
			for _, seg := range strings.Split(rest, `\`) {
				bad = bad || seg == "." || seg == ".." || strings.Contains(seg, ":") || strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ")
			}
		case strings.HasPrefix(got, "/"):
			for _, seg := range strings.Split(got[1:], "/") {
				bad = bad || seg == "." || seg == ".." || (seg == "" && got != "/")
			}
		default:
			bad = true
		}
		if bad {
			t.Fatalf("cwd %q reached ActionIR as %q", cwd, got)
		}
		variants := []string{cwd + "/."}
		if strings.HasSuffix(cwd, "/") || isWindowsPath(got) && strings.HasSuffix(cwd, `\`) {
			variants[0] = cwd + "." // a backslash separates only in Windows paths
		}
		if isWindowsPath(got) {
			variants = append(variants, strings.ReplaceAll(cwd, `\`, "/"), strings.ReplaceAll(cwd, "/", `\`))
			if isDrivePath(cwd) {
				variants = append(variants, strings.ToLower(cwd[:1])+cwd[1:], strings.ToUpper(cwd[:1])+cwd[1:])
			}
		}
		for _, v := range variants {
			if other, p, err := hookCwd(t, m, v); err != nil || other != got || p.Hash != first.Hash {
				t.Fatalf("the spellings %q and %q of one directory became %q and %q (%v)", cwd, v, got, other, err)
			}
		}
	})
}
