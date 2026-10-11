// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package log builds PantherClaw's structured operational logger (SB-4).
//
// Records are JSON objects on one line with the keys ts (UTC, RFC 3339 with
// nanoseconds), level, event (a dotted name such as "authz.decision"), plus
// service, version and any attributes. Defenses against secret leakage and
// log injection (T-041):
//
//   - Secret[T] and Sensitive[T] render as [REDACTED];
//   - attributes whose key looks sensitive (authorization, cookie, token,
//     secret, password, api_key, proof, private_key, …) are redacted by key;
//   - structured values that contain a sensitive key are redacted entirely;
//   - GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_) are redacted
//     wherever they appear in a value, whatever their length (G0 M8: stateless
//     installation tokens are about 520 characters);
//   - string values are capped at 2 KiB, events at 128 bytes;
//   - the JSON encoder escapes control characters and invalid UTF-8, so an
//     attribute can never start a new log line.
//
// Raw request/response payloads are never logged.
package log

import (
	"context"
	"encoding/json/v2"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Standard attribute keys (SB-4 mandatory fields).
const (
	KeyTime       = "ts"
	KeyLevel      = "level"
	KeyEvent      = "event"
	KeyService    = "service"
	KeyVersion    = "version"
	KeyOrgID      = "org_id"
	KeyActor      = "actor"
	KeyRequestID  = "request_id"
	KeyTraceID    = "trace_id"
	KeyTxnID      = "txn_id"
	KeyOutcome    = "outcome"
	KeyReasonCode = "reason_code"
	KeyError      = "error"
)

const (
	// MaxValueBytes caps every string attribute value (SB-4).
	MaxValueBytes = 2048
	// MaxEventBytes caps the event name.
	MaxEventBytes = 128
	truncMark     = "…[truncated]"
)

// sensitiveKeyParts are matched against normalized attribute keys
// (lowercase, '-' replaced by '_'). A key containing any part is redacted.
var sensitiveKeyParts = []string{
	"authorization", "cookie", "password", "passwd", "passphrase", "token",
	"secret", "api_key", "apikey", "proof", "private_key", "privatekey",
	"credential", "session_key", "dsn",
}

// githubToken matches a GitHub token in free text, of any length (HR-203).
var githubToken = regexp.MustCompile(`(gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}`)

// scrub redacts GitHub tokens in a value.
func scrub(s string) string {
	if !strings.Contains(s, "gh") && !strings.Contains(s, "github_pat_") {
		return s
	}
	return githubToken.ReplaceAllString(s, Redacted)
}

// Options configures New.
type Options struct {
	Service string
	Version string
	Level   slog.Leveler
	// ContextAttrs extract request-scoped attributes (for example trace ids)
	// from the context of each record, in addition to those added by With.
	ContextAttrs []func(context.Context) []slog.Attr
}

// New returns a JSON logger writing to w.
func New(w io.Writer, opts Options) *slog.Logger {
	level := opts.Level
	if level == nil {
		level = slog.LevelInfo
	}
	base := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: replaceAttr,
	})
	var h slog.Handler = &contextHandler{inner: base, extract: opts.ContextAttrs}
	attrs := []slog.Attr{}
	if opts.Service != "" {
		attrs = append(attrs, slog.String(KeyService, opts.Service))
	}
	if opts.Version != "" {
		attrs = append(attrs, slog.String(KeyVersion, opts.Version))
	}
	return slog.New(h.WithAttrs(attrs))
}

// Discard returns a logger that drops everything (for tests and tools).
func Discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// ParseLevel parses debug, info, warn or error.
func ParseLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, true
	case "info", "":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}

// Actor returns the mandatory actor{type,id} group.
func Actor(typ, id string) slog.Attr {
	return slog.Group(KeyActor, slog.String("type", typ), slog.String("id", id))
}

// Err returns an error attribute (its text is capped like any string).
func Err(err error) slog.Attr {
	if err == nil {
		return slog.String(KeyError, "")
	}
	return slog.String(KeyError, err.Error())
}

func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 {
		switch a.Key {
		case slog.TimeKey:
			if t, ok := a.Value.Any().(time.Time); ok {
				return slog.String(KeyTime, t.UTC().Format(time.RFC3339Nano))
			}
			return slog.Attr{Key: KeyTime, Value: a.Value}
		case slog.MessageKey:
			return slog.String(KeyEvent, capString(a.Value.String(), MaxEventBytes))
		case slog.LevelKey:
			return slog.Attr{Key: KeyLevel, Value: a.Value}
		}
	}
	if sensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	for _, g := range groups {
		if sensitiveKey(g) {
			return slog.String(a.Key, Redacted)
		}
	}
	switch a.Value.Kind() {
	case slog.KindString:
		return slog.String(a.Key, capString(scrub(a.Value.String()), MaxValueBytes))
	case slog.KindAny:
		return slog.String(a.Key, renderAny(a.Value.Any()))
	case slog.KindBool, slog.KindDuration, slog.KindFloat64, slog.KindInt64, slog.KindTime,
		slog.KindUint64, slog.KindGroup, slog.KindLogValuer:
		return a // fixed-size scalars, or values slog resolves/expands before calling us
	default:
		return a
	}
}

// renderAny converts structured values to capped strings. Values that
// contain a sensitive key anywhere are redacted as a whole.
func renderAny(v any) string {
	switch x := v.(type) {
	case error:
		return capString(scrub(x.Error()), MaxValueBytes)
	case []byte:
		return capString(scrub(string(x)), MaxValueBytes)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[unloggable value]"
	}
	if containsSensitiveKey(b) {
		return Redacted
	}
	return capString(scrub(string(b)), MaxValueBytes)
}

func sensitiveKey(key string) bool {
	k := strings.ReplaceAll(strings.ToLower(key), "-", "_")
	for _, part := range sensitiveKeyParts {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}

func containsSensitiveKey(jsonText []byte) bool {
	s := strings.ReplaceAll(strings.ToLower(string(jsonText)), "-", "_")
	for _, part := range sensitiveKeyParts {
		// Look for the part inside an object key: `"…part…":`.
		for i := 0; ; {
			j := strings.Index(s[i:], part)
			if j < 0 {
				break
			}
			end := i + j + len(part)
			if k := strings.IndexByte(s[end:], '"'); k >= 0 && k < 64 &&
				end+k+1 < len(s) && s[end+k+1] == ':' {
				return true
			}
			i = end
		}
	}
	return false
}

// capString truncates s to at most limit bytes on a rune boundary.
func capString(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit - len(truncMark)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncMark
}
