// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Dedupe windows (D23, HR-277).
const (
	// BaseKeyWindow is how long a trigger's own key (schedule occurrence,
	// feed entry, webhook-id, manual idempotency key) is held: the longest
	// declared window, so no source key outlives a declared one.
	BaseKeyWindow = 30 * 24 * time.Hour
	// MaxDedupeWindow bounds a declared dedupe window.
	MaxDedupeWindow = 30 * 24 * time.Hour
)

// The base keys: one per trigger source (D16–D21, D59). Each names the
// one thing that may start at most one execution per automation.

// ScheduleKey is a schedule occurrence's key.
func ScheduleKey(automation ids.UUID, fireAt time.Time) string {
	return "schedule:" + automation.String() + ":" + fireAt.UTC().Format(time.RFC3339)
}

// EventKey is a platform event's key: its ledger entry id.
func EventKey(entry ids.UUID) string { return "event:" + entry.String() }

// InboundKey is a signed inbound event's key: its source and webhook-id.
func InboundKey(source ids.UUID, webhookID string) string {
	return "inbound:" + source.String() + ":" + digest(webhookID)
}

// ManualKey is a manual start's key: the caller's idempotency key.
func ManualKey(idempotency string) string { return "manual:" + digest(idempotency) }

// RetryKey is a retry's key (D59).
func RetryKey(execution ids.UUID, idempotency string) string {
	return "retry:" + execution.String() + ":" + digest(idempotency)
}

// ThresholdKey is a threshold window's key.
func ThresholdKey(automation ids.UUID, group string, bucket time.Time) string {
	return "threshold:" + automation.String() + ":" + digest(group) + ":" + bucket.UTC().Format(time.RFC3339)
}

// ConditionKey is a condition episode's key.
func ConditionKey(automation ids.UUID, subject string, since time.Time) string {
	return "condition:" + automation.String() + ":" + digest(subject) + ":" + since.UTC().Format(time.RFC3339Nano)
}

var paramRef = regexp.MustCompile(`\{\{\s*params\.([a-z][a-z0-9_]{0,62})\s*\}\}`)

// DedupeKey is the declared parameter key of a trigger (D23): the
// definition's `when.dedupe.key` template rendered over the trigger's
// typed parameters, or "" when the definition declares none. Two triggers
// of one automation with the same key start one execution within the
// declared window. It is pure, so assurance's DUPLICATE scenarios compute
// exactly what the trigger path enforces.
func DedupeKey(def *autodomain.Definition, t autodomain.TriggerRef) string {
	if def == nil || def.When.Dedupe == nil || strings.TrimSpace(def.When.Dedupe.Key) == "" {
		return ""
	}
	tmpl := def.When.Dedupe.Key
	var b strings.Builder
	last := 0
	for _, m := range paramRef.FindAllStringSubmatchIndex(tmpl, -1) {
		b.WriteString(tmpl[last:m[0]])
		name := tmpl[m[2]:m[3]]
		// Each value is length-prefixed so no two parameter sets render alike.
		if v, ok := t.Params[name]; ok {
			txt := v.Text()
			b.WriteString(string(v.Type) + ":" + strconv.Itoa(len(txt)) + ":" + txt)
		} else {
			b.WriteString("absent")
		}
		last = m[1]
	}
	b.WriteString(tmpl[last:])
	return "key:" + t.Automation.String() + ":" + digest(b.String())
}

// DedupeWindow is the declared key's window, at most MaxDedupeWindow.
func DedupeWindow(def *autodomain.Definition) time.Duration {
	if def == nil || def.When.Dedupe == nil {
		return 0
	}
	return min(def.When.Dedupe.Window.D(), MaxDedupeWindow)
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}
