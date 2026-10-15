// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package feed turns the evidence ledger's chain into a stream of
// normalized events (G0 M10 D2). Detection, the live stream, search and
// SIEM export all read it. The cursor is the chain seq; the stable event id
// is the ledger entry id.
//
// Normalize is pure and has one entry per ledger kind; unknown kinds pass
// through with their kind and actor only. Events carry ids, decisions and
// small scalar attributes, never payloads or secrets.
package feed

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Event is one normalized ledger entry.
type Event struct {
	Seq              int64
	ID               ids.UUID
	Org              ids.OrgID
	Kind             string
	OccurredAt       time.Time
	ActorType        string
	ActorID          string
	Subjects         []reflexdomain.Subject
	Decision         string
	Reason           string
	Operation        string
	Mode             string
	Outcome          string
	Environment      string
	DestinationClass string
	Test             bool
	// Attrs are scalar attributes: at most MaxAttrs keys of at most
	// MaxAttrValue bytes, never payloads or secrets.
	Attrs map[string]string
}

// Limits on an event's attributes.
const (
	MaxAttrs     = 32
	MaxAttrValue = 512
)

// Subject returns the first subject of type t, if any.
func (e Event) Subject(t reflexdomain.SubjectType) (string, bool) {
	for _, s := range e.Subjects {
		if s.Type == t {
			return s.ID, true
		}
	}
	return "", false
}

// ErrMalformed reports a known kind whose body does not parse.
var ErrMalformed = errors.New("feed: malformed ledger body")

// normalizer fills e from one kind's body.
type normalizer func(e *Event, body []byte) error

// kinds is the per-kind table. audit.* entries share one normalizer.
var kinds = map[string]normalizer{
	"receipt.decision":        decision,
	"receipt.execution":       execution,
	"receipt.effect":          effect,
	"coverage.snapshot":       coverageSnapshot,
	"coverage.invalidation":   coverageInvalidation,
	"sandbox.closure":         sandboxClosure,
	reflexdomain.KindAlert:    reflexEntry,
	reflexdomain.KindLive:     reflexEntry,
	reflexdomain.KindIncident: reflexEntry,
}

// Known reports whether kind has its own normalizer (audit.* included).
func Known(kind string) bool {
	_, ok := kinds[kind]
	return ok || strings.HasPrefix(kind, "audit.")
}

// Normalize turns one ledger entry into an event. Seq, ID and Org are the
// reader's to set. An unknown kind passes through with kind and actor
// only; a known kind whose body does not parse is an error.
func Normalize(kind, actorType, actorID string, occurred time.Time, body []byte) (Event, error) {
	e := Event{Kind: kind, ActorType: actorType, ActorID: actorID, OccurredAt: occurred}
	fn, ok := kinds[kind]
	if !ok && strings.HasPrefix(kind, "audit.") {
		fn, ok = auditEntry, true
	}
	if !ok || len(body) == 0 {
		return e, nil
	}
	if err := fn(&e, body); err != nil {
		return Event{Kind: kind, ActorType: actorType, ActorID: actorID, OccurredAt: occurred},
			fmt.Errorf("%w: %s: %w", ErrMalformed, kind, err)
	}
	e.Subjects = dedupe(e.Subjects)
	e.Attrs = clamp(e.Attrs)
	return e, nil
}

func decision(e *Event, body []byte) error {
	var b struct {
		Txn        string `json:"txn"`
		Evaluation string `json:"evaluation"`
		Decision   string `json:"decision"`
		Reason     string `json:"reason"`
		Monitor    string `json:"monitor"`
		Would      string `json:"would"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	e.Decision, e.Reason = b.Decision, b.Reason
	e.Subjects = appendID(e.Subjects, reflexdomain.SubjectTransaction, b.Txn)
	e.Attrs = attrs("evaluation", b.Evaluation, "would", b.Would)
	if b.Monitor == "true" {
		e.Mode = "MONITOR"
	}
	return nil
}

func execution(e *Event, body []byte) error {
	var b struct {
		Txn     string `json:"txn"`
		Permit  string `json:"permit"`
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	e.Outcome = b.Outcome
	e.Subjects = appendID(e.Subjects, reflexdomain.SubjectTransaction, b.Txn)
	e.Attrs = attrs("permit", b.Permit)
	return nil
}

func effect(e *Event, body []byte) error {
	var b struct {
		Txn   string `json:"txn"`
		Seq   string `json:"seq"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	e.Outcome = b.State
	e.Subjects = appendID(e.Subjects, reflexdomain.SubjectTransaction, b.Txn)
	e.Attrs = attrs("effect_seq", b.Seq)
	return nil
}

func coverageSnapshot(e *Event, body []byte) error {
	var b struct {
		Scope struct {
			Agent      string `json:"agent"`
			Connection string `json:"connection"`
			Operation  string `json:"operation"`
		} `json:"scope"`
		State         string `json:"state"`
		Snapshot      string `json:"snapshot"`
		Closure       string `json:"closure"`
		PreviousState string `json:"previous_state"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	e.Operation, e.Outcome = b.Scope.Operation, b.State
	e.Subjects = appendID(e.Subjects, reflexdomain.SubjectAgent, b.Scope.Agent)
	e.Subjects = appendID(e.Subjects, reflexdomain.SubjectConnection, b.Scope.Connection)
	e.Attrs = attrs("state", b.State, "snapshot", b.Snapshot, "closure", b.Closure, "previous_state", b.PreviousState)
	return nil
}

func coverageInvalidation(e *Event, body []byte) error {
	var b struct {
		ID         string `json:"id"`
		Connection string `json:"connection"`
		Agent      string `json:"agent"`
		Kind       string `json:"kind"`
		Subject    string `json:"subject"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	e.Reason = b.Kind
	e.Subjects = appendID(e.Subjects, reflexdomain.SubjectAgent, b.Agent)
	e.Subjects = appendID(e.Subjects, reflexdomain.SubjectConnection, b.Connection)
	e.Attrs = attrs("invalidation", b.ID, "kind", b.Kind, "subject", b.Subject)
	return nil
}

func sandboxClosure(e *Event, body []byte) error {
	var b struct {
		Closure     string   `json:"closure"`
		Agent       string   `json:"agent"`
		Connections []string `json:"connections"`
		Result      string   `json:"result"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	e.Outcome = b.Result
	e.Subjects = appendID(e.Subjects, reflexdomain.SubjectAgent, b.Agent)
	for _, c := range b.Connections {
		e.Subjects = appendID(e.Subjects, reflexdomain.SubjectConnection, c)
	}
	e.Attrs = attrs("closure", b.Closure)
	return nil
}

// reflexEntry reads Reflex's own entries (alerts, live events, incidents):
// detection skips them, the live stream and export read them.
func reflexEntry(e *Event, body []byte) error {
	var b struct {
		ID        string                 `json:"id"`
		Rule      string                 `json:"rule"`
		Severity  string                 `json:"severity"`
		Attention string                 `json:"attention"`
		State     string                 `json:"state"`
		Subjects  []reflexdomain.Subject `json:"subjects"`
		Test      bool                   `json:"test"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	for _, s := range b.Subjects {
		if s.Valid() {
			e.Subjects = append(e.Subjects, s)
		}
	}
	e.Outcome, e.Test = b.State, b.Test
	e.Attrs = attrs("id", b.ID, "rule", b.Rule, "severity", b.Severity, "attention", b.Attention)
	return nil
}

// objectTypes maps audit object types to subject types.
var objectTypes = map[string]reflexdomain.SubjectType{
	"agent": reflexdomain.SubjectAgent, "instance": reflexdomain.SubjectInstance, "run": reflexdomain.SubjectRun,
	"transaction": reflexdomain.SubjectTransaction, "grant": reflexdomain.SubjectGrant,
	"connection": reflexdomain.SubjectConnection, "credential": reflexdomain.SubjectCredential,
	"gateway": reflexdomain.SubjectGateway, "package": reflexdomain.SubjectPackage, "user": reflexdomain.SubjectUser,
	"service_account": reflexdomain.SubjectServiceAccount, "policy_version": reflexdomain.SubjectPolicyVersion,
	"alert": reflexdomain.SubjectAlert, "incident": reflexdomain.SubjectIncident, "case": reflexdomain.SubjectCase,
	"finding": reflexdomain.SubjectFinding, "approval_request": reflexdomain.SubjectResource,
}

// detailSubjects are audit detail keys that name a subject.
var detailSubjects = map[string]reflexdomain.SubjectType{
	"agent": reflexdomain.SubjectAgent, "agent_id": reflexdomain.SubjectAgent,
	"instance": reflexdomain.SubjectInstance, "instance_id": reflexdomain.SubjectInstance,
	"run": reflexdomain.SubjectRun, "run_id": reflexdomain.SubjectRun, "child_run": reflexdomain.SubjectRun,
	"txn": reflexdomain.SubjectTransaction, "transaction": reflexdomain.SubjectTransaction,
	"grant": reflexdomain.SubjectGrant, "grant_id": reflexdomain.SubjectGrant, "parent": reflexdomain.SubjectGrant,
	"connection": reflexdomain.SubjectConnection, "connection_id": reflexdomain.SubjectConnection,
	"credential": reflexdomain.SubjectCredential, "gateway": reflexdomain.SubjectGateway,
	"package": reflexdomain.SubjectPackage,
}

var uuidLike = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// auditEntry reads audit.<name> entries ({name, outcome, reason_code,
// object, details}).
func auditEntry(e *Event, body []byte) error {
	var b struct {
		Outcome    string `json:"outcome"`
		ReasonCode string `json:"reason_code"`
		Object     *struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"object"`
		Details map[string]string `json:"details"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	e.Outcome, e.Reason = b.Outcome, b.ReasonCode
	// A simulated connection's or transaction's audit entry is a test event
	// (HR-222, D59 L5).
	e.Test = b.Details["simulated"] == "true"
	if b.Object != nil {
		if t, ok := objectTypes[b.Object.Type]; ok {
			e.Subjects = appendID(e.Subjects, t, b.Object.ID)
		}
		e.Attrs = attrs("object_type", b.Object.Type, "object_id", b.Object.ID)
	}
	for _, k := range slices.Sorted(maps.Keys(b.Details)) {
		v := b.Details[k]
		if t, ok := detailSubjects[k]; ok && (uuidLike.MatchString(v) || t == reflexdomain.SubjectPackage || t == reflexdomain.SubjectGateway) {
			e.Subjects = appendID(e.Subjects, t, v)
		}
		if k == "operation" {
			e.Operation = v
		}
		if e.Attrs == nil {
			e.Attrs = map[string]string{}
		}
		e.Attrs[k] = v
	}
	return nil
}

func appendID(s []reflexdomain.Subject, t reflexdomain.SubjectType, id string) []reflexdomain.Subject {
	if id == "" || len(id) > 256 {
		return s
	}
	return append(s, reflexdomain.Subject{Type: t, ID: id})
}

func dedupe(s []reflexdomain.Subject) []reflexdomain.Subject {
	out := s[:0:0]
	for _, x := range s {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	if len(out) > reflexdomain.MaxSubjects {
		out = out[:reflexdomain.MaxSubjects]
	}
	return out
}

// attrs builds an attribute map from key, value pairs, leaving out empty
// values.
func attrs(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}

// secretLike are attribute key parts that suggest a secret; such attributes
// are dropped (the audit validator refuses them too).
var secretLike = []string{"secret", "token", "password", "passphrase", "private", "credential_value", "cookie", "authorization", "proof"}

// clamp keeps at most MaxAttrs attributes in key order, drops secret-like
// keys and over-long values.
func clamp(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if len(out) == MaxAttrs {
			break
		}
		v := m[k]
		if len(v) > MaxAttrValue || slices.ContainsFunc(secretLike, func(p string) bool { return strings.Contains(k, p) }) {
			continue
		}
		out[k] = v
	}
	return out
}
