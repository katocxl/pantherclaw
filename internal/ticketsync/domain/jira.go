// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"regexp"
	"strings"
	"time"
)

// Jira webhooks (D255). A Jira Cloud webhook registered with a secret
// signs its body with HMAC-SHA256 in the X-Hub-Signature header
// ("sha256=<hex>"), and names each delivery in
// X-Atlassian-Webhook-Identifier. The server verifies the signature with
// the sync configuration's secret before it reads anything else.

// Jira webhook headers.
const (
	JiraSignatureHeader = "X-Hub-Signature"
	JiraDeliveryHeader  = "X-Atlassian-Webhook-Identifier"
)

// MaxWebhookBytes bounds an inbound webhook body.
const MaxWebhookBytes = 1 << 20

// Webhook errors.
var (
	ErrSignature = errors.New("ticketsync: the webhook signature does not verify")
	ErrWebhook   = errors.New("ticketsync: the webhook is not a Jira issue or comment event")
)

var (
	issueKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,9}-[1-9][0-9]{0,9}$`)
	deliveryPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	// ProjectKeyPattern is a Jira project key.
	ProjectKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,9}$`)
)

// ValidIssueKey reports whether k is a Jira issue key.
func ValidIssueKey(k string) bool { return issueKeyPattern.MatchString(k) }

// ValidDeliveryID reports whether id can be stored as a delivery id.
func ValidDeliveryID(id string) bool { return deliveryPattern.MatchString(id) }

// VerifyJiraSignature reports whether header is a valid "sha256=<hex>"
// HMAC-SHA256 of body under one of secrets, compared in constant time.
func VerifyJiraSignature(header string, body []byte, secrets ...[]byte) bool {
	sum, ok := strings.CutPrefix(strings.TrimSpace(header), "sha256=")
	if !ok {
		return false
	}
	got, err := hex.DecodeString(sum)
	if err != nil || len(got) != sha256.Size {
		return false
	}
	match := false
	for _, s := range secrets {
		if len(s) == 0 {
			continue
		}
		m := hmac.New(sha256.New, s)
		m.Write(body)
		if hmac.Equal(m.Sum(nil), got) {
			match = true
		}
	}
	return match
}

// SignJira returns the X-Hub-Signature value of body under secret (the
// simulator and tests).
func SignJira(secret, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// Event is an inbound Jira event, reduced to what the sync reads.
type Event struct {
	Kind     string
	IssueKey string
	// At is when Jira says the change happened; a change at or before the
	// newest one already seen is a replay.
	At      time.Time
	Changes []Change
	Comment *Comment
}

type jiraUser struct {
	DisplayName string `json:"displayName"`
}

type jiraWebhook struct {
	Timestamp    int64  `json:"timestamp"`
	WebhookEvent string `json:"webhookEvent"`
	Issue        struct {
		Key    string `json:"key"`
		Fields struct {
			Updated string `json:"updated"`
			Status  struct {
				StatusCategory struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"status"`
		} `json:"fields"`
	} `json:"issue"`
	Changelog struct {
		Items []struct {
			Field      string `json:"field"`
			FieldID    string `json:"fieldId"`
			FromString string `json:"fromString"`
			ToString   string `json:"toString"`
		} `json:"items"`
	} `json:"changelog"`
	Comment *struct {
		ID     string         `json:"id"`
		Author jiraUser       `json:"author"`
		Body   jsontext.Value `json:"body"`
	} `json:"comment"`
}

// jiraFields maps Jira field names (lower case) to the sync's fields.
// Severity, containment and restoration are custom fields named so; an
// unknown field is not read.
var jiraFields = map[string]Field{
	"status": FieldState, "resolution": FieldState, "severity": FieldSeverity, "containment": FieldContainment,
	"restoration": FieldRestoration, "assignee": FieldAssignee, "labels": FieldLabels, "priority": FieldPriority,
}

// jiraTime is Jira's issue time format.
const jiraTime = "2006-01-02T15:04:05.000-0700"

// ParseJiraWebhook reads a Jira issue or comment webhook body.
func ParseJiraWebhook(body []byte) (Event, error) {
	if len(body) > MaxWebhookBytes {
		return Event{}, ErrWebhook
	}
	var w jiraWebhook
	if err := json.Unmarshal(body, &w); err != nil {
		return Event{}, ErrWebhook
	}
	ev := Event{Kind: w.WebhookEvent, IssueKey: w.Issue.Key}
	switch w.WebhookEvent {
	case "jira:issue_updated", "comment_created", "comment_updated":
	default:
		return Event{}, ErrWebhook
	}
	if !ValidIssueKey(ev.IssueKey) {
		return Event{}, ErrWebhook
	}
	switch {
	case w.Timestamp > 0:
		ev.At = time.UnixMilli(w.Timestamp).UTC()
	default:
		t, err := time.Parse(jiraTime, w.Issue.Fields.Updated)
		if err != nil {
			return Event{}, ErrWebhook
		}
		ev.At = t.UTC()
	}
	done := w.Issue.Fields.Status.StatusCategory.Key == "done"
	for _, it := range w.Changelog.Items {
		f, ok := jiraFields[strings.ToLower(strings.TrimSpace(it.Field))]
		if !ok {
			continue
		}
		c := Change{Field: f, From: it.FromString, To: it.ToString}
		if f == FieldState && strings.EqualFold(it.Field, "status") {
			c.Done = done
		}
		ev.Changes = append(ev.Changes, c)
	}
	if w.Comment != nil && strings.HasPrefix(w.WebhookEvent, "comment_") {
		c := &Comment{ID: w.Comment.ID, Author: w.Comment.Author.DisplayName}
		var s string
		if json.Unmarshal(w.Comment.Body, &s) == nil {
			c.Body = s
		} else if len(w.Comment.Body) > 0 {
			c.Body = "(a rich-text comment)"
		}
		ev.Comment = c
	}
	return ev, nil
}
