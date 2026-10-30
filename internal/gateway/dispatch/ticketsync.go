// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"regexp"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// Ticket sync (G0 M20 D255). The server never holds the ticket system's
// credential (HR-060): a ticket the sync opens or comments on is a task of
// purpose ticket_sync, leased by the gateway like a verification read and
// sent through the connection with its sealed credential. Only the
// package's own create and comment operations are sent, and only through a
// pc.jira connection; the task is leased once (a write is never retried),
// and only the answer's status, digest and the new issue's key and id come
// back. Nothing a ticket says reaches an authorization decision (HR-527).

// ticketPackage is the one package ticket sync tasks go through.
const ticketPackage = "pc.jira"

// ticketOperations are the writes a ticket sync task may make, with the
// answer fields it reports.
var ticketOperations = map[string][]string{
	"jira.issue.create":  {"/id", "/key"},
	"jira.issue.comment": {"/id"},
}

// ticketSync makes a ticket sync task's write.
func (e *Engine) ticketSync(ctx context.Context, conn *control.Connection, l Lease) (Observation, error) {
	report, ok := ticketOperations[l.Operation]
	if !ok || conn.Package == nil || conn.Package.Name != ticketPackage {
		return Observation{}, fmt.Errorf("%w: ticket sync", ErrNotReviewedRead)
	}
	def, ok := conn.Package.Definition(l.Operation)
	if !ok || def.Dispatch == nil || def.Dispatch.HTTP == nil {
		return Observation{}, fmt.Errorf("%w: ticket sync", ErrNotReviewedRead)
	}
	var req verifyRequest
	if err := json.Unmarshal(l.Request, &req, json.RejectUnknownMembers(true)); err != nil || req.Mode != "ticket_sync" ||
		req.Target.Type != def.Target.Type || !targetMatches(def.Target.IDPattern, req.Target.ID) {
		return Observation{}, fmt.Errorf("%w: ticket sync request", ErrNotReviewedRead)
	}
	res, ok := e.readWith(ctx, conn, def, req.Target, req.Params, "")
	if !ok {
		// The write may have reached the ticket system: the server records
		// the status and never sends it again.
		return Observation{HTTPStatus: res.Status}, nil
	}
	sum := sha256.Sum256(res.Body)
	out := Observation{HTTPStatus: res.Status, Digest: sum[:]}
	if res.Status >= 200 && res.Status <= 299 {
		declared := map[string]bool{}
		for _, f := range report {
			declared[f] = true
		}
		out.Found, out.Fields = true, fields(res.Body, declared)
	}
	return out, nil
}

// targetMatches reports whether id matches the definition's anchored
// target pattern.
func targetMatches(pattern, id string) bool {
	re, err := regexp.Compile(pattern)
	return err == nil && id != "" && re.MatchString(id)
}
