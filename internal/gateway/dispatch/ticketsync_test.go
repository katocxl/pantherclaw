// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestHR527_TicketSyncSendsOnlyTicketWrites: a ticket sync lease is sent
// only through a pc.jira connection and only as the package's issue create
// or comment; a transition, any other operation or package, or a request
// that is not a ticket sync request is refused before anything is sent
// (D255: the gateway never acts on a ticket's behalf beyond these).
//
// Covers: F545
func TestHR527_TicketSyncSendsOnlyTicketWrites(t *testing.T) {
	e := &Engine{}
	jira := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c"}, Package: &domain.Package{Name: "pc.jira"}}
	github := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c"}, Package: &domain.Package{Name: "pc.github"}}
	for name, c := range map[string]struct {
		conn *control.Connection
		op   string
	}{
		"a transition":       {jira, "jira.issue.transition"},
		"a read":             {jira, "jira.issue.read"},
		"another package":    {github, "jira.issue.create"},
		"no package":         {&control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c"}}, "jira.issue.create"},
		"an undefined write": {jira, "jira.issue.create"}, // the stub package defines nothing
	} {
		_, err := e.ticketSync(context.Background(), c.conn, Lease{Purpose: "ticket_sync", Operation: c.op, Request: []byte(`{"mode":"ticket_sync"}`)})
		if !errors.Is(err, ErrNotReviewedRead) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if targetMatches(`^(?P<project>[A-Z][A-Z0-9_]{1,9})$`, "SEC-1") || !targetMatches(`^(?P<project>[A-Z][A-Z0-9_]{1,9})$`, "SEC") {
		t.Error("the target pattern is not applied")
	}
}
