// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim"
	"github.com/katocxl/pantherclaw/internal/sim/jira"
	pcjira "github.com/katocxl/pantherclaw/packages/pc-jira"
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

// TestT226_ATicketSyncWriteNeverReachesACustomerProject: the gateway reads
// jira.project.external before a sync write: an internal project gets the
// issue; a service desk, and a project it could not read, get nothing, and
// the observation says refused (D277, HR-522).
//
// Covers: T-226, F545
func TestT226_ATicketSyncWriteNeverReachesACustomerProject(t *testing.T) {
	s := jira.New(sim.JiraProjects(), sim.JiraIssues(), jira.Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	p, err := manifest.Decode(pcjira.Package)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{
		broker: &plainOpener{plain: []byte("ZGV2QGV4YW1wbGUudGVzdDp0b2tlbg==")}, allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		clients: map[string]clientEntry{}, tokenClients: map[string]clientEntry{}, log: pclog.Discard(), factTimeout: DefaultFactTimeout,
	}
	conn := &control.Connection{
		GatewayConnection: &pb.GatewayConnection{Id: "c", Kind: "http", BaseUrl: srv.URL, AccessMode: "pantherclaw_held"}, Package: p,
		Credential: &pb.SealedCredential{Kind: credentials.KindStatic, AllowedHosts: []string{u.Host}, Header: "Authorization", Scheme: "Basic"},
	}
	open := func(project string) Observation {
		t.Helper()
		out, err := e.ticketSync(context.Background(), conn, Lease{Purpose: "ticket_sync", Operation: "jira.issue.create", Request: []byte(
			`{"mode":"ticket_sync","target":{"type":"jira_project","id":"` + project + `"},"params":{"summary":"s","description":"d","issue_type":"Task"}}`)})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := len(s.Issues())
	for _, project := range []string{sim.JiraHelpDesk, "NOSUCH"} {
		if out := open(project); out.Fields[ticketRefused] != ticketRefusedExternal || out.HTTPStatus != 0 {
			t.Fatalf("%s: %+v", project, out)
		}
	}
	if n := len(s.Issues()); n != before {
		t.Fatalf("a refused write reached Jira: %d issues, %d before", n, before)
	}
	out := open(sim.JiraEngineering)
	if out.HTTPStatus != http.StatusCreated || out.Fields["/key"] == "" || len(s.Issues()) != before+1 {
		t.Fatalf("an internal project: %+v, %d issues", out, len(s.Issues()))
	}
}
