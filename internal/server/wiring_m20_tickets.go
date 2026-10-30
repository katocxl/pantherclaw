// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"
	"net/http"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/ticketsync/adapters/ticketsyncrpc"
	tsapp "github.com/katocxl/pantherclaw/internal/ticketsync/app"
)

// m20TicketProcedures are ticket sync's RPCs (G0 M20 D255, D264) and the
// chat identity links for Slack approval DMs (D256, D265), with the
// permissions their protos declare.
var m20TicketProcedures = map[string]td.Permission{
	pantherclawv1connect.TicketSyncServiceCreateTicketSyncConfigProcedure: td.PermConnectionManage,
	pantherclawv1connect.TicketSyncServiceListTicketSyncConfigsProcedure:  td.PermConnectionRead,
	pantherclawv1connect.TicketSyncServiceRotateTicketSyncSecretProcedure: td.PermConnectionManage,
	pantherclawv1connect.TicketSyncServiceSetTicketSyncPausedProcedure:    td.PermConnectionManage,
	pantherclawv1connect.TicketSyncServiceLinkCaseTicketProcedure:         td.PermCaseManage,
	pantherclawv1connect.TicketSyncServiceLinkIncidentTicketProcedure:     td.PermIncidentManage,
	pantherclawv1connect.TicketSyncServiceOpenCaseTicketProcedure:         td.PermCaseManage,
	pantherclawv1connect.TicketSyncServiceOpenIncidentTicketProcedure:     td.PermIncidentManage,
	pantherclawv1connect.TicketSyncServiceGetTicketFieldOwnersProcedure:   td.PermCaseRead,
	pantherclawv1connect.TicketSyncServiceSetTicketFieldOwnerProcedure:    td.PermConnectionManage,
	pantherclawv1connect.NotificationServiceProposeSlackLinkProcedure:     "authenticated",
	pantherclawv1connect.NotificationServiceConfirmChatLinkProcedure:      "authenticated",
	pantherclawv1connect.NotificationServiceRevokeChatLinkProcedure:       "authenticated",
	pantherclawv1connect.NotificationServiceListChatLinksProcedure:        "authenticated",
}

func init() { maps.Copy(procedurePermissions, m20TicketProcedures) }

// newTicketSync builds the ticket sync use cases (Business edition). The
// verification store hands it the gateway's ticket sync reports, and the
// API serves it and its inbound webhooks.
func newTicketSync(pool *db.Pool, kp keys.KeyProvider, bill *billing.Service) *tsapp.Service {
	return &tsapp.Service{Pool: pool, Envelope: pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp)), Editions: bill}
}

// registerM20Tickets serves TicketSyncService and registers the field
// owner surface with the protected-change Gate (D264).
func registerM20Tickets(rs *connect.Server, d apiDeps) {
	if d.tickets == nil {
		d.tickets = newTicketSync(d.pool, d.kp, d.billing)
	}
	d.tickets.RegisterProtected(d.m11protect.gate)
	pantherclawv1connect.RegisterTicketSyncServiceHandler(rs, ticketsyncrpc.New(d.tickets, d.publicURL))
}

// mountTicketWebhooks adds the public inbound ticket webhook route; the
// configuration's signature is its credential (D255).
func mountTicketWebhooks(mux *http.ServeMux, d apiDeps) {
	if d.tickets == nil {
		return
	}
	ticketsyncrpc.Webhooks{Svc: d.tickets}.Mount(mux)
}
