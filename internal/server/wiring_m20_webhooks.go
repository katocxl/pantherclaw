// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"
	"maps"
	"net/http"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m20WebhookProcedures are the Ed25519 webhook opt-ins (G0 M20 D251,
// HR-510): each destination kind's own manage permission, checked again by
// its use case (a person, and the edition the destination already has).
var m20WebhookProcedures = map[string]td.Permission{
	pantherclawv1connect.NotificationServiceSetChannelSignatureSchemeProcedure:          td.PermNotificationManage,
	pantherclawv1connect.SIEMServiceSetSIEMDestinationSignatureSchemeProcedure:          td.PermSIEMManage,
	pantherclawv1connect.TriggerServiceSetAutomationDestinationSignatureSchemeProcedure: td.PermAutomationEndpointsManage,
}

func init() { maps.Copy(procedurePermissions, m20WebhookProcedures) }

// webhookJWKS is an org's webhook JWKS document: its ACTIVE and RETIRING
// webhooks keys, and no other org's (HR-511). The keystore implements it.
type webhookJWKS interface {
	WebhookJWKS(ctx context.Context, org ids.OrgID) ([]byte, error)
}

// emptyJWKS is served for an org without webhook keys, and when none are
// wired: the same answer as for an org that does not exist, so the route
// does not tell orgs apart.
var emptyJWKS = []byte(`{"keys":[]}`)

// mountWebhookJWKS serves GET /.well-known/pantherclaw/orgs/{org}/webhook-jwks.json
// (D251), public like the platform JWKS. Receivers of opted-in webhooks
// verify `v1a,` signatures with it.
func mountWebhookJWKS(mux *http.ServeMux, src webhookJWKS, log *slog.Logger) {
	mux.HandleFunc("GET /.well-known/pantherclaw/orgs/{org}/webhook-jwks.json", func(w http.ResponseWriter, r *http.Request) {
		org, err := ids.Parse[ids.Org](r.PathValue("org"))
		if err != nil || org == ids.PlatformOrg {
			http.NotFound(w, r)
			return
		}
		b := emptyJWKS
		if src != nil {
			if b, err = src.WebhookJWKS(r.Context(), org); err != nil {
				log.ErrorContext(r.Context(), "webhooks.jwks_failed", slog.String("org", org.String()), slog.Any("error", err))
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write(b)
	})
}
