// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"
	"maps"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/webhookkeys"
	"github.com/katocxl/pantherclaw/internal/webhookkeys/webhookkeysrpc"
)

// m20WebhookProcedures are the Ed25519 webhook opt-ins (G0 M20 D251,
// HR-510): each destination kind's own manage permission, checked again by
// its use case (a person, and the edition the destination already has).
var m20WebhookProcedures = map[string]td.Permission{
	pantherclawv1connect.WebhookKeyServiceListWebhookKeysProcedure:                      td.PermWebhookKeyRead,
	pantherclawv1connect.WebhookKeyServiceRotateWebhookKeyProcedure:                     td.PermWebhookKeyManage,
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

// webhookJWKSRateLimit is how many JWKS requests one client address may make
// a minute (D271): receivers cache the document, so this only stops floods.
const webhookJWKSRateLimit = 60

// mountWebhookJWKS serves GET /.well-known/pantherclaw/orgs/{org}/webhook-jwks.json
// (D251), public like the platform JWKS. Receivers of opted-in webhooks
// verify `v1a,` signatures with it. It is rate limited per client address
// (clientIP, nil for the direct peer) and the keystore serves it from
// memory, so a flood of org ids never reaches the database (D271).
func mountWebhookJWKS(mux *http.ServeMux, src webhookJWKS, clientIP httpx.ClientIPFunc, log *slog.Logger) {
	limiter := httpx.NewLimiter(webhookJWKSRateLimit, time.Minute, nil).WithClientIP(clientIP)
	mux.HandleFunc("GET /.well-known/pantherclaw/orgs/{org}/webhook-jwks.json", func(w http.ResponseWriter, r *http.Request) {
		if !limiter.AllowRequest(r) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
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

// webhookJWKSOf is the per-org key store the JWKS route reads; nil (an
// empty set) without a key provider.
func webhookJWKSOf(d apiDeps) webhookJWKS {
	if d.pool == nil || d.kp == nil {
		return nil
	}
	return processWebhookKeys(d.pool, d.kp)
}

// registerM20Webhooks serves WebhookKeyService (D261).
func registerM20Webhooks(rs *connect.Server, d apiDeps) {
	if d.pool == nil || d.kp == nil {
		return
	}
	svc := webhookkeys.New(d.pool, processWebhookKeys(d.pool, d.kp), d.publicURL)
	pantherclawv1connect.RegisterWebhookKeyServiceHandler(rs, webhookkeysrpc.New(svc))
}

// processKeys holds one webhook key store per pool in this process, so the
// senders, the JWKS route and WebhookKeyService share its caches: a
// rotation or a first key here drops the cached JWKS at once (D271).
var processKeys = struct {
	sync.Mutex
	m map[*db.Pool]*keystore.WebhookKeys
}{m: map[*db.Pool]*keystore.WebhookKeys{}}

func processWebhookKeys(pool *db.Pool, kp keys.KeyProvider) *keystore.WebhookKeys {
	processKeys.Lock()
	defer processKeys.Unlock()
	w, ok := processKeys.m[pool]
	if !ok {
		w = keystore.NewWebhookKeys(pool, kp)
		processKeys.m[pool] = w
	}
	return w
}

// registerM20WebhookJobs adds the hourly sweep that revokes expired
// RETIRING webhook keys (D271, HR-512).
func registerM20WebhookJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, kp keys.KeyProvider, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	if err := webhookkeys.RegisterJobs(reg, pool, processWebhookKeys(pool, kp), log); err != nil {
		return nil, err
	}
	return append(periodic, webhookkeys.PeriodicJobs()...), nil
}
