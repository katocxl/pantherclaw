// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"context"
	"encoding/json/v2"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Discovery limits (HR-148, G0 M3 constraint 15).
const (
	MaxNewDiscoveriesPerMinute = 60
	MaxOpenDiscoveries         = 200
	// MaxObserved bounds each observed attribute, in bytes.
	MaxObserved = 256
)

// DiscoverInput is a gateway's report of a request whose key-only proof
// it could not tie to an admitted instance (PAP-1 §4).
type DiscoverInput struct {
	Request pap.Request
	Proof   string
	// Gateway is the reporting gateway's id (from its credential).
	Gateway string
	// Route, ClientAddress and UserAgent are UNTRUSTED observations.
	Route, ClientAddress, UserAgent string
}

// floods remembers when a flood was last audited per org and gateway, so
// a flood writes one event a minute, not one per sighting.
type floods struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (f *floods) due(key string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.last == nil {
		f.last = map[string]time.Time{}
	}
	if now.Sub(f.last[key]) < time.Minute {
		return false
	}
	f.last[key] = now
	return true
}

// truncate keeps at most MaxObserved bytes of valid UTF-8.
func truncate(s string) string {
	s = strings.ToValidUTF8(s, "")
	for len(s) > MaxObserved {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	return s
}

// Discover records an unknown workload (HR-148). The report is verified as
// a key-only proof in the PAP-1 §4 order and consumed; a proof that fails
// creates nothing. A key that belongs to an instance is not unknown. The
// first sighting of a key creates a DISCOVERED agent, its discovery and an
// ADMISSION entry; later ones are only counted. At most
// MaxNewDiscoveriesPerMinute new discoveries per gateway and
// MaxOpenDiscoveries open ones per org: past either, the sighting is
// dropped and a security.discovery_flood event is audited (once a minute).
// It returns the new discovery's id, or the zero id when nothing was
// created. Discovering grants nothing.
func (s *Service) Discover(ctx context.Context, org ids.OrgID, in DiscoverInput) (ids.UUID, error) {
	if in.Request.Token != "" {
		return ids.UUID{}, pap.Err(pap.CodeInvalidToken) // a report carries only a key-only proof
	}
	c, err := pap.VerifyRequest(nil, s.issuer, in.Request, in.Proof, s.clk.Now())
	if err != nil {
		return ids.UUID{}, err
	}
	if err := s.Consume(ctx, org, c); err != nil {
		return ids.UUID{}, err
	}
	gw := truncate(in.Gateway)
	observed := map[string]string{
		"gateway": gw, "route": truncate(in.Route), "client_address": truncate(in.ClientAddress), "user_agent": truncate(in.UserAgent),
	}
	var out ids.UUID
	flood := false
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockDiscoveries(ctx, org.String()); err != nil {
			return err
		}
		jkt := c.JKT()
		if known, err := q.InstanceExistsForKey(ctx, org, jkt); err != nil || known {
			return err
		}
		if n, err := q.TouchDiscovery(ctx, org, &jkt); err != nil || n > 0 {
			return err
		}
		load, err := q.DiscoveryLoad(ctx, org, gw)
		if err != nil {
			return err
		}
		if load.OpenDiscoveries >= MaxOpenDiscoveries || load.RecentFromGateway >= MaxNewDiscoveriesPerMinute {
			flood = true
			return nil
		}
		out, err = s.insertDiscovery(ctx, q, tx, org, c, observed)
		return err
	})
	if err != nil {
		return ids.UUID{}, err
	}
	if flood {
		s.auditFlood(ctx, org, gw)
	}
	return out, nil
}

func (s *Service) insertDiscovery(ctx context.Context, q *dbq.Queries, tx db.TenantTx, org ids.OrgID, c pap.Checked,
	observed map[string]string,
) (ids.UUID, error) {
	jkt := c.JKT()
	agent, err := q.InsertDiscoveredAgent(ctx, dbq.InsertDiscoveredAgentParams{
		OrgID: org, ID: ids.NewV7(), Name: "discovered-" + jkt[:12], CreatedBy: "gateway:" + observed["gateway"],
	})
	if err != nil {
		return ids.UUID{}, err
	}
	jwk, err := json.Marshal(jws.JWK{Kty: "OKP", Crv: "Ed25519", X: b64(c.Key())})
	if err != nil {
		return ids.UUID{}, err
	}
	obs, err := json.Marshal(observed)
	if err != nil {
		return ids.UUID{}, err
	}
	d, err := q.InsertGatewayDiscovery(ctx, dbq.InsertGatewayDiscoveryParams{
		OrgID: org, ID: ids.NewV7(), AgentID: agent.ID, KeyJkt: &jkt, PublicJwk: jwk, Observed: obs,
	})
	if err != nil {
		return ids.UUID{}, err
	}
	ev, err := json.Marshal(map[string]map[string]string{
		"trusted":   {"fingerprint": jkt, "source": "gateway", "discovery_id": d.ID.String()},
		"untrusted": observed,
	})
	if err != nil {
		return ids.UUID{}, err
	}
	if _, err := q.InsertAgentAdmissionEntry(ctx, dbq.InsertAgentAdmissionEntryParams{
		OrgID: org, ID: ids.NewV7(), AgentID: agent.ID, Evidence: ev,
	}); err != nil {
		return ids.UUID{}, err
	}
	if err := agents.RecordChange(ctx, q, org, agent.ID, adomain.Change{
		Kind: adomain.ChangeDiscovered, Actor: adomain.System,
		Details: map[string]string{"discovery_id": d.ID.String(), "fingerprint": jkt},
	}); err != nil {
		return ids.UUID{}, err
	}
	return d.ID, recordAs(ctx, tx, evdomain.Actor{Type: "gateway", ID: observed["gateway"]}, auditkind.IdentityWorkloadDiscovered,
		"agent", agent.ID, map[string]string{"discovery_id": d.ID.String(), "fingerprint": jkt})
}

// auditFlood writes security.discovery_flood at most once a minute per org
// and gateway, in its own transaction.
func (s *Service) auditFlood(ctx context.Context, org ids.OrgID, gw string) {
	if !s.floods.due(org.String()+"|"+gw, time.Now()) {
		return
	}
	_ = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return recordAs(ctx, tx, evdomain.Actor{Type: "gateway", ID: gw}, auditkind.SecurityDiscoveryFlood, "org", org.UUID(),
			map[string]string{"gateway": gw})
	})
}
