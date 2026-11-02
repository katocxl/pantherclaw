// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"slices"
	"time"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// SourceIDJAG: the principal an Identity Assertion JWT Authorization Grant
// proves, for the agent the assertion's client authenticated as (G0 M26
// D400, D408). The run's launcher is that client's instance.
const SourceIDJAG = "id_jag"

// IdentityRunInput starts the root run an IdP-native token uses (G0 M26
// D400-D402). The use case has already authenticated the client and the
// person, and chosen the grant; StartForIdentityTx checks the grant again in
// the run's own transaction (HR-620).
type IdentityRunInput struct {
	Org      ids.OrgID
	Agent    ids.UUID
	Instance ids.UUID
	User     ids.UUID
	// Issuer and Subject, when set, are the assertion's (iss, sub): the
	// source is id_jag and the launcher the instance. Unset, the run is the
	// signed-in person's own (source launcher, D408.4).
	Issuer, Subject string
	Grant           ids.UUID
	// Operations narrow the run within the grant; nil is the whole grant.
	Operations []string
	TaskRef    string
	TTL        time.Duration
}

// StartForIdentityTx starts the run in tx. The run is bound to the grant,
// never outlives it, and holds the narrowed operations; no grant row is
// written (HR-620, H8).
func (s *Service) StartForIdentityTx(ctx context.Context, tx db.TenantTx, in IdentityRunInput) (Run, error) {
	if in.TTL == 0 {
		in.TTL = DefaultTTL
	}
	minutes, err := checkLabel(in.TaskRef, in.TTL)
	if err != nil {
		return Run{}, err
	}
	q := dbq.New(tx)
	a, err := usableAgent(ctx, q, in.Org, in.Agent)
	if err != nil {
		return Run{}, err
	}
	if err := admittedInstance(ctx, q, in.Org, a.ID, in.Instance); err != nil {
		return Run{}, err
	}
	user, instance := in.User, in.Instance
	userActor := Actor{Kind: string(td.KindUser), ID: user.String()}
	p := dbq.InsertRunParams{
		OrgID: in.Org, ID: ids.NewV7(), AgentID: a.ID, InstanceID: &instance, EnvironmentID: *a.EnvironmentID,
		PrincipalUserID: &user, TaskRef: in.TaskRef, TtlMinutes: minutes, Simulated: a.RangeAgent,
	}
	if len(in.Operations) > 0 {
		p.ScopeOperations = slices.Clone(in.Operations)
	}
	chain := []Actor{userActor}
	actor := evdomain.Actor{Type: string(td.KindUser), ID: user.String()}
	if in.Issuer != "" {
		p.PrincipalSource, p.LauncherInstanceID = SourceIDJAG, &instance
		p.SubjectIssuer, p.SubjectSubject = &in.Issuer, &in.Subject
		chain = append(chain, Actor{Kind: "instance", ID: instance.String()})
		actor = evdomain.Actor{Type: "instance", ID: instance.String()}
	} else {
		p.PrincipalSource, p.LauncherUserID = SourceLauncher, &user
	}
	if p.ActorChain, err = json.Marshal(chain); err != nil {
		return Run{}, err
	}
	if err := s.bindGrant(ctx, tx, in.Org, in.Grant, &p); err != nil {
		return Run{}, err
	}
	r, err := q.InsertRun(ctx, p)
	if err != nil {
		return Run{}, err
	}
	out, err := view(r, r.State)
	if err != nil {
		return Run{}, err
	}
	return out, record(ctx, tx, actor, "run.started", out)
}
