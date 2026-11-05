// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"time"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Runs of Kubernetes pods (G0 M32 D973, D973a). KubernetesService's
// StartPodRun starts a pod's run in the caller's transaction, launched by
// the pod's instance under the run grant of the trusted-issuer revision it
// was attested by, for the grant's principal. Only that handler calls it,
// after it authenticated the instance by PAP/1; StartRun's launcher check
// (ErrLauncher) is unchanged.

// SourceTrustedIssuer: the principal of the issuer entry's run grant
// (migration 00366).
const SourceTrustedIssuer = "trusted_issuer"

// ErrRunGrantPrincipal refuses a run grant whose principal is an instance:
// a pod's run acts for a user or a service account (D973a).
var ErrRunGrantPrincipal = pcerr.New(pcerr.FailedPrecondition, "K8S_RUN_GRANT_PRINCIPAL",
	"the issuer entry's run grant must name a user or a service account")

// WorkloadStart starts one pod's run.
type WorkloadStart struct {
	Org      ids.OrgID
	AgentID  ids.UUID
	Instance ids.UUID
	// IssuerRevision is the trusted-issuer revision the instance was
	// attested by; IssuerEntry its entry, named as the launcher in audit.
	IssuerRevision ids.UUID
	IssuerEntry    ids.UUID
	// RunGrant is that revision's run grant.
	RunGrant ids.UUID
	// PodName names the run.
	PodName string
	TTL     time.Duration
}

// StartForWorkloadTx starts the pod's run in the caller's transaction.
func (s *Service) StartForWorkloadTx(ctx context.Context, tx db.TenantTx, in WorkloadStart) (Run, error) {
	if in.TTL == 0 {
		in.TTL = DefaultTTL
	}
	minutes, err := checkLabel(in.PodName, in.TTL)
	if err != nil {
		return Run{}, err
	}
	if in.Org != tx.OrgID() || in.Instance.IsZero() || in.IssuerRevision.IsZero() || in.RunGrant.IsZero() {
		return Run{}, ErrLauncher
	}
	if s.grants == nil {
		return Run{}, ErrGrantsUnavailable
	}
	q := dbq.New(tx)
	a, err := usableAgent(ctx, q, in.Org, in.AgentID)
	if err != nil {
		return Run{}, err
	}
	if err := admittedInstance(ctx, q, in.Org, a.ID, in.Instance); err != nil {
		return Run{}, err
	}
	gid, err := gdomain.ParseGrantID(in.RunGrant.String())
	if err != nil {
		return Run{}, ErrGrantNotFound
	}
	g, found, err := s.grants.GrantInTx(ctx, tx, in.Org, gid)
	if err != nil {
		return Run{}, err
	}
	if !found {
		return Run{}, ErrGrantNotFound
	}
	inst, rev := in.Instance, in.IssuerRevision
	p := dbq.InsertRunParams{
		OrgID: in.Org, ID: ids.NewV7(), AgentID: a.ID, InstanceID: &inst, EnvironmentID: *a.EnvironmentID,
		PrincipalSource: SourceTrustedIssuer, TaskRef: in.PodName, TtlMinutes: minutes, Simulated: a.RangeAgent,
		LauncherInstanceID: &inst, LauncherIssuerID: &rev,
	}
	principal := g.Principal.ID
	switch g.Principal.Kind {
	case gdomain.PrincipalUser:
		p.PrincipalUserID = &principal
	case gdomain.PrincipalServiceAccount:
		p.PrincipalSaID = &principal
	default:
		return Run{}, ErrRunGrantPrincipal
	}
	launcher := Actor{Kind: "trusted_issuer", ID: in.IssuerEntry.String()}
	chain := []Actor{{Kind: string(g.Principal.Kind), ID: principal.String()}, launcher}
	if p.ActorChain, err = json.Marshal(chain); err != nil {
		return Run{}, err
	}
	if err := s.bindGrant(ctx, tx, in.Org, in.RunGrant, &p); err != nil {
		return Run{}, err
	}
	var out Run
	err = tx.Savepoint(ctx, "pod_run", func() error {
		r, err := q.InsertRun(ctx, p)
		if err != nil {
			return err
		}
		if out, err = view(r, r.State); err != nil {
			return err
		}
		return recordStart(ctx, tx, evdomain.Actor{Type: launcher.Kind, ID: launcher.ID}, out)
	})
	return out, err
}
