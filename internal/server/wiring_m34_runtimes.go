// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"maps"
	"regexp"
	"slices"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The M34 core stream's wiring (G0 M34 D991, D992): a connection's runtime
// target, and RuntimeService, called by a cloud agent runtime's PantherClaw
// component (the AgentCore interceptor) and authenticated by PAP/1 like
// WorkloadService.

var m34RuntimeProcedures = map[string]td.Permission{
	pantherclawv1connect.ConnectionServiceSetConnectionRuntimeTargetProcedure:   td.PermConnectionManage,
	pantherclawv1connect.ConnectionServiceClearConnectionRuntimeTargetProcedure: td.PermConnectionManage,
	// A workload procedure, authenticated in its handler, never plan-gated
	// (HR-357), so it has no class (as D970c).
	pantherclawv1connect.RuntimeServiceStartRuntimeRunProcedure: td.PermWorkloadRun,
}

// Setting a runtime target adds a way for a runtime's gateway to be decided
// through the connection (a change); clearing one removes it (safety), as
// for a gateway's Kubernetes binding.
var m34RuntimeClasses = map[string]entitlements.Class{
	pantherclawv1connect.ConnectionServiceSetConnectionRuntimeTargetProcedure:   entitlements.ClassChange,
	pantherclawv1connect.ConnectionServiceClearConnectionRuntimeTargetProcedure: entitlements.ClassSafety,
}

func init() {
	maps.Copy(procedurePermissions, m34RuntimeProcedures)
	maps.Copy(procedureClasses, m34RuntimeClasses)
}

// registerM34Runtimes serves RuntimeService.
func registerM34Runtimes(rs *connect.Server, d apiDeps, workload *workloadrpc.Workload, runs *runsapp.Service) {
	pantherclawv1connect.RegisterRuntimeServiceHandler(rs, &runtimeRuns{pool: d.pool, workload: workload, runs: runs, clk: clock.System{}})
}

type runtimeRuns struct {
	pantherclawv1connect.UnimplementedRuntimeServiceHandler
	pool     *db.Pool
	workload *workloadrpc.Workload
	runs     *runsapp.Service
	clk      clock.Clock
}

// runtimeIssuerKinds are the attestation presets of a cloud agent runtime's
// instance (D992).
var runtimeIssuerKinds = []string{
	string(issuers.KindAWS), string(issuers.KindGCP), string(issuers.KindAzureMI), string(issuers.KindEntraAgent),
	string(issuers.KindSPIFFEX509), string(issuers.KindGCPInstance), // L3, G0 M35 D1030
}

// runtimeRunName is the name a caller gives its run.
var runtimeRunName = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,200}$`)

// Refusals (HR-761).
var (
	errRuntimeSigner = pcerr.New(pcerr.PermissionDenied, "RUNTIME_NOT_CLOUD_INSTANCE",
		"the caller is not an L2 instance enrolled by aws_iam, gcp_workload, azure_mi or entra_agent_id attestation through an active issuer entry")
	errRuntimeNoRunGrant = pcerr.New(pcerr.FailedPrecondition, "RUNTIME_NO_RUN_GRANT",
		"the caller's issuer entry has no run grant")
	errRuntimeRunName = pcerr.New(pcerr.InvalidArgument, "RUNTIME_RUN_NAME",
		"a run name is 1 to 200 letters, digits and . _ : / -")
)

// signer loads the caller's issuer revision and refuses anything but an
// admitted L2 instance enrolled by a cloud attestation preset whose entry
// is still active.
func (s *runtimeRuns) signer(ctx context.Context, q *dbq.Queries, in pap.Instance) (dbq.PcTrustedIssuer, error) {
	row, err := q.GetInstance(ctx, in.Org, in.Instance)
	if db.IsNoRows(err) {
		return dbq.PcTrustedIssuer{}, errRuntimeSigner
	} else if err != nil {
		return dbq.PcTrustedIssuer{}, err
	}
	if row.AgentID != in.Agent || row.State != "ADMITTED" || row.EnrolledVia != "attestation" || row.AttLevel < 2 ||
		row.IssuerRevisionID == nil || row.AttestedUntil == nil || !row.AttestedUntil.After(s.clk.Now()) {
		return dbq.PcTrustedIssuer{}, errRuntimeSigner
	}
	rev, err := q.ActiveRevisionFor(ctx, in.Org, *row.IssuerRevisionID)
	if db.IsNoRows(err) {
		return dbq.PcTrustedIssuer{}, errRuntimeSigner
	} else if err != nil {
		return dbq.PcTrustedIssuer{}, err
	}
	if !slices.Contains(runtimeIssuerKinds, rev.Kind) {
		return dbq.PcTrustedIssuer{}, errRuntimeSigner
	}
	return rev, nil
}

// StartRuntimeRun implements RuntimeServiceHandler (D992): a run launched by
// the caller's instance under its issuer entry's run grant, as StartPodRun
// starts a pod's (D973a).
func (s *runtimeRuns) StartRuntimeRun(ctx context.Context, req *pantherclawv1.StartRuntimeRunRequest) (*pantherclawv1.StartRuntimeRunResponse, error) {
	in, err := s.workload.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	name := req.GetName()
	if !runtimeRunName.MatchString(name) {
		return nil, errRuntimeRunName
	}
	var run runsapp.Run
	err = s.pool.InTenantTx(ctx, in.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rev, err := s.signer(ctx, q, in)
		if err != nil {
			return err
		}
		if rev.RunGrantID == nil {
			return errRuntimeNoRunGrant
		}
		run, err = s.runs.StartForWorkloadTx(ctx, tx, runsapp.WorkloadStart{
			Org: in.Org, AgentID: in.Agent, Instance: in.Instance, IssuerRevision: rev.ID, IssuerEntry: rev.EntryID,
			RunGrant: *rev.RunGrantID, PodName: name, Runtime: true,
		})
		if err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.RuntimeRunStarted, Actor: evdomain.Actor{Type: "instance", ID: in.Instance.String()},
			Outcome: audit.Success, Object: &audit.Object{Type: "run", ID: run.ID.String()},
			Details: map[string]string{
				"instance_id": in.Instance.String(), "run_id": run.ID.String(), "name": name,
				"issuer_kind": rev.Kind, "issuer_entry": rev.EntryID.String(),
			},
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	s.workload.SetNonce(ctx, in)
	return &pantherclawv1.StartRuntimeRunResponse{RunId: run.ID.String()}, nil
}
