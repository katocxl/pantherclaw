// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	coverage "github.com/katocxl/pantherclaw/internal/coverage/app"
	covdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ErrStale refuses a probe run's closures when a mapped connection changed
// since the session opened: its bindings, or a change that invalidates
// closures (HR-211). The evidence no longer describes the connection, so a
// new session probes again.
var ErrStale = pcerr.New(pcerr.FailedPrecondition, "SANDBOX_SESSION_STALE",
	"a mapped connection changed since the sandbox session opened; open a new session")

// Closure is the closure recorded for one mapped connection.
type Closure struct {
	Connection, ID ids.UUID
	Passed         bool
	Failed         []string
	ExpiresAt      time.Time
}

// CanaryResult is what the canary's report recorded, and the nonces of
// the next probe run.
type CanaryResult struct {
	Closures []Closure
	Next     Nonces
}

// SubmitCanaryReport verifies the canary's signed report and, with the
// same probe run's sandbox and control reports, records the closure of
// every mapped connection through the coverage closure contract (HR-121,
// HR-215). The canary's verdicts are computed here from its hits, never
// taken from the caller: external_canary is blocked when no hit carries
// the sandbox run's marker, canary_control reachable when one carries the
// control run's. Coverage decides each closure's result itself; a failed
// one drops ENFORCED at once.
func (s *Service) SubmitCanaryReport(ctx context.Context, session ids.UUID, compact string) (CanaryResult, error) {
	var out CanaryResult
	_, err := s.submit(ctx, session, compact, nil, func(k string) bool { return k == KindCanary },
		func(ctx context.Context, tx db.TenantTx, q *dbq.Queries, sess dbq.PcSandboxSession, a Accepted) error {
			run, err := s.probeRun(ctx, q, sess, a, compact)
			if err != nil {
				return err
			}
			conns, err := q.SandboxSessionBindings(ctx, sess.OrgID, sess.ID)
			if err != nil {
				return err
			}
			config, err := hex.DecodeString(strings.TrimPrefix(sess.ConfigDigest, "sha256:"))
			if err != nil {
				return err
			}
			verdict := covdomain.Evaluate(run.probes, run.checks)
			for _, conn := range conns {
				id, err := s.Coverage.RecordClosure(ctx, tx, covdomain.Closure{
					Agent: sess.AgentID, Connection: conn.ConnectionID, SandboxSession: sess.ID, SessionStartedAt: sess.OpenedAt, ObservedAt: run.observed,
					Probes: run.probes, SigningKeyJKT: sess.ProbeJkt, ServerNonce: run.nonce, ResultsSHA256: run.digest,
					Engine:       covdomain.Engine{Version: sess.EngineVersion, APIVersion: sess.ApiVersion, Runtime: sess.Runtime},
					ImageDigests: []string{sess.AgentImage, sess.EdgeImage, sess.ProbeImage}, ConfigSHA256: [32]byte(config),
					ConfigChecks: run.checks, Bound: covdomain.Bound{
						ConnectionRevision: conn.ConnectionRevision, Gateway: conn.GatewayID, PackageVersion: conn.PackageVersionID,
						CredentialVersion: conn.CredentialVersion,
					},
				})
				switch {
				case errors.Is(err, coverage.ErrClosureStale), errors.Is(err, coverage.ErrNoBinding):
					return ErrStale
				case errors.Is(err, coverage.ErrClosureReplayed):
					return reject("the probe run was already recorded")
				case err != nil:
					return err
				}
				out.Closures = append(out.Closures, Closure{
					Connection: conn.ConnectionID, ID: id, Passed: verdict.Passed, Failed: verdict.Failed,
					ExpiresAt: run.observed.Add(s.Coverage.Freshness.EnforcedTTL),
				})
			}
			out.Next, err = issueNonces(ctx, q, sess.OrgID, sess.ID)
			return err
		})
	return out, err
}

// run is the probe run a canary report closes.
type run struct {
	probes []covdomain.ProbeResult
	// checks are the configuration checks, as the host signed them.
	checks []covdomain.ConfigCheck
	// observed is when the server received the sandbox report; nonce is
	// its nonce.
	observed time.Time
	nonce    string
	// digest is the SHA-256 of the three reports as signed.
	digest [32]byte
}

// probeRun gathers the probe run a canary report closes: the sandbox and
// control reports whose nonces were issued with the canary's, and the
// canary's verdicts.
func (s *Service) probeRun(ctx context.Context, q *dbq.Queries, sess dbq.PcSandboxSession, canary Accepted, compact string) (run, error) {
	runs, err := q.LatestProbeRuns(ctx, sess.OrgID, sess.ID, canary.issuedAt)
	if err != nil {
		return run{}, err
	}
	reports := map[string]dbq.PcProbeRun{}
	for _, r := range runs {
		reports[r.Kind] = r
	}
	sb, okS := reports[KindSandbox]
	ctl, okC := reports[KindControl]
	if !okS || !okC {
		return run{}, reject("the probe run's sandbox or control report is missing")
	}
	// Each stored report verified on submission with the key of its kind.
	sandbox, err := report.Verify(sb.Report, ed25519.PublicKey(sess.ProbePublicKey))
	if err != nil {
		return run{}, err
	}
	control, err := report.Verify(ctl.Report, ed25519.PublicKey(sess.HostPublicKey))
	if err != nil {
		return run{}, err
	}
	// observed is the server's time of the sandbox report, not the probe's
	// clock: it is never before the session started.
	out := run{observed: sb.ReceivedAt, nonce: sandbox.Nonce, digest: sha256.Sum256([]byte(sb.Report + "\n" + ctl.Report + "\n" + compact))}
	// The network facts and configuration checks are pclaw's, observed on the
	// host: they count as the host key signed them, in the control report,
	// and the probe-signed sandbox report must carry the same.
	if sandbox.Network != control.Network || !slices.Equal(sandbox.Config.Checks, control.Config.Checks) {
		return run{}, reject("the sandbox report's network or checks differ from the host's")
	}
	for _, k := range control.Config.Checks {
		out.checks = append(out.checks, covdomain.ConfigCheck{ID: k.ID, OK: k.OK, Detail: k.Detail})
	}
	for _, r := range append(append([]report.Result{}, sandbox.Results...), control.Results...) {
		out.probes = append(out.probes, covdomain.ProbeResult{Name: r.Name, Role: r.Role, Expect: r.Expect, Observed: r.Observed, Detail: r.Detail})
	}
	leaked, seen := hits(canary.Report, report.Marker(sandbox.Nonce)), hits(canary.Report, report.Marker(control.Nonce))
	out.probes = append(out.probes,
		covdomain.ProbeResult{
			Name: covdomain.ProbeExternalCanary, Role: covdomain.RoleCanary, Expect: covdomain.Blocked,
			Observed: outcome(leaked > 0), Detail: strconv.Itoa(leaked) + " hits of the sandbox run's marker",
		},
		covdomain.ProbeResult{
			Name: "canary_control", Role: covdomain.RolePositiveControl, Expect: covdomain.Reachable,
			Observed: outcome(seen > 0), Detail: strconv.Itoa(seen) + " hits of the control run's marker",
		},
	)
	return out, nil
}

func hits(r report.Report, marker string) int {
	n := 0
	for _, h := range r.Canary.Hits {
		if h.Marker == marker {
			n++
		}
	}
	return n
}

func outcome(reached bool) string {
	if reached {
		return covdomain.Reachable
	}
	return covdomain.Blocked
}

// EndSession ends a session (sandbox.run over its agent) and revokes its
// sandbox instance, moving the containment epoch so that outstanding
// permits fail (HR-002): the instance acts only inside its session.
func (s *Service) EndSession(ctx context.Context, id ids.UUID) (dbq.PcSandboxSession, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return dbq.PcSandboxSession{}, err
	}
	var out dbq.PcSandboxSession
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		sess, err := q.LockSandboxSession(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		a, err := agentFor(ctx, c, q, sess.AgentID)
		if err != nil {
			return err
		}
		if out, err = s.end(ctx, q, sess, "ENDED", c.Principal.String(), actor(c)); err != nil {
			return err
		}
		return record(ctx, tx, c, "sandbox.session_ended", sess.ID, map[string]string{"agent_id": a.ID.String()})
	})
	return out, err
}

// end closes an open session in state to and revokes its instance: the one
// its enrollment token enrolled, whether or not a report bound it yet. A
// closed session is returned as it is. by and act name who ends it.
func (s *Service) end(ctx context.Context, q *dbq.Queries, sess dbq.PcSandboxSession, to, by string, act adomain.Actor,
) (dbq.PcSandboxSession, error) {
	ended, err := q.EndSandboxSession(ctx, to, sess.OrgID, sess.ID)
	if db.IsNoRows(err) {
		return sess, nil
	} else if err != nil {
		return sess, err
	}
	instance := sess.InstanceID
	if instance == nil {
		in, err := q.SandboxSessionInstance(ctx, sess.OrgID, &sess.EnrollmentTokenID)
		if db.IsNoRows(err) {
			return ended, nil
		} else if err != nil {
			return ended, err
		}
		instance = &in.ID
	}
	reason := "sandbox session " + strings.ToLower(to)
	if _, err := q.CloseInstance(ctx, dbq.CloseInstanceParams{
		OrgID: sess.OrgID, ID: *instance, FromState: "ADMITTED", ToState: "REVOKED", DecidedBy: &by, Reason: &reason,
	}); db.IsNoRows(err) {
		return ended, nil // already revoked
	} else if err != nil {
		return ended, err
	}
	if err := agents.RecordChange(ctx, q, sess.OrgID, sess.AgentID, adomain.Change{
		Kind: adomain.ChangeInstanceRevoked, Actor: act, Reason: reason,
		Details: map[string]string{"instance_id": instance.String(), "sandbox_session_id": sess.ID.String()},
	}); err != nil {
		return ended, err
	}
	if err := q.InsertContainment(ctx, sess.OrgID); err != nil {
		return ended, err
	}
	_, err = q.BumpEpoch(ctx, sess.OrgID)
	return ended, err
}

// actor is the caller as an agent change's actor.
func actor(c tenancy.Caller) adomain.Actor {
	if c.Principal.Kind == td.KindServiceAccount {
		return adomain.ServiceAccountActor(c.Principal.ID)
	}
	return adomain.UserActor(c.Principal.ID)
}
