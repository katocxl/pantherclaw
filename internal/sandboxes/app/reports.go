// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// rejected is why a report was refused: recorded, never returned (the
// caller sees ErrReport).
type rejected struct{ reason string }

func (r rejected) Error() string { return "probe report rejected: " + r.reason }

func reject(reason string) error { return rejected{reason} }

// now is the service clock's time, for a nonce's and a session's lifetime.
func (s *Service) now() time.Time {
	if s.Clock == nil {
		return time.Now()
	}
	return s.Clock.Now()
}

// Accepted is a verified report.
type Accepted struct {
	Kind   string
	Report report.Report
	// Failed names the results that were not as expected.
	Failed []string
	// issuedAt is when the report's nonce was issued, with its probe run's.
	issuedAt time.Time
}

// SubmitProbeReport verifies the probe container's or the control run's
// signed report and keeps it (HR-215). On the session's first report it
// binds the sandbox instance, which must be admitted, and the run.
func (s *Service) SubmitProbeReport(ctx context.Context, session ids.UUID, compact string, run *ids.UUID) (Accepted, error) {
	return s.submit(ctx, session, compact, run, func(k string) bool { return k == KindSandbox || k == KindControl }, nil)
}

// submit verifies a report of an allowed kind in the session's
// transaction, runs then (the canary's closures) and keeps the report. A
// rejection is recorded in a transaction of its own and returned as
// ErrReport.
func (s *Service) submit(ctx context.Context, session ids.UUID, compact string, run *ids.UUID, allowed func(string) bool,
	then func(ctx context.Context, tx db.TenantTx, q *dbq.Queries, sess dbq.PcSandboxSession, a Accepted) error,
) (Accepted, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Accepted{}, err
	}
	var out Accepted
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		sess, err := q.LockSandboxSession(ctx, c.Org, session)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if _, err := agentFor(ctx, c, q, sess.AgentID, td.PermSandboxRun); err != nil {
			return err
		}
		if sess.State != "OPEN" || !s.now().Before(sess.ExpiresAt) {
			return ErrNotOpen
		}
		a, nonce, err := verify(ctx, q, sess, compact, allowed)
		if err != nil {
			return err
		}
		if err := s.bind(ctx, q, sess, run); err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(compact))
		if _, err := q.InsertProbeRun(ctx, dbq.InsertProbeRunParams{
			OrgID: c.Org, ID: ids.NewV7(), SessionID: sess.ID, NonceID: nonce.ID, Kind: a.Kind, Report: compact, ReportSha256: sum[:],
		}); err != nil {
			return err
		}
		if then != nil {
			if err := then(ctx, tx, q, sess, a); err != nil {
				return err
			}
		}
		out = a
		return record(ctx, tx, c, "sandbox.report_accepted", sess.ID, map[string]string{
			"kind": a.Kind, "failed": strconv.Itoa(len(a.Failed)),
		})
	})
	if r, ok := errors.AsType[rejected](err); ok {
		_ = s.Pool.InTenantTx(context.WithoutCancel(ctx), c.Org, func(ctx context.Context, tx db.TenantTx) error {
			return record(ctx, tx, c, "sandbox.report_rejected", session, map[string]string{"reason": r.reason})
		})
		return Accepted{}, ErrReport
	}
	return out, err
}

// verify checks a report against its session (HR-215, HR-218): its key
// (the session's probe key for the sandbox run, its host key for the
// control run and the canary), a kind the call accepts, the session, a
// nonce of that kind issued to the session, unused and at most 15 minutes
// old (used now), the session's images, configuration and engine, and for
// the sandbox run the isolated network and passing configuration checks.
func verify(ctx context.Context, q *dbq.Queries, sess dbq.PcSandboxSession, compact string, allowed func(string) bool,
) (Accepted, dbq.PcProbeNonce, error) {
	r, err := report.Verify(compact, ed25519.PublicKey(sess.ProbePublicKey))
	byProbe := err == nil
	if !byProbe {
		r, err = report.Verify(compact, ed25519.PublicKey(sess.HostPublicKey))
	}
	if err != nil {
		return Accepted{}, dbq.PcProbeNonce{}, reject("signature or format")
	}
	kind := strings.ToUpper(r.Kind)
	switch {
	case byProbe != (kind == KindSandbox):
		return Accepted{}, dbq.PcProbeNonce{}, reject("signed with the other kind's key")
	case !allowed(kind):
		return Accepted{}, dbq.PcProbeNonce{}, reject("kind " + r.Kind)
	case r.Session != sess.ID.String():
		return Accepted{}, dbq.PcProbeNonce{}, reject("another session")
	case r.Images != report.Images{Agent: sess.AgentImage, Edge: sess.EdgeImage, Probe: sess.ProbeImage}:
		return Accepted{}, dbq.PcProbeNonce{}, reject("images differ from the session's")
	case r.Config.Digest != sess.ConfigDigest:
		return Accepted{}, dbq.PcProbeNonce{}, reject("configuration differs from the session's")
	case r.Engine.Version != sess.EngineVersion || r.Engine.APIVersion != sess.ApiVersion || r.Engine.Runtime != sess.Runtime ||
		major(r.Engine.Version) < docker.MinEngineMajor:
		return Accepted{}, dbq.PcProbeNonce{}, reject("engine")
	case kind == KindSandbox && (!r.Network.Internal || r.Network.GatewayModeIPv4 != "isolated" || r.Network.IPv6 ||
		len(r.Config.Checks) == 0 || slices.ContainsFunc(r.Config.Checks, func(c report.Check) bool { return !c.OK })):
		return Accepted{}, dbq.PcProbeNonce{}, reject("the sandbox network or configuration is not isolated")
	}
	sum := sha256.Sum256([]byte(r.Nonce))
	n, err := q.UseProbeNonce(ctx, dbq.UseProbeNonceParams{OrgID: sess.OrgID, NonceSha256: sum[:], SessionID: sess.ID, Kind: kind})
	if db.IsNoRows(err) {
		return Accepted{}, dbq.PcProbeNonce{}, reject("nonce unknown, used, expired or of another kind")
	} else if err != nil {
		return Accepted{}, dbq.PcProbeNonce{}, err
	}
	a := Accepted{Kind: kind, Report: r, issuedAt: n.CreatedAt}
	for _, x := range r.Results {
		if !x.Passed() {
			a.Failed = append(a.Failed, x.Name)
		}
	}
	return a, n, nil
}

// bind binds the session's sandbox instance, which must be admitted, and
// marks it as the session's; and its run, which must be the instance's.
func (s *Service) bind(ctx context.Context, q *dbq.Queries, sess dbq.PcSandboxSession, run *ids.UUID) error {
	in, err := q.SandboxSessionInstance(ctx, sess.OrgID, &sess.EnrollmentTokenID)
	if db.IsNoRows(err) || (err == nil && in.State != "ADMITTED") {
		return reject("the sandbox instance is not enrolled and admitted")
	} else if err != nil {
		return err
	}
	if n, err := q.BindSandboxSessionInstance(ctx, &in.ID, sess.OrgID, sess.ID); err != nil {
		return err
	} else if n != 1 {
		return reject("another instance")
	}
	if n, err := q.MarkSandboxInstance(ctx, dbq.MarkSandboxInstanceParams{
		OrgID: sess.OrgID, ID: in.ID, EnrollmentTokenID: &sess.EnrollmentTokenID, SessionID: &sess.ID,
	}); err != nil {
		return err
	} else if n != 1 {
		return reject("the instance belongs to another session")
	}
	if run == nil {
		return nil
	}
	r, err := q.GetRun(ctx, sess.OrgID, *run)
	if db.IsNoRows(err) || (err == nil && (r.PcRun.InstanceID == nil || *r.PcRun.InstanceID != in.ID)) {
		return reject("the run is not the sandbox instance's")
	} else if err != nil {
		return err
	}
	if n, err := q.BindSandboxSessionRun(ctx, run, sess.OrgID, sess.ID); err != nil {
		return err
	} else if n != 1 {
		return reject("another run")
	}
	return nil
}

// major is a version's major number, 0 when unreadable.
func major(v string) int {
	n, _ := strconv.Atoi(strings.SplitN(strings.TrimPrefix(v, "v"), ".", 2)[0])
	return n
}
