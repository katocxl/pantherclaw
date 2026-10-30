// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/ed25519"
	"time"

	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/hosting/domain"
	"github.com/katocxl/pantherclaw/internal/hosting/profile"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// HostIdentity is an authenticated host agent: one host, no org (HR-500).
type HostIdentity = ca.HostIdentity

// hostSupersededGrace is how long a renewed host certificate still works.
const hostSupersededGrace = 10 * time.Minute

// Errors of host agent calls. Every refusal of a host's identity is the
// same answer; every refusal about a hosted gateway the host does not run
// is NotFound, so a host learns nothing of other hosts' orgs (T-217).
var (
	ErrHostCredentials = pcerr.New(pcerr.Unauthenticated, "HOSTING_HOST_CREDENTIALS", "hosting host credentials required")
	ErrNotAssigned     = pcerr.New(pcerr.NotFound, "HOSTED_GATEWAY_NOT_FOUND", "hosted gateway not found")
	ErrTokenGone       = pcerr.New(pcerr.FailedPrecondition, "HOSTED_TOKEN_GONE", "the enrollment token was already pulled")
	ErrHostRenewal     = pcerr.New(pcerr.FailedPrecondition, "HOSTING_HOST_RENEWAL_REFUSED", "only the host's current certificate can be renewed")
)

// AuthenticateHost checks a verified host certificate against its row on
// every call: the certificate ACTIVE (or SUPERSEDED within the grace),
// unexpired by the database clock, and its host not RETIRED.
func (s *Service) AuthenticateHost(ctx context.Context, id HostIdentity) error {
	ok := false
	err := s.pool.InGlobalTx(ctx, db.GlobalHosting, func(ctx context.Context, tx db.GlobalTx) error {
		r, err := dbq.New(tx).HostingHostCertAuth(ctx, id.Cert)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		now := r.DbNow
		live := r.State == "ACTIVE" || (r.State == "SUPERSEDED" && r.SupersededAt != nil && now.Before(r.SupersededAt.Add(hostSupersededGrace)))
		ok = r.HostID == id.Host && r.HostState != domain.HostRetired && live && !now.Before(r.NotBefore) && now.Before(r.NotAfter)
		return nil
	})
	if err != nil {
		return err
	}
	if !ok {
		return ErrHostCredentials
	}
	return nil
}

// Assignment is one hosted gateway a host runs, as its agent needs it:
// never a token and never another org's data.
type Assignment struct {
	Org           ids.OrgID
	ID            ids.UUID
	Slug          string
	Hostname      string
	State         string
	Gateway       ids.UUID
	Limits        profile.Limits
	Version       string
	TargetVersion string
}

// Assignments lists the hosted gateways placed on the host and records
// that its agent was seen. Each org's row is read in that org's own
// transaction (HR-051), and only rows naming this host are returned.
func (s *Service) Assignments(ctx context.Context, id HostIdentity, agentVersion string) ([]Assignment, error) {
	var host dbq.PcHostingHost
	err := s.pool.InGlobalTx(ctx, db.GlobalHosting, func(ctx context.Context, tx db.GlobalTx) error {
		q := dbq.New(tx)
		if len(agentVersion) > 64 {
			agentVersion = agentVersion[:64]
		}
		if err := q.TouchHostingHost(ctx, &agentVersion, id.Host); err != nil {
			return err
		}
		var err error
		host, err = q.GetHostingHost(ctx, id.Host)
		return err
	})
	if err != nil {
		return nil, err
	}
	refs, err := s.assigned(ctx, id.Host, "")
	if err != nil {
		return nil, err
	}
	out := make([]Assignment, 0, len(refs))
	for _, r := range refs {
		err := s.pool.InTenantTx(ctx, r.Org, func(ctx context.Context, tx db.TenantTx) error {
			h, err := dbq.New(tx).GetHostedGateway(ctx, r.Org, r.ID)
			if db.IsNoRows(err) {
				return nil
			} else if err != nil {
				return err
			}
			if h.HostID == nil || *h.HostID != id.Host || h.GatewayID == nil {
				return nil
			}
			out = append(out, Assignment{
				Org: h.OrgID, ID: h.ID, Slug: h.Slug, Hostname: domain.Hostname(h.Slug, host.Domain), State: h.State, Gateway: *h.GatewayID,
				Limits:  profile.Limits{MilliCPUs: int(h.MilliCpus), MemoryMiB: int(h.MemoryMib), PIDs: int(h.Pids)},
				Version: deref(h.Version), TargetVersion: deref(h.TargetVersion),
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Token is what the host agent writes to the org's private tmpfs
// directory for the gateway process, once.
type Token struct {
	Secret        pclog.Secret[string]
	GatewayAPIURL string
	CAFingerprint string
}

// PullToken hands the hosted gateway's enrollment token to the host it is
// placed on, once (HR-502): the record forgets it in the same transaction.
// Another host, a second pull or a gateway already enrolled gets nothing.
func (s *Service) PullToken(ctx context.Context, id HostIdentity, org ids.OrgID, hosted ids.UUID) (Token, error) {
	var out Token
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if state, err := q.OrgState(ctx, org); err != nil || state != "ACTIVE" {
			return ErrNotAssigned
		}
		h, err := q.LockHostedGateway(ctx, org, hosted)
		if db.IsNoRows(err) || (err == nil && (h.HostID == nil || *h.HostID != id.Host)) {
			return ErrNotAssigned
		} else if err != nil {
			return err
		}
		if h.State != domain.StateProvisioned || h.TokenSealed == nil {
			return ErrTokenGone
		}
		plain, err := s.env.Decrypt(ctx, tokenField(org, hosted), tokenPurpose, h.TokenSealed)
		if err != nil {
			return err
		}
		if n, err := q.TakeHostedToken(ctx, org, hosted, &id.Host); err != nil {
			return err
		} else if n != 1 {
			return ErrTokenGone
		}
		out = Token{Secret: pclog.NewSecret(string(plain)), GatewayAPIURL: s.gatewayAPIURL, CAFingerprint: ca.Fingerprint(s.ca.Certificate())}
		return record(ctx, tx, hostActor(id.Host), "hosted_gateway.token_pulled", hosted, map[string]string{"host_id": id.Host.String()})
	})
	return out, err
}

// Report records the state and version of a process the host runs.
func (s *Service) Report(ctx context.Context, id HostIdentity, org ids.OrgID, hosted ids.UUID, healthy bool, version string) error {
	if len(version) > 64 {
		return pcerr.New(pcerr.InvalidArgument, "VERSION_INVALID", "version too long")
	}
	var target *string
	if s.fleet != nil {
		p, err := s.fleet.FleetPolicy(ctx, org)
		if err != nil {
			return err
		}
		target = rolloutTarget(version, p.MinimumVersion)
	}
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.ReportHostedGateway(ctx, dbq.ReportHostedGatewayParams{
			Healthy: healthy, Version: &version, OrgID: org, ID: hosted, HostID: &id.Host,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotAssigned
		}
		_, err = q.SetHostedTarget(ctx, target, org, hosted)
		return err
	})
}

// rolloutTarget is the version a hosted gateway should upgrade to: the
// org's fleet minimum, while it reports a lower or an unknown version. The
// minimum never moves a gateway down, and without one there is no target.
func rolloutTarget(reported string, minimum gwapp.Version) *string {
	if !minimum.Known() {
		return nil
	}
	if v, ok := gwapp.ParseVersion(reported); ok && v.Compare(minimum) >= 0 {
		return nil
	}
	t := minimum.String()
	return &t
}

// Stopped records that the host stopped and removed a deprovisioned
// process. Its gateway was revoked before (HR-503).
func (s *Service) Stopped(ctx context.Context, id HostIdentity, org ids.OrgID, hosted ids.UUID) error {
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		n, err := dbq.New(tx).FinishDeprovisionHostedGateway(ctx, org, hosted, &id.Host)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotAssigned
		}
		return record(ctx, tx, hostActor(id.Host), "hosted_gateway.stopped", hosted, nil)
	})
}

// HostCertificate is a host certificate the CA issued.
type HostCertificate struct {
	Certificate   []byte
	CACertificate []byte
	Identity      HostIdentity
}

// AddHost records a shared hosting host and issues its agent's first
// certificate for pub (operator command, never an RPC).
func (s *Service) AddHost(ctx context.Context, name, domainName string, capacity, milliCPUs, memoryMiB int32, pub ed25519.PublicKey) (HostCertificate, error) {
	var out HostCertificate
	err := s.pool.InGlobalTx(ctx, db.GlobalHosting, func(ctx context.Context, tx db.GlobalTx) error {
		q := dbq.New(tx)
		h, err := q.InsertHostingHost(ctx, dbq.InsertHostingHostParams{
			ID: ids.NewV7(), Name: name, Domain: domainName, Capacity: capacity, MilliCpus: milliCPUs, MemoryMib: memoryMiB,
		})
		if err != nil {
			return err
		}
		out, err = s.issueHost(ctx, q, pub, h.ID, "ENROLL", nil)
		return err
	})
	return out, err
}

// RenewHost issues a certificate for a new key to the host behind its
// current certificate; the old one is accepted for the grace more.
func (s *Service) RenewHost(ctx context.Context, id HostIdentity, pub ed25519.PublicKey) (HostCertificate, error) {
	var out HostCertificate
	err := s.pool.InGlobalTx(ctx, db.GlobalHosting, func(ctx context.Context, tx db.GlobalTx) error {
		q := dbq.New(tx)
		old, err := q.LockHostingHostCert(ctx, id.Cert)
		if err != nil || old.HostID != id.Host || old.State != "ACTIVE" {
			return ErrHostRenewal
		}
		if out, err = s.issueHost(ctx, q, pub, id.Host, "RENEW", &old.ID); err != nil {
			return err
		}
		if n, err := q.SupersedeHostingHostCert(ctx, old.ID); err != nil {
			return err
		} else if n != 1 {
			return ErrHostRenewal
		}
		return nil
	})
	return out, err
}

func (s *Service) issueHost(ctx context.Context, q *dbq.Queries, pub ed25519.PublicKey, host ids.UUID, via string, previous *ids.UUID) (HostCertificate, error) {
	id := HostIdentity{Host: host, Cert: ids.NewV7()}
	iss, err := s.ca.IssueHost(pub, id, s.clk.Now())
	if err != nil {
		return HostCertificate{}, err
	}
	err = q.InsertHostingHostCert(ctx, dbq.InsertHostingHostCertParams{
		ID: id.Cert, HostID: host, Serial: iss.Serial, KeyThumbprint: iss.Thumbprint, IssuedVia: via, PreviousID: previous,
		NotBefore: iss.NotBefore, NotAfter: iss.NotAfter,
	})
	return HostCertificate{Certificate: iss.DER, CACertificate: s.ca.Certificate(), Identity: id}, err
}
