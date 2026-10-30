// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/ed25519"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/hosting/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// ErrNotHosted: the calling gateway has no live hosted gateway record, so
// it gets no hosted server certificate.
var ErrNotHosted = pcerr.New(pcerr.NotFound, "HOSTED_GATEWAY_NOT_FOUND", "this gateway is not a PantherClaw-hosted gateway")

// ServerCertificate is a hosted gateway's agent-facing certificate.
type ServerCertificate struct {
	Certificate   []byte
	CACertificate []byte
	Hostname      string
}

// IssueServerCertificate issues the calling hosted gateway its 7-day
// agent-facing server certificate for pub (G0 M19 D210), over its own mTLS
// identity only. Its one name, <slug>.gw.<host domain>, comes from the
// org's hosted gateway record that names this gateway, never from the
// request: a gateway gets only its own org's name, and a gateway no live
// record names gets nothing. The caller must hold the certificate the
// provisioner's token enrolled, or a renewal of it (D219).
func (s *Service) IssueServerCertificate(ctx context.Context, id ca.Identity, pub ed25519.PublicKey) (ServerCertificate, error) {
	var h dbq.PcHostedGateway
	err := s.pool.InTenantTx(ctx, id.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		h, err = q.HostedGatewayOfGateway(ctx, id.Org, id.Gateway)
		if db.IsNoRows(err) || (err == nil && (h.HostID == nil || h.EnrolledCertID == nil)) {
			return ErrNotHosted
		} else if err != nil {
			return err
		}
		ok, err := q.CertDescendsFrom(ctx, *h.EnrolledCertID, id.Org, id.Cert)
		if err == nil && !ok {
			return ErrNotHosted
		}
		return err
	})
	if err != nil {
		return ServerCertificate{}, err
	}
	var host dbq.PcHostingHost
	if err := s.pool.InGlobalTx(ctx, db.GlobalHosting, func(ctx context.Context, tx db.GlobalTx) error {
		var err error
		host, err = dbq.New(tx).GetHostingHost(ctx, *h.HostID)
		return err
	}); err != nil {
		return ServerCertificate{}, err
	}
	name := domain.Hostname(h.Slug, host.Domain)
	iss, err := s.ca.IssueHostedServer(pub, name, s.clk.Now())
	if err != nil {
		return ServerCertificate{}, err
	}
	err = s.pool.InTenantTx(ctx, id.Org, func(ctx context.Context, tx db.TenantTx) error {
		return record(ctx, tx, gatewayActor(id), "hosted_gateway.server_certificate_issued", h.ID, map[string]string{
			"hostname": name, "key_thumbprint": iss.Thumbprint, "not_after": iss.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		})
	})
	return ServerCertificate{Certificate: iss.DER, CACertificate: s.ca.Certificate(), Hostname: name}, err
}

func gatewayActor(id ca.Identity) evdomain.Actor {
	return evdomain.Actor{Type: "gateway", ID: id.Gateway.String()}
}
