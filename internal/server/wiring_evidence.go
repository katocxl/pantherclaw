// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/evidence/adapters/evidencerpc"
	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	"github.com/katocxl/pantherclaw/internal/evidence/anchoring"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	"github.com/katocxl/pantherclaw/internal/evidence/keydocs"
	"github.com/katocxl/pantherclaw/internal/evidence/packbuild"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// mountEvidenceKeys serves evidence-keys.json and revoked-keys.json
// (PAP-1 §11, G0 M7): public, from the keystore, without private material.
func mountEvidenceKeys(mux *http.ServeMux, d apiDeps) {
	pool := d.pool
	keydocs.New(func(ctx context.Context, ps []keys.Purpose) ([]keystore.PublishedKey, error) {
		return keystore.PublishedKeys(ctx, pool, ps)
	}, d.publicURL, d.logOrigin, clock.System{}, d.log).Mount(mux)
}

// registerEvidenceWorkers adds the checkpoint and daily verification jobs
// (G0 M7 design decision 8, HR-194) and returns their schedules.
func registerEvidenceWorkers(reg *jobs.Registry, cfg *Config, pool *db.Pool, keyReg *keys.Registry,
	notify checkpoints.Notifier, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	svc := &checkpoints.Service{
		Pool: pool, Keys: keyReg, LogOrigin: cfg.logOrigin(), Cosign: cfg.Evidence.MLDSACosign, Notify: notify, Log: log,
	}
	if err := checkpoints.Register(reg, svc); err != nil {
		return nil, err
	}
	if err := packbuild.Register(reg, newPackBuilder(cfg, pool, keyReg, log)); err != nil {
		return nil, err
	}
	periodic := append(checkpoints.PeriodicJobs(cfg.checkpointInterval()), packbuild.PeriodicJobs()...)
	if !cfg.Evidence.Anchoring.Enabled {
		return periodic, nil
	}
	anchors, err := newAnchoring(cfg, pool, keyReg, log)
	if err != nil {
		return nil, err
	}
	if err := anchoring.Register(reg, anchors); err != nil {
		return nil, err
	}
	return append(periodic, anchoring.PeriodicJobs()...), nil
}

// Request timeouts of the anchoring clients: Rekor v2 answers once a
// checkpoint covers the entry.
const (
	rekorRequestTimeout = 60 * time.Second
	tsaRequestTimeout   = 20 * time.Second
)

// newAnchoring builds the anchoring job from evidence.anchoring (design
// decision 12, HR-195): the Rekor v2 and RFC 3161 clients on the M1 egress
// client, each limited to its configured host, verifying against the
// configured log key and origin and the authority's chain.
func newAnchoring(cfg *Config, pool *db.Pool, keyReg *keys.Registry, log *slog.Logger) (*anchoring.Service, error) {
	a := cfg.Evidence.Anchoring
	rawKey, err := os.ReadFile(a.Rekor.PublicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("evidence.anchoring.rekor.public_key_file: %w", err)
	}
	der := rawKey
	if b, _ := pem.Decode(rawKey); b != nil {
		if b.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("evidence.anchoring.rekor.public_key_file: a PEM %q block, want PUBLIC KEY", b.Type)
		}
		der = b.Bytes
	}
	logKey, err := anchor.NewLog(a.rekorOrigin(), der)
	if err != nil {
		return nil, fmt.Errorf("evidence.anchoring.rekor.public_key_file: %w", err)
	}
	pemChain, err := os.ReadFile(a.TSA.CertChainFile)
	if err != nil {
		return nil, fmt.Errorf("evidence.anchoring.tsa.cert_chain_file: %w", err)
	}
	chain, err := anchor.ParseCertificateChain(pemChain)
	if err != nil {
		return nil, fmt.Errorf("evidence.anchoring.tsa.cert_chain_file: %w", err)
	}
	tsaVerifier, err := anchor.NewTSAVerifier(chain)
	if err != nil {
		return nil, fmt.Errorf("evidence.anchoring.tsa.cert_chain_file: %w", err)
	}
	rekorHTTP, err := anchoring.EgressDoer(a.Rekor.URL, rekorRequestTimeout)
	if err != nil {
		return nil, err
	}
	tsaHTTP, err := anchoring.EgressDoer(a.TSA.URL, tsaRequestTimeout)
	if err != nil {
		return nil, err
	}
	return &anchoring.Service{
		Pool: pool, Keys: keyReg, LogOrigin: cfg.logOrigin(), Interval: cfg.anchoringInterval(),
		Rekor: &anchor.RekorClient{URL: a.Rekor.URL, HTTP: rekorHTTP, Log: logKey},
		TSA:   &anchor.TSAClient{URL: a.TSA.URL, HTTP: tsaHTTP, Verifier: tsaVerifier},
		Log:   log,
	}, nil
}

// registerEvidence serves EvidenceService on the public API, with decision
// replay when the server can open sealed inputs, and evidence packs (their
// build job is enqueued in the creating transaction and runs in the worker).
func registerEvidence(rs *connect.Server, d apiDeps) error {
	svc := evapp.New(d.pool, d.logOrigin)
	if d.kp != nil {
		svc.WithReplay(replayEngine(d.pool, d.kp), clock.System{})
	}
	if d.billing != nil {
		insert, err := jobs.NewClient(d.pool, nil, jobs.Config{Logger: d.log}) // insert-only: enqueue in the creating transaction
		if err != nil {
			return err
		}
		svc.WithPacks(func(ctx context.Context, tx db.TenantTx, org ids.OrgID, pack ids.UUID) error {
			args, err := packbuild.NewBuildArgs(org, pack)
			if err != nil {
				return err
			}
			return jobs.InsertTx(ctx, insert, tx, args, nil)
		}, d.billing)
	}
	pantherclawv1connect.RegisterEvidenceServiceHandler(rs, evidencerpc.New(svc))
	return nil
}

// newPackBuilder builds evidence packs in the worker (design decision 15):
// signed with the evidence_packs key, co-signed with ML-DSA-65 when
// evidence.mldsa_cosign is on. Payload captures plug in when capture
// (migration 00073) is in; until then a pack that asks for them records the
// gap.
func newPackBuilder(cfg *Config, pool *db.Pool, keyReg *keys.Registry, log *slog.Logger) *packbuild.Service {
	return &packbuild.Service{
		Pool: pool, Keys: keyReg, LogOrigin: cfg.logOrigin(), Cosign: cfg.Evidence.MLDSACosign,
		Explorer: &txapp.Explorer{Pool: pool}, Bundles: evapp.New(pool, cfg.logOrigin()), Log: log,
	}
}
