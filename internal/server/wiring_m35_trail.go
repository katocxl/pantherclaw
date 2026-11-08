// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	"github.com/katocxl/pantherclaw/internal/evidence/anchoring"
	"github.com/katocxl/pantherclaw/internal/evidence/globallog"
	"github.com/katocxl/pantherclaw/internal/evidence/receiptsig"
	"github.com/katocxl/pantherclaw/internal/evidence/sigstoretuf"
	"github.com/katocxl/pantherclaw/internal/evidence/witness"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// Trail crypto wiring (G0 M35 D1040–D1042): the Sigstore TUF client for
// anchoring, the deployment-wide root log and its witnesses, and the
// ML-DSA-65 co-signature on receipts.

// Request timeouts of the Trail clients.
const (
	tufRequestTimeout     = 30 * time.Second
	witnessRequestTimeout = 30 * time.Second
)

// receiptsSigner returns the receipts signer: the receipts key's, and with
// evidence.mldsa_cosign on (Enterprise, never in FIPS mode) also the
// receipts_pq key's co-signature, PAP-1 sigs[] (D1042, HR-784).
func receiptsSigner(cosign bool, reg *keys.Registry, receipts receiptsig.JWSSigner) receiptsig.JWSSigner {
	if !cosign {
		return receipts
	}
	return &receiptsig.Signer{Next: receipts, Keys: reg}
}

// newTUFAnchoring builds the anchoring job for evidence.anchoring.trust
// "tuf" (D1040, HR-780): the Rekor v2 and RFC 3161 clients as with files,
// but the log's key and the authority's chain come from Sigstore's
// trusted_root.json, fetched through TUF by the egress client and refreshed
// daily. Until a refresh succeeds nothing is submitted.
func newTUFAnchoring(cfg *Config, pool *db.Pool, keyReg *keys.Registry, log *slog.Logger) (*anchoring.Service, error) {
	a := cfg.Evidence.Anchoring
	rekorHTTP, err := anchoring.EgressDoer(a.Rekor.URL, rekorRequestTimeout)
	if err != nil {
		return nil, err
	}
	tsaHTTP, err := anchoring.EgressDoer(a.TSA.URL, tsaRequestTimeout)
	if err != nil {
		return nil, err
	}
	client := &sigstoretuf.Client{
		Repository: a.TUF.Repository, CacheDir: a.TUF.CacheDir,
		HTTP: httpx.NewEgressClient(httpx.EgressConfig{Timeout: tufRequestTimeout}),
	}
	trust := &anchoring.TUFTrust{
		Fetch: func(ctx context.Context) ([]byte, error) {
			m, err := client.Fetch(ctx)
			return m.TrustedRoot, err
		},
		RekorOrigin: a.rekorOrigin(), TSAURL: a.TSA.URL, Pool: pool, Log: log,
	}
	return &anchoring.Service{
		Pool: pool, Keys: keyReg, LogOrigin: cfg.logOrigin(), Interval: cfg.anchoringInterval(),
		Rekor: &anchor.RekorClient{URL: a.Rekor.URL, HTTP: rekorHTTP},
		TSA:   &anchor.TSAClient{URL: a.TSA.URL, HTTP: tsaHTTP},
		Log:   log, TUF: trust,
	}, nil
}

// newGlobalLog builds the root log's job and its witness clients (D1041).
func newGlobalLog(cfg *Config, pool *db.Pool, keyReg *keys.Registry, log *slog.Logger) (*globallog.Service, error) {
	svc := &globallog.Service{
		Pool: pool, Keys: keyReg, LogOrigin: cfg.logOrigin(), Threshold: cfg.witnessThreshold(), Log: log,
	}
	for _, w := range cfg.Evidence.Witnesses {
		v, err := witness.ParseVKey(w.VKey)
		if err != nil {
			return nil, fmt.Errorf("evidence.witnesses %s: %w", w.Name, err)
		}
		doer, err := anchoring.EgressDoer(w.URL, witnessRequestTimeout)
		if err != nil {
			return nil, fmt.Errorf("evidence.witnesses %s: %w", w.Name, err)
		}
		svc.Witnesses = append(svc.Witnesses, &witness.Client{Name: w.Name, URL: w.URL, Key: v, HTTP: doer})
	}
	return svc, nil
}

// registerTrailWorkers adds, with anchoring on, the daily TUF refresh (for
// trust "tuf") and the root log's append-and-witness job, and returns their
// schedules.
func registerTrailWorkers(reg *jobs.Registry, cfg *Config, pool *db.Pool, keyReg *keys.Registry, anchors *anchoring.Service,
	log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	var periodic []*river.PeriodicJob
	if anchors.TUF != nil {
		p, err := anchoring.RegisterTUF(reg, anchors.TUF)
		if err != nil {
			return nil, err
		}
		periodic = append(periodic, p...)
	}
	gl, err := newGlobalLog(cfg, pool, keyReg, log)
	if err != nil {
		return nil, err
	}
	if err := globallog.Register(reg, gl); err != nil {
		return nil, err
	}
	return append(periodic, globallog.PeriodicJobs()...), nil
}

// mountGlobalCheckpoint serves the root log's newest checkpoint with its
// cosignatures (D1041): public, the log's size and root only.
func mountGlobalCheckpoint(mux *http.ServeMux, d apiDeps) {
	(&globallog.Handler{Pool: d.pool, Log: d.log}).Mount(mux)
}
