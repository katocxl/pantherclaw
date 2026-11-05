// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchoring

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TUFRefreshInterval is how often the TUF-fetched trust material is
// refreshed (G0 M35 D1040: daily).
const TUFRefreshInterval = 24 * time.Hour

// ErrNoTUFTrust reports that no TUF-verified Rekor key and TSA chain have
// been loaded yet: nothing is submitted until they are (fail closed).
var ErrNoTUFTrust = errors.New("anchoring: no TUF-verified trust material yet")

// TUFTrust holds the configured Rekor log's key and the timestamp
// authority's chain as Sigstore's trusted_root.json, fetched and verified
// through TUF, states them (evidence.anchoring.trust: tuf; G0 M35 D1040,
// HR-780). A refresh that fails keeps the material it had.
type TUFTrust struct {
	// Fetch returns a TUF-verified trusted_root.json.
	Fetch func(ctx context.Context) ([]byte, error)
	// RekorOrigin is the configured log's checkpoint origin; TSAURL is the
	// configured authority's URL.
	RekorOrigin string
	TSAURL      string
	Pool        *db.Pool
	Log         *slog.Logger

	cur atomic.Pointer[tufState]
}

type tufState struct {
	log anchor.Log
	tsa *anchor.TSAVerifier
	at  time.Time
}

func (t *TUFTrust) log() *slog.Logger {
	if t.Log == nil {
		return pclog.Discard()
	}
	return t.Log
}

// current returns the loaded log key and TSA verifier.
func (t *TUFTrust) current() (anchor.Log, *anchor.TSAVerifier, bool) {
	s := t.cur.Load()
	if s == nil {
		return anchor.Log{}, nil, false
	}
	return s.log, s.tsa, true
}

// load makes sure the service has TUF-verified trust material no older
// than a refresh interval: every worker process refreshes its own when the
// daily job ran elsewhere. It reports whether material is loaded.
func (t *TUFTrust) load(ctx context.Context) bool {
	if s := t.cur.Load(); s != nil && time.Since(s.at) < TUFRefreshInterval {
		return true
	}
	if err := t.Refresh(ctx); err != nil {
		t.log().ErrorContext(ctx, "evidence.tuf_audit_failed", slog.String("error", err.Error()))
	}
	_, _, ok := t.current()
	return ok
}

// trustedRootURIs reads the timestamp authorities' URIs, in order.
type trustedRootURIs struct {
	TimestampAuthorities []struct {
		URI string `json:"uri"`
	} `json:"timestampAuthorities"`
}

// Refresh fetches the trusted root through TUF and picks the configured log
// (by origin) and authority (by URL). Any failure keeps what was loaded and
// is recorded in the platform audit.
func (t *TUFTrust) Refresh(ctx context.Context) error {
	err := t.refresh(ctx)
	if err == nil {
		return nil
	}
	t.log().WarnContext(ctx, "evidence.tuf_refresh_failed", slog.String("cause", err.Error()))
	if t.Pool == nil {
		return nil
	}
	return t.Pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: auditkind.EvidenceTUFRefreshFailed, Actor: Actor, Outcome: audit.Failure, ReasonCode: "TUF_REFRESH_FAILED",
			Object: &audit.Object{Type: "sigstore_trusted_root", ID: t.RekorOrigin},
		})
		return err
	})
}

func (t *TUFTrust) refresh(ctx context.Context) error {
	raw, err := t.Fetch(ctx)
	if err != nil {
		return err
	}
	root, err := bundle.ParseSigstoreRoot(raw)
	if err != nil {
		return err
	}
	var uris trustedRootURIs
	if err := json.Unmarshal(raw, &uris); err != nil {
		return fmt.Errorf("anchoring: trusted root: %w", err)
	}
	var s tufState
	found := false
	for _, l := range root.Logs {
		if l.Origin == t.RekorOrigin {
			s.log, found = l, true
			break
		}
	}
	if !found {
		return fmt.Errorf("anchoring: the trusted root has no log of origin %q", t.RekorOrigin)
	}
	if len(uris.TimestampAuthorities) != len(root.TSAs) {
		return errors.New("anchoring: the trusted root's timestamp authorities do not parse")
	}
	want := strings.TrimSuffix(t.TSAURL, "/")
	for i, a := range uris.TimestampAuthorities {
		if strings.TrimSuffix(a.URI, "/") == want || strings.HasPrefix(want, strings.TrimSuffix(a.URI, "/")+"/") {
			s.tsa = root.TSAs[i] // the newest matching one wins
		}
	}
	if s.tsa == nil {
		return fmt.Errorf("anchoring: the trusted root has no timestamp authority at %q", t.TSAURL)
	}
	s.at = time.Now().UTC()
	t.cur.Store(&s)
	t.log().InfoContext(ctx, "evidence.tuf_refreshed", slog.String("log", s.log.Origin))
	return nil
}

// TUFRefreshArgs asks for one refresh. It carries no data (HR-056).
type TUFRefreshArgs struct{}

// Kind implements river.JobArgs.
func (TUFRefreshArgs) Kind() string { return "evidence.tuf_refresh" }

// InsertOpts keeps one refresh queued or running at a time.
func (TUFRefreshArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type tufWorker struct {
	river.WorkerDefaults[TUFRefreshArgs]
	trust *TUFTrust
}

func (w *tufWorker) Timeout(*river.Job[TUFRefreshArgs]) time.Duration { return 5 * time.Minute }

func (w *tufWorker) Work(ctx context.Context, _ *river.Job[TUFRefreshArgs]) error {
	return w.trust.Refresh(ctx)
}

// RegisterTUF adds the refresh worker to reg and returns its daily schedule,
// which also runs at start.
func RegisterTUF(reg *jobs.Registry, t *TUFTrust) ([]*river.PeriodicJob, error) {
	if err := jobs.Register[TUFRefreshArgs](reg, &tufWorker{trust: t}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(TUFRefreshInterval),
			func() (river.JobArgs, *river.InsertOpts) { return TUFRefreshArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
	}, nil
}
