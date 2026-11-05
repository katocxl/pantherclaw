// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/intel/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Feed import (G0 M38 D1103; HR-817). A signed feed is verified against the
// intel roots, refused when it is older than the accepted one or another
// feed under the same version, and its indicators replace the current set
// in one global transaction. Every org that consumes gets a new gateway
// configuration, so its gateways' content scan matches the new set.

// Import sources.
const (
	SourceImport = "IMPORT"
	SourceFetch  = "FETCH"
)

// Import errors, by stable code.
var (
	ErrFeedSignature = pcerr.New(pcerr.InvalidArgument, "INTEL_FEED_SIGNATURE", "the feed does not verify against the intel roots")
	ErrFeedExpired   = pcerr.New(pcerr.FailedPrecondition, "INTEL_FEED_EXPIRED", "the feed is past its expiry")
	ErrFeedRollback  = pcerr.New(pcerr.FailedPrecondition, "INTEL_FEED_ROLLBACK",
		"the feed is older than the accepted one, or another feed under the same version")
	ErrFeedNoRoot = pcerr.New(pcerr.FailedPrecondition, "INTEL_NO_ROOT", "no intel root key is trusted by this build")
	ErrFeedFormat = pcerr.New(pcerr.InvalidArgument, "INTEL_FEED_FORMAT", "the feed's payload breaks its format")
)

// codeOf maps a domain verification error to its stable error.
func codeOf(err error) error {
	switch {
	case errors.Is(err, domain.ErrNoRoot):
		return fmt.Errorf("%w: %w", ErrFeedNoRoot, err)
	case errors.Is(err, domain.ErrExpired):
		return fmt.Errorf("%w: %w", ErrFeedExpired, err)
	case errors.Is(err, domain.ErrRollback):
		return fmt.Errorf("%w: %w", ErrFeedRollback, err)
	case errors.Is(err, domain.ErrFormat):
		return fmt.Errorf("%w: %w", ErrFeedFormat, err)
	}
	return fmt.Errorf("%w: %w", ErrFeedSignature, err)
}

// Importer imports feeds.
type Importer struct {
	Pool  *db.Pool
	Roots domain.Roots
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	Log *slog.Logger
}

// Imported is what an import did.
type Imported struct {
	Version    uint64
	KID        string
	Indicators int
	// Changed is false when the same feed was accepted before.
	Changed bool
	// Orgs is how many consuming orgs' gateways got a new configuration.
	Orgs int
}

func (im *Importer) now() time.Time {
	if im.Now != nil {
		return im.Now()
	}
	return time.Now()
}

func (im *Importer) log() *slog.Logger {
	if im.Log != nil {
		return im.Log
	}
	return slog.Default()
}

// Import verifies doc and, unless it is the feed accepted already, replaces
// the current indicators with its own.
func (im *Importer) Import(ctx context.Context, doc, source string) (Imported, error) {
	v, err := domain.Verify(doc, im.Roots, im.now())
	if err != nil {
		return Imported{}, codeOf(err)
	}
	out := Imported{Version: v.Version, KID: v.KID, Indicators: len(v.Indicators)}
	err = im.Pool.InGlobalTx(ctx, db.GlobalIntel, func(ctx context.Context, tx db.GlobalTx) error {
		out.Changed = false
		q := dbq.New(tx)
		var last *domain.State
		switch row, err := q.LockIntelState(ctx); {
		case err == nil:
			last = &domain.State{Version: uint64(row.FeedVersion), Digest: row.FeedDigest} //nolint:gosec // G115: the column is >= 1
		case !db.IsNoRows(err):
			return err
		}
		if err := domain.CheckAdvance(last, v); err != nil {
			return codeOf(err)
		}
		if last != nil && last.Version == v.Version {
			return nil // the same feed again
		}
		if err := q.DeleteIntelIndicators(ctx); err != nil {
			return err
		}
		for _, x := range v.Indicators {
			if err := insert(ctx, q, x, v.Version); err != nil {
				return err
			}
		}
		out.Changed = true
		return q.PutIntelState(ctx, dbq.PutIntelStateParams{
			FeedVersion: int64(v.Version), FeedDigest: v.Digest, Kid: v.KID, //nolint:gosec // G115: a feed version fits
			IssuedAt: v.Issued, ExpiresAt: v.Expiry, Source: source,
		})
	}, db.Serializable())
	if err != nil {
		return Imported{}, err
	}
	if !out.Changed {
		return out, nil
	}
	im.log().InfoContext(ctx, "intel.feed_imported", slog.Uint64("version", v.Version), slog.String("kid", v.KID),
		slog.Int("indicators", len(v.Indicators)), slog.String("source", source))
	n, err := im.refreshGateways(ctx)
	out.Orgs = n
	if err != nil {
		// The feed stands; gateways pick it up at their next configuration.
		im.log().WarnContext(ctx, "intel.gateways_not_refreshed", pclog.Err(err))
	}
	return out, nil
}

func insert(ctx context.Context, q *dbq.Queries, x domain.Indicator, version uint64) error {
	day, err := time.Parse(time.DateOnly, x.FirstSeen)
	if err != nil {
		return err
	}
	var sum *string
	if x.SHA256 != "" {
		s := x.SHA256
		sum = &s
	}
	shingles, techniques := x.Shingles, domain.SortedTechniques(x.Techniques)
	if shingles == nil {
		shingles = []string{}
	}
	if techniques == nil {
		techniques = []string{}
	}
	return q.InsertIntelIndicator(ctx, dbq.InsertIntelIndicatorParams{
		ID: x.ID, Kind: string(x.Kind), Sha256: sum, Shingles: shingles, Severity: string(x.Severity),
		Techniques: techniques, FirstSeen: pgtype.Date{Time: day, Valid: true}, Summary: x.Summary,
		FeedVersion: int64(version), //nolint:gosec // G115: a feed version fits
	})
}

// refreshGateways gives every consuming org's gateways a new configuration.
func (im *Importer) refreshGateways(ctx context.Context) (int, error) {
	n := 0
	err := im.Pool.CrossOrgPages(ctx, db.ListActiveOrgs, 500, func(page []db.OrgRef) error {
		for _, o := range page {
			err := im.Pool.InTenantTx(ctx, o.Org, func(ctx context.Context, tx db.TenantTx) error {
				q := dbq.New(tx)
				st, err := ReadSettings(ctx, q, o.Org)
				if err != nil || !st.Consume.Consumes() {
					return err
				}
				n++
				return q.BumpOrgGateways(ctx, o.Org)
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return n, err
}

// Fetch (D1103): with intel.feed_url set, a daily job fetches the feed
// through the egress client (https only, no redirects, bounded) and imports
// it. An empty URL is off.

// MaxFetchBytes bounds a fetched feed.
const MaxFetchBytes = domain.MaxFeedBytes

// Doer sends one request.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Fetcher fetches and imports the feed.
type Fetcher struct {
	URL      string
	HTTP     Doer
	Importer *Importer
}

// CheckFeedURL reports whether u may be the feed URL: https with a host.
func CheckFeedURL(u string) error {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.Host == "" || p.User != nil {
		return fmt.Errorf("intel.feed_url %q is not an https URL", u)
	}
	return nil
}

// Run fetches the feed once and imports it.
func (f *Fetcher) Run(ctx context.Context) error {
	if f.URL == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/jose")
	res, err := f.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("intel: fetch: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("intel: fetch: HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, MaxFetchBytes+1))
	if err != nil {
		return fmt.Errorf("intel: fetch: %w", err)
	}
	if len(body) > MaxFetchBytes {
		return fmt.Errorf("intel: fetch: the feed is over %d bytes", MaxFetchBytes)
	}
	_, err = f.Importer.Import(ctx, string(body), SourceFetch)
	return err
}
