// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package browsercompare is the gateway's cloaking compare (G0 M33 D986,
// HR-759): after the hook face allowed a browser.navigate to a site an
// admin marked for comparing, the gateway fetches the page twice without
// cookies, once as the agent's browser asked for it and once with a plain
// user agent, and reports to the server only when the two differ: their
// text is less than half alike, or one answer is 2xx and the other is not.
// It never delays or changes a decision, stores no page content, and sees
// only header-based cloaking from the gateway's own network (PARTIAL,
// alert only).
package browsercompare

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Limits (D986).
const (
	// QueueSize is how many compares wait; more are dropped and counted.
	QueueSize = 32
	// Window is how often one (connection, host, path) is compared: once
	// per Window.
	Window = time.Hour
	// PerGateway is the most compares a gateway makes per Window.
	PerGateway = 60
	// MaxRedirects is how many redirects a fetch follows, each by hand.
	MaxRedirects = 3
	// MaxBody is the most of a page read.
	MaxBody = 1 << 20
	// FetchTimeout bounds one fetch, its redirects included.
	FetchTimeout = 10 * time.Second
	// reportTimeout bounds one report to the server.
	reportTimeout = 10 * time.Second
	// mismatchBelow is the similarity (permille) under which two pages differ.
	mismatchBelow = 500
)

// Metric names.
const (
	MetricDropped       = "pc_browser_compare_dropped_total"
	MetricFetchFailures = "pc_browser_compare_fetch_failures_total"
)

// Site is a site an admin marked for comparing.
type Site struct {
	Host              string
	IncludeSubdomains bool
}

// Listed reports whether host is one of sites: the host itself, or a
// subdomain of a site that includes its subdomains. An IP host never
// matches.
func Listed(host string, sites []Site) bool {
	if host == "" || strings.HasPrefix(host, "[") || isIPv4(host) {
		return false
	}
	for _, s := range sites {
		if host == s.Host || (s.IncludeSubdomains && strings.HasSuffix(host, "."+s.Host)) {
			return true
		}
	}
	return false
}

func isIPv4(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 || strings.Trim(p, "0123456789") != "" {
			return false
		}
	}
	return true
}

// Job is one allowed navigation to compare.
type Job struct {
	Connection, Run, Transaction string
	// URL is the normalized url of the action; Host its target.
	URL, Host string
	// UserAgent and AcceptLanguage are the agent browser's.
	UserAgent, AcceptLanguage string
}

// Report is a mismatch the server records (ReportPageCompare). It carries
// digests and sizes only, never page content (HR-750).
type Report struct {
	Connection, Run, Transaction, Host string
	// PathSHA256 is the hex sha256 of the escaped path, "?" and the query.
	PathSHA256               string
	AgentStatus, PlainStatus int32
	AgentBytes, PlainBytes   int64
	SimilarityPermille       int32
}

// Reporter sends a Report to the server.
type Reporter func(ctx context.Context, r Report) error

// Options configure a Comparer.
type Options struct {
	// PlainUserAgent is the gateway configuration's
	// browser_compare.plain_user_agent; the compare is off while it is
	// empty.
	PlainUserAgent string
	// Client is the egress client (httpx.NewEgressClient: HR-070..072);
	// it must not follow redirects or keep cookies.
	Client *http.Client
	Report Reporter
	Log    *slog.Logger
	// Meter records the metrics; nil uses the global meter provider.
	Meter metric.Meter
}

// Comparer runs compares in the background. A nil Comparer is off.
type Comparer struct {
	plainUA string
	client  *http.Client
	report  Reporter
	log     *slog.Logger
	queue   chan Job

	mu    sync.Mutex
	pages map[string]time.Time
	runs  []time.Time
	now   func() time.Time

	dropped, failures         atomic.Int64
	droppedMetric, failMetric metric.Int64Counter
}

// New returns a Comparer, or nil when the compare is off: no plain user
// agent is configured, or there is no client or reporter.
func New(o Options) *Comparer {
	if strings.TrimSpace(o.PlainUserAgent) == "" || o.Client == nil || o.Report == nil {
		return nil
	}
	if o.Log == nil {
		o.Log = pclog.Discard()
	}
	m := o.Meter
	if m == nil {
		m = otel.Meter("github.com/katocxl/pantherclaw/internal/gateway/browsercompare")
	}
	c := &Comparer{
		plainUA: o.PlainUserAgent, client: o.Client, report: o.Report, log: o.Log, queue: make(chan Job, QueueSize),
		pages: map[string]time.Time{}, now: time.Now,
	}
	c.droppedMetric, _ = m.Int64Counter(MetricDropped, metric.WithDescription("Browser compares dropped: the queue was full."))
	c.failMetric, _ = m.Int64Counter(MetricFetchFailures, metric.WithDescription("Browser compares not made: a fetch failed."))
	return c
}

// Enabled reports whether the compare is on.
func (c *Comparer) Enabled() bool { return c != nil }

// Dropped and FetchFailures are the counts since start.
func (c *Comparer) Dropped() int64       { return c.dropped.Load() }
func (c *Comparer) FetchFailures() int64 { return c.failures.Load() }

// pathDigest is the hex sha256 of u's escaped path, "?" and its raw query.
func pathDigest(u *url.URL) string {
	sum := sha256.Sum256([]byte(u.EscapedPath() + "?" + u.RawQuery))
	return hex.EncodeToString(sum[:])
}

// Enqueue queues j without blocking; it reports whether j was queued. A
// page compared within the hour, the gateway's hourly limit and a full
// queue (counted) all leave j out.
func (c *Comparer) Enqueue(j Job) bool {
	if c == nil {
		return false
	}
	u, err := url.Parse(j.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || j.Host == "" {
		return false
	}
	key := j.Connection + "\x00" + j.Host + "\x00" + pathDigest(u)
	now := c.now()
	c.mu.Lock()
	for k, at := range c.pages {
		if now.Sub(at) >= Window {
			delete(c.pages, k)
		}
	}
	keep := c.runs[:0]
	for _, at := range c.runs {
		if now.Sub(at) < Window {
			keep = append(keep, at)
		}
	}
	c.runs = keep
	if _, seen := c.pages[key]; seen || len(c.runs) >= PerGateway {
		c.mu.Unlock()
		return false
	}
	select {
	case c.queue <- j:
		c.pages[key] = now
		c.runs = append(c.runs, now)
		c.mu.Unlock()
		return true
	default:
		c.mu.Unlock()
		c.dropped.Add(1)
		c.droppedMetric.Add(context.Background(), 1)
		return false
	}
}

// Run makes the queued compares until ctx ends.
func (c *Comparer) Run(ctx context.Context) error {
	if c == nil {
		<-ctx.Done()
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case j := <-c.queue:
			c.compare(ctx, j)
		}
	}
}

// page is one fetch's result.
type page struct {
	status int32
	bytes  int64
	sig    Fingerprint
}

func (c *Comparer) compare(ctx context.Context, j Job) {
	u, err := url.Parse(j.URL)
	if err != nil {
		return
	}
	// The fetches send the address without its user info, query or
	// fragment (scheme://host/path), so nothing the agent's address carried
	// in them reaches the site again (D1221 L5, R-80); the report's path
	// digest is still the D986 one, of the path and the query.
	addr := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath}
	a, errA := c.fetch(ctx, addr, j.UserAgent, j.AcceptLanguage)
	b, errB := c.fetch(ctx, addr, c.plainUA, "")
	if errA != nil || errB != nil {
		c.failures.Add(1)
		c.failMetric.Add(ctx, 1)
		c.log.DebugContext(ctx, "gateway.browser_compare_fetch_failed", slog.String("connection_id", j.Connection),
			slog.String("host", j.Host), slog.Bool("agent_failed", errA != nil), slog.Bool("plain_failed", errB != nil))
		return
	}
	sim := Similarity(a.sig, b.sig)
	if sim >= mismatchBelow && ok2xx(a.status) == ok2xx(b.status) {
		return
	}
	r := Report{
		Connection: j.Connection, Run: j.Run, Transaction: j.Transaction, Host: j.Host, PathSHA256: pathDigest(u),
		AgentStatus: a.status, PlainStatus: b.status, AgentBytes: a.bytes, PlainBytes: b.bytes, SimilarityPermille: sim,
	}
	rctx, cancel := context.WithTimeout(ctx, reportTimeout)
	defer cancel()
	if err := c.report(rctx, r); err != nil {
		c.log.WarnContext(ctx, "gateway.browser_compare_report_failed", slog.String("connection_id", j.Connection),
			slog.String("host", j.Host), pclog.Err(err))
	}
}

func ok2xx(status int32) bool { return status >= 200 && status < 300 }

var (
	errRedirect = errors.New("browsercompare: redirect not followed")
	errStatus   = errors.New("browsercompare: status out of range")
)

// fetch GETs u without cookies, following up to MaxRedirects redirects by
// hand (http and https only, each hop a new request through the same
// client), and reads at most MaxBody of the final page.
func (c *Comparer) fetch(ctx context.Context, u *url.URL, userAgent, acceptLanguage string) (page, error) {
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	for hop := 0; ; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return page{}, err
		}
		req.Header.Set("Accept", "text/html")
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		if acceptLanguage != "" {
			req.Header.Set("Accept-Language", acceptLanguage)
		}
		res, err := c.client.Do(req)
		if err != nil {
			return page{}, err
		}
		if loc := res.Header.Get("Location"); isRedirect(res.StatusCode) && loc != "" && hop < MaxRedirects {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
			_ = res.Body.Close()
			next, err := u.Parse(loc)
			if err != nil || (next.Scheme != "http" && next.Scheme != "https") || next.Host == "" {
				return page{}, errRedirect
			}
			next.Fragment, next.RawFragment = "", ""
			u = next
			continue
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, MaxBody))
		_ = res.Body.Close()
		if err != nil {
			return page{}, err
		}
		if res.StatusCode < 100 || res.StatusCode > 599 {
			return page{}, errStatus
		}
		return page{status: int32(res.StatusCode), bytes: int64(len(body)), sig: Sign(Text(body))}, nil
	}
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}
