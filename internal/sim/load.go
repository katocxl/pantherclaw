// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// loadConfig drives `pantherclaw-sim load`: an open-loop, constant-arrival
// load (requests start on schedule whatever the latency, so slow responses
// are measured instead of hidden by coordinated omission).
type loadConfig struct {
	Gateway string
	// Connection is the payments connection's name, the first path segment
	// at the gateway (G0 M6).
	Connection string
	// Key signs every request (PAP-1 §4); Token returns the workload token
	// and Run is the run the requests belong to.
	Key         ed25519.PrivateKey
	Token       func() string
	Run         string
	Rate        int
	Duration    time.Duration
	Warmup      time.Duration
	Amount      string
	MaxInFlight int
	// Unique refunds a distinct (charge, amount) pair per request; Tag
	// names this run's charges.
	Unique bool
	Tag    string
	// MCP sends each refund as a 2026-07-28 MCP tools/call (create_refund)
	// to /mcp/{connection} instead of the HTTP route (G0 M15 D15).
	MCP bool
}

// requests is how many requests the run sends, warm-up included.
func (c loadConfig) requests() int {
	return int((c.Warmup + c.Duration) / (time.Second / time.Duration(c.Rate)))
}

// sample is one request's measurements, in milliseconds.
type sample struct {
	status    int
	total     float64 // client-observed, request start to full response
	authz     float64 // gateway's Authorize call
	overhead  float64 // gateway total minus target time
	gwTotal   float64
	ok        bool
	afterWarm bool
	// toolError: an MCP answer with isError true.
	toolError bool
}

// Summary is the machine-readable result.
type Summary struct {
	Rate       int                           `json:"target_rps"`
	Achieved   float64                       `json:"achieved_rps"`
	Duration   string                        `json:"duration"`
	Requests   int                           `json:"requests"`
	Dropped    int64                         `json:"dropped"`
	Errors     int                           `json:"transport_errors"`
	Statuses   map[string]int                `json:"statuses"`
	Percentile map[string]map[string]float64 `json:"percentiles_ms"`
}

func runLoad(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	ctx, cancel := context.WithCancel(ctx) // also stops the token renewal
	defer cancel()
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c loadConfig
	fs.StringVar(&c.Gateway, "gateway", "http://127.0.0.1:8090", "gateway base URL")
	fs.StringVar(&c.Connection, "connection", "payments", "the payments connection's name (dev seed --target-url creates \"payments\")")
	workloadFile := fs.String("workload-file", "", "workload key file (from `pantherclaw-server dev seed --workload-out`)")
	tokenFile := fs.String("token-file", "", "use this workload token instead of asking the key file's server")
	fs.StringVar(&c.Run, "run", "", "run id (default: the key file's run)")
	fs.IntVar(&c.Rate, "rate", 1000, "requests per second")
	fs.DurationVar(&c.Duration, "duration", 30*time.Second, "measured duration (after warm-up)")
	fs.DurationVar(&c.Warmup, "warmup", 5*time.Second, "warm-up excluded from the results")
	fs.StringVar(&c.Amount, "amount", "1.00", "refund amount per request (USD)")
	fs.IntVar(&c.MaxInFlight, "max-in-flight", 2048, "requests in flight before new ones are dropped (and counted)")
	fs.BoolVar(&c.Unique, "unique", false, "refund a distinct charge and amount per request (identical refunds are parked since M4); ignores --amount")
	fs.BoolVar(&c.MCP, "mcp", false, "send MCP tools/call (create_refund, 2026-07-28) to /mcp/{connection} instead of the HTTP route")
	factsKey := fs.String("facts-key-file", "", "report the charges as refundable first, with this fact provider API key (from `dev seed --facts-key-out`)")
	out := fs.String("out", "", "also write the JSON summary to this file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *workloadFile == "" || c.Rate < 1 || c.Rate > 20000 || c.Duration <= 0 || c.MaxInFlight < 1 {
		fs.Usage()
		return flag.ErrHelp
	}
	kf, err := workloadclient.ReadKeyFile(*workloadFile)
	if err != nil {
		return err
	}
	if c.Key, err = kf.Key(); err != nil {
		return err
	}
	if c.Run == "" {
		c.Run = kf.RunID
	}
	if c.Token, err = workloadTokens(ctx, kf, *tokenFile); err != nil {
		return err
	}
	c.Tag = runTag(time.Now())
	if *factsKey != "" {
		facts, err := newFactReporter(kf.Server, *factsKey, chargesFor(c.Tag, c.requests(), c.Unique))
		if err != nil {
			return err
		}
		if err := facts.report(ctx); err != nil {
			return err
		}
		go facts.refresh(ctx, func(err error) { _, _ = fmt.Fprintln(stderr, "sim load:", err) })
	}
	s, err := drive(ctx, c)
	if err != nil {
		return err
	}
	printSummary(stdout, s)
	if *out != "" {
		b, err := json.Marshal(s, json.Deterministic(true))
		if err != nil {
			return err
		}
		return os.WriteFile(*out, b, 0o600)
	}
	return nil
}

func drive(ctx context.Context, c loadConfig) (Summary, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &workloadclient.Transport{Key: c.Key, Token: c.Token, Base: &http.Transport{
			Proxy: nil, MaxIdleConns: c.MaxInFlight, MaxIdleConnsPerHost: c.MaxInFlight, IdleConnTimeout: 90 * time.Second,
		}},
	}
	run := c.Run
	interval := time.Second / time.Duration(c.Rate)
	total := c.requests()
	start := time.Now()
	warmEnd := start.Add(c.Warmup)

	var (
		mu       sync.Mutex
		samples  = make([]sample, 0, total)
		wg       sync.WaitGroup
		inFlight atomic.Int64
		dropped  atomic.Int64
	)
	for i := range total {
		at := start.Add(time.Duration(i) * interval)
		if d := time.Until(at); d > 0 {
			select {
			case <-ctx.Done():
				wg.Wait()
				return Summary{}, ctx.Err()
			case <-time.After(d):
			}
		}
		if inFlight.Load() >= int64(c.MaxInFlight) {
			dropped.Add(1)
			continue
		}
		inFlight.Add(1)
		charge, amount := "ch_load1", c.Amount
		if c.Unique {
			charge, amount = uniqueRefund(c.Tag, i)
		}
		body := `{"charge":"` + charge + `","amount":"` + amount + `","currency":"USD","reason":"duplicate"}`
		wg.Go(func() {
			defer inFlight.Add(-1)
			s := one(ctx, client, c, run, body)
			s.afterWarm = at.After(warmEnd)
			mu.Lock()
			samples = append(samples, s)
			mu.Unlock()
		})
	}
	wg.Wait()
	elapsed := time.Since(warmEnd)
	return summarize(c, samples, dropped.Load(), elapsed), nil
}

func one(ctx context.Context, client *http.Client, c loadConfig, run, body string) sample {
	if c.MCP {
		return oneMCP(ctx, client, c, run, body)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.Gateway, "/")+"/"+c.Connection+"/v1/refunds", strings.NewReader(body))
	if err != nil {
		return sample{}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PAP-Run-Id", run)
	req.Header.Set("PC-Action-Id", ids.NewV7().String())
	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return sample{}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	s := sample{status: resp.StatusCode, total: ms(time.Since(t0)), ok: true}
	timing := serverTiming(resp.Header.Values("Server-Timing"))
	s.authz, s.gwTotal = timing["authz"], timing["total"]
	if s.gwTotal > 0 {
		s.overhead = s.gwTotal - timing["target"]
	}
	return s
}

// serverTiming parses `name;dur=1.234` entries.
func serverTiming(values []string) map[string]float64 {
	out := map[string]float64{}
	for _, v := range values {
		for entry := range strings.SplitSeq(v, ",") {
			name, dur, ok := strings.Cut(strings.TrimSpace(entry), ";dur=")
			if !ok {
				continue
			}
			if f, err := strconv.ParseFloat(dur, 64); err == nil {
				out[name] = f
			}
		}
	}
	return out
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func summarize(c loadConfig, all []sample, dropped int64, elapsed time.Duration) Summary {
	s := Summary{Rate: c.Rate, Duration: c.Duration.String(), Dropped: dropped, Statuses: map[string]int{}, Percentile: map[string]map[string]float64{}}
	var total, authz, overhead []float64
	for _, x := range all {
		if !x.afterWarm {
			continue
		}
		s.Requests++
		if !x.ok {
			s.Errors++
			continue
		}
		key := strconv.Itoa(x.status)
		if x.toolError {
			key += "/tool_error"
		}
		s.Statuses[key]++
		total = append(total, x.total)
		if x.status == http.StatusOK {
			authz = append(authz, x.authz)
			overhead = append(overhead, x.overhead)
		}
	}
	if elapsed > 0 {
		s.Achieved = float64(s.Requests) / elapsed.Seconds()
	}
	for name, xs := range map[string][]float64{"client_total": total, "authorize": authz, "gateway_overhead": overhead} {
		s.Percentile[name] = percentiles(xs)
	}
	return s
}

func percentiles(xs []float64) map[string]float64 {
	if len(xs) == 0 {
		return map[string]float64{}
	}
	slices.Sort(xs)
	at := func(p float64) float64 { return xs[min(len(xs)-1, int(p*float64(len(xs))))] }
	return map[string]float64{"p50": at(0.50), "p95": at(0.95), "p99": at(0.99), "max": xs[len(xs)-1]}
}

func printSummary(w io.Writer, s Summary) {
	_, _ = fmt.Fprintf(w, "SIMULATED load: target %d rps for %s, achieved %.0f rps; %d requests, %d dropped, %d transport errors\n",
		s.Rate, s.Duration, s.Achieved, s.Requests, s.Dropped, s.Errors)
	_, _ = fmt.Fprintf(w, "statuses: %v\n", s.Statuses)
	_, _ = fmt.Fprintf(w, "%-18s %9s %9s %9s %9s\n", "metric (ms)", "p50", "p95", "p99", "max")
	for _, name := range []string{"authorize", "gateway_overhead", "client_total"} {
		p := s.Percentile[name]
		_, _ = fmt.Fprintf(w, "%-18s %9.2f %9.2f %9.2f %9.2f\n", name, p["p50"], p["p95"], p["p99"], p["max"])
	}
}

// oneMCP sends one refund as an MCP tools/call, as pclaw mcp proxy does
// for a 2026-07-28 client, without an action id, so the gateway looks up
// a hold first (G0 M15 D14). Only the client's time is measured: the MCP
// face sends no Server-Timing.
func oneMCP(ctx context.Context, client *http.Client, c loadConfig, run, args string) sample {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_refund","arguments":` + args +
		`,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.Gateway, "/")+"/mcp/"+c.Connection, strings.NewReader(body))
	if err != nil {
		return sample{}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("PAP-Run-Id", run)
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "create_refund")
	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return sample{}
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return sample{status: resp.StatusCode, total: ms(time.Since(t0)), ok: true, toolError: strings.Contains(string(b), `"isError":true`)}
}
