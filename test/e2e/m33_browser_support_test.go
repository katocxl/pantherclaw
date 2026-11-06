// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// The M33 browser stack (G0 M33): the refund stack with people, bob as an
// Approver, pc.browser and pc.computer with their hook connections
// "browser" and "computer" (dev seed --browser), the cloaking compare on,
// and a run on a grant that names every pc.browser and pc.computer
// operation. The agent's browser is played by `pclaw browser host`, the
// native messaging host the extension talks to (D979), driven over Chrome's
// framing; the computer-use wrappers' hook calls go through a second host
// configured for "computer".

// m33ExtensionID is the managed extension's id the host trusts.
const m33ExtensionID = "abcdefghijklmnopabcdefghijklmnop"

// m33PlainUA is the gateway's plain user agent for the cloaking compare.
const m33PlainUA = "PantherClaw-Compare/1 (e2e)"

// m33Bounds names every pc.browser and pc.computer operation: the grant is
// the run's; the site list and the takeover hold are the browser step's.
const m33Bounds = `{"operations": ["browser.navigate", "browser.form.submit", "browser.download", "browser.click",
	"browser.takeover", "computer.input"]}`

// browserStack is the M33 stack.
type browserStack struct {
	*stack
	b   *browser
	key *webauthntest.Authenticator
	// browserConn is the "browser" connection's id.
	browserConn string
}

func startBrowserStack(t *testing.T) *browserStack {
	t.Helper()
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, browser: true, browserCompareUA: m33PlainUA})
	_, b, key := approver(t, s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p})
	bs := &browserStack{stack: s, b: b, key: key}
	bs.browserConn = s.row(t, "SELECT id::text FROM pc.connections WHERE name = 'browser'")
	s.grantRun(t, m33Bounds, false)
	return bs
}

// listBrowserSites puts the org's browser sites in place, as an admin's confirmed
// additions leave them (the service and its second person are tested in
// internal/browsersites, HR-749), and waits for the gateway to serve the
// configuration that carries them.
func (s *stack) listBrowserSites(t *testing.T, sites ...m33Site) {
	t.Helper()
	for _, site := range sites {
		s.exec(t, `INSERT INTO pc.browser_sites (id, org_id, host, include_subdomains, compare, note, created_by)
			VALUES ($1, $2, $3, $4, $5, 'e2e', 'e2e')`, ids.NewV7(), s.org, site.host, site.subdomains, site.compare)
	}
	s.exec(t, "UPDATE pc.gateways SET config_version = config_version + 1 WHERE org_id = $1", s.org)
	s.waitConfig(t, s.configVersion(t, s.gatewayID(t)))
}

type m33Site struct {
	host                string
	subdomains, compare bool
}

// approveBrowser has bob approve the latest request of txn on its page
// with his key, and returns the request's state.
func (bs *browserStack) approveBrowser(t *testing.T, txn, operation string) string {
	t.Helper()
	req := bs.requestOf(t, txn)
	if req == "" {
		t.Fatalf("no approval request for %s", txn)
	}
	path := "/approvals/" + req
	if code, page := bs.b.page(t, path+"?org="+bs.org.String()); code != http.StatusOK || !strings.Contains(page, operation) {
		t.Fatalf("approval page of %s: %d", operation, code)
	}
	code, body := bs.b.post(t, path+"/approve-options", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("approve options: %d %v", code, body)
	}
	resp, err := bs.key.Assert(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	code, body = bs.b.post(t, path+"/approve", map[string]any{"ceremony": body["ceremony"], "response": jsontext.Value(resp)})
	if code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, body)
	}
	return string(body["state"])
}

// reasonOf is a transaction's reason code.
func (bs *browserStack) reasonOf(t *testing.T, txn string) string {
	t.Helper()
	return bs.row(t, "SELECT reason_code FROM pc.transactions WHERE id = $1", txn)
}

// ledgerCount counts the org's ledger entries of an audit kind.
func (bs *browserStack) ledgerCount(t *testing.T, kind string) int {
	t.Helper()
	var n int
	bs.query(t, "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2", []any{bs.org, "audit." + kind}, &n)
	return n
}

// waitLedger waits until the org has n ledger entries of the audit kind.
func (bs *browserStack) waitLedger(t *testing.T, kind string, n int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for bs.ledgerCount(t, kind) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d %s entries, want %d", bs.ledgerCount(t, kind), kind, n)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// txnCount counts the org's transactions.
func (bs *browserStack) txnCount(t *testing.T) int {
	t.Helper()
	var n int
	bs.query(t, "SELECT count(*)::int FROM pc.transactions WHERE org_id = $1", []any{bs.org}, &n)
	return n
}

// nativeHost is a running `pclaw browser host`, spoken to the way Chrome
// does: a uint32 little-endian length, then UTF-8 JSON.
type nativeHost struct {
	t    *testing.T
	in   *io.PipeWriter
	mu   sync.Mutex
	got  map[string]chan hostReply
	done chan int
	errs *strings.Builder
}

// hostReply is a decide or status answer.
type hostReply struct {
	ID            string `json:"id"`
	Decision      string `json:"decision"`
	Held          bool   `json:"held"`
	Code          string `json:"code"`
	Reason        string `json:"reason"`
	TransactionID string `json:"transaction_id"`
	OK            bool   `json:"ok"`
	Run           string `json:"run"`
}

// startHost writes the host configuration for connection (0600, as
// install-host does) and starts the host as Chrome does, with the caller's
// origin.
func (bs *browserStack) startHost(t *testing.T, connection string) *nativeHost {
	t.Helper()
	cfg, err := json.Marshal(map[string]any{
		"gateway": bs.gateway, "connection": connection, "key_file": bs.keyFile, "run": bs.run, "extension_ids": []string{m33ExtensionID},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "host-config.json")
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	h := &nativeHost{t: t, in: inW, got: map[string]chan hostReply{}, done: make(chan int, 1), errs: &strings.Builder{}}
	var errMu sync.Mutex
	stderr := browserWriterFunc(func(p []byte) (int, error) { errMu.Lock(); defer errMu.Unlock(); return h.errs.Write(p) })
	go func() {
		code := pclaw.Run(context.Background(), []string{"browser", "host", "--config", path, "chrome-extension://" + m33ExtensionID + "/"},
			outW, stderr, noEnv, pclaw.Options{Stdin: inR})
		_ = outW.Close()
		h.done <- code
	}()
	go func() {
		for {
			var n uint32
			if err := binary.Read(outR, binary.LittleEndian, &n); err != nil {
				return
			}
			raw := make([]byte, n)
			if _, err := io.ReadFull(outR, raw); err != nil {
				return
			}
			var r hostReply
			if err := json.Unmarshal(raw, &r, json.RejectUnknownMembers(false)); err != nil {
				continue
			}
			h.mu.Lock()
			ch := h.got[r.ID]
			h.mu.Unlock()
			if ch != nil {
				ch <- r
			}
		}
	}()
	t.Cleanup(func() {
		_ = inW.Close()
		select {
		case <-h.done:
		case <-time.After(10 * time.Second):
			t.Error("the browser host did not exit on stdin EOF")
		}
	})
	return h
}

type browserWriterFunc func([]byte) (int, error)

func (f browserWriterFunc) Write(p []byte) (int, error) { return f(p) }

// send writes one framed message and waits for its answer.
func (h *nativeHost) send(msg map[string]any) hostReply {
	h.t.Helper()
	id := ids.NewV7().String()
	msg["v"], msg["id"] = 1, id
	raw, err := json.Marshal(msg)
	if err != nil {
		h.t.Fatal(err)
	}
	ch := make(chan hostReply, 1)
	h.mu.Lock()
	h.got[id] = ch
	h.mu.Unlock()
	frame := binary.LittleEndian.AppendUint32(nil, uint32(len(raw)))
	if _, err := h.in.Write(append(frame, raw...)); err != nil {
		h.t.Fatal(err)
	}
	select {
	case r := <-ch:
		return r
	case <-time.After(30 * time.Second):
		h.t.Fatalf("no answer from the browser host to %s\n%s", raw, h.errs.String())
		return hostReply{}
	}
}

// decide asks the host about one browser or computer action.
func (h *nativeHost) decide(tool, action string, input map[string]any) hostReply {
	h.t.Helper()
	return h.send(map[string]any{"type": "decide", "tool": tool, "action_id": action, "input": input})
}

// navigate is the hold page's browser_navigate ask (D980).
func (h *nativeHost) navigate(action, call, url string) hostReply {
	h.t.Helper()
	return h.decide("browser_navigate", action, map[string]any{
		"url": url, "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0 e2e", "accept_language": "en-US", "call": call,
	})
}

// gatewayControl is a control client with the stack gateway's own identity:
// what the gateway itself sends the server.
func (bs *browserStack) gatewayControl(t *testing.T) *control.Client {
	t.Helper()
	cfg := bs.gatewayCfg
	id, err := gateway.LoadOrEnroll(context.Background(), &cfg, bs.gatewayEnroll, pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	return control.NewClient(id, "", cfg.Control.GatewayURL, 10*time.Second, pclog.Discard())
}

// pageCompare is a mismatch report for host on the browser connection.
func (bs *browserStack) pageCompare(host, pathSHA string) *pb.ReportPageCompareRequest {
	return &pb.ReportPageCompareRequest{
		ConnectionId: bs.browserConn, RunId: bs.run, Host: host, PathSha256: pathSHA,
		AgentStatus: 200, PlainStatus: 200, AgentBytes: 51200, PlainBytes: 900, SimilarityPermille: 120,
	}
}
