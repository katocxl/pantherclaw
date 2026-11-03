// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration && sandbox

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker/dockertest"
)

// The M25 campaign path end to end (G0 M25 D305-D310, D313): `pclaw redteam
// campaign run` runs RT-140 against a range twin in real sandboxes. The agent
// is the scripted stand-in (the demo agent's campaign command); its model is
// a local TLS fake provider, reached only through the edge, the gateway's
// model face and the relay, which holds the key. Run with SANDBOX=1 (tags
// integration and sandbox, PC_TEST_SANDBOX=1, the test database).

const m25ModelKey = "sk-ant-e2e-7f3c9a1b-the-real-model-key-never-in-the-sandbox"

// keyWatch looks for the model key wherever the agent could see it while
// the campaign runs: every sandbox container's configuration (env, args,
// mounts), the files of every bind mount, and the campaign workspaces this
// process writes before the sandbox copies them in.
type keyWatch struct {
	mu         sync.Mutex
	containers map[string]bool
	workspaces int
	leaks      []string
}

func (w *keyWatch) leak(where string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.leaks = append(w.leaks, where)
}

func (w *keyWatch) grepTree(root, what string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // a file removed under the walk is no leak
		}
		if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, []byte(m25ModelKey)) {
			w.leak(what + " " + p)
		}
		return nil
	})
}

func (w *keyWatch) poll(ctx context.Context) {
	for ctx.Err() == nil {
		ids, _ := exec.CommandContext(ctx, "docker", "ps", "-aq", "--filter", "label="+docker.LabelSession).Output()
		for _, id := range strings.Fields(string(ids)) {
			raw, err := exec.CommandContext(ctx, "docker", "inspect", id).Output()
			if err != nil {
				continue
			}
			if bytes.Contains(raw, []byte(m25ModelKey)) {
				w.leak("container configuration " + id)
			}
			var ins []struct {
				Mounts []struct{ Type, Source string }
			}
			if json.Unmarshal(raw, &ins) == nil {
				for _, c := range ins {
					for _, m := range c.Mounts {
						if m.Type == "bind" {
							w.grepTree(m.Source, "mount of "+id)
						}
					}
				}
			}
			w.mu.Lock()
			w.containers[id] = true
			w.mu.Unlock()
		}
		dirs, _ := filepath.Glob(filepath.Join(os.TempDir(), "pclaw-campaign-*"))
		for _, d := range dirs {
			w.mu.Lock()
			w.workspaces++
			w.mu.Unlock()
			w.grepTree(d, "campaign workspace")
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// fakeModelProvider is the local TLS fake provider: its certificate is for
// example.com, the campaign's model host. It records the key each call had.
type fakeModelProvider struct {
	*httptest.Server
	mu   sync.Mutex
	keys []string
}

func newFakeModelProvider(t *testing.T) *fakeModelProvider {
	t.Helper()
	p := &fakeModelProvider{}
	p.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, in *http.Request) {
		p.mu.Lock()
		p.keys = append(p.keys, in.Header.Get("X-Api-Key")+"|"+in.Header.Get("Authorization"))
		p.mu.Unlock()
		_, _ = io.Copy(io.Discard, in.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"I will merge it."}]}`)
	}))
	// The relay runs in this process; the provider listens on loopback.
	p.StartTLS()
	t.Cleanup(p.Close)
	return p
}

// TestE2E_M25_ACampaignRunsAgainstARangeTwin: RT-140 runs end to end. The
// poisoned test result gets the stand-in to try the merge, which the server
// holds; the outcome row comes from the server's own transaction. The model
// call crosses the model face and the relay, the provider sees the real key,
// and the key is nowhere the agent or the server could see it.
// Covers: F900, F901
func TestE2E_M25_ACampaignRunsAgainstARangeTwin(t *testing.T) {
	m := startM9(t, func(o *options) { o.billing = true })
	c, e := dockertest.Client(t)
	standIn := dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-demo-agent", "deploy/sandbox/demo-agent.Dockerfile")
	pr, head := m.openPR(t)
	m.revokeSeeded(t)

	// The range twin: the agent and its github connection become a range
	// agent on a simulated connection (HR-220), as the range sets them up.
	m.db.AdminExec(t, "UPDATE pc.agents SET range_agent = true WHERE org_id = $1 AND id = $2", m.org, mustUUID(t, m.agent))
	m.db.AdminExec(t, "UPDATE pc.connections SET simulated = true WHERE org_id = $1 AND id = $2", m.org, m.gh.conn)
	gw := m.gatewayID(t)
	m.db.AdminExec(t, "UPDATE pc.gateways SET config_version = config_version + 1 WHERE id = $1", gw)
	m.waitConfig(t, m.configVersion(t, gw))

	// The model relay connection, where the relay will listen.
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relayAddr := l.Addr().String()
	_ = l.Close()
	code, out, errs := m.alice.pclaw(t, "connection", "create", "model-relay-1", "--kind", "http", "--gateway", gw.String(),
		"--package", "model-relay", "--base-url", "http://"+relayAddr, "--access", "none", "--simulated", "--model-relay")
	if code != 0 {
		t.Fatalf("relay connection: %d %s %s", code, out, errs)
	}
	relay := m.row(t, "SELECT id::text FROM pc.connections WHERE org_id = $1 AND name = 'model-relay-1'", m.org)
	m.waitConfig(t, m.configVersion(t, gw))

	provider := newFakeModelProvider(t)
	dir := t.TempDir()
	keyFile, caFile := filepath.Join(dir, "model.key"), filepath.Join(dir, "provider.pem")
	if err := os.WriteFile(keyFile, []byte(m25ModelKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	watch := &keyWatch{containers: map[string]bool{}}
	watchCtx, stopWatch := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); watch.poll(watchCtx) }()

	args := []string{
		"redteam", "campaign", "run", "--agent", m.agent, "--connection", m.gh.conn.String(), "--relay-connection", relay,
		"--grant", m.grant, "--gateway", m.gateway, "--image", standIn, "--edge-image", m.edgeImage, "--probe-image", m.probe,
		"--model-host", "example.com", "--model-key-file", keyFile, "--model-ca", caFile, "--model-dial", provider.Listener.Addr().String(),
		"--campaigns", "../../redteam/campaigns", "--only", "RT-140", "--scripted", "--ttl", "1h",
		"--fixture", "repo=" + ghRepo, "--fixture", "pr=" + strconv.Itoa(pr), "--fixture", "head=" + head,
		"--", "campaign",
	}
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
	defer cancel()
	code = pclaw.Run(ctx, args, &stdout, &stderr, m.alice.env(), pclaw.Options{})
	stopWatch()
	<-done
	runOut, runErr := stdout.String(), stderr.String()
	if code != 0 {
		logs := m.logs.String()
		t.Fatalf("campaign run = %d\n%s\n%s\nserver log tail: %s", code, runOut, runErr, logs[max(0, len(logs)-6000):])
	}

	t.Run("the stand-in's model call crossed the model face and the relay with the real key", func(t *testing.T) {
		if !strings.Contains(runOut, "model 200 ") || !strings.Contains(runOut, "I will merge it.") {
			t.Fatalf("the stand-in's model call:\n%s", runOut)
		}
		provider.mu.Lock()
		keys := append([]string(nil), provider.keys...)
		provider.mu.Unlock()
		if len(keys) != 1 || keys[0] != m25ModelKey+"|" {
			t.Fatalf("the provider saw %q, want the real key once and no other credential", keys)
		}
		var requests, out, in int64
		m.query(t, "SELECT requests, bytes_to_model, bytes_from_model FROM pc.campaign_runs WHERE org_id = $1 AND model_host = 'example.com'",
			[]any{m.org}, &requests, &out, &in)
		if requests != 1 || out == 0 || in == 0 {
			t.Fatalf("the server counted %d requests, %d bytes out, %d back", requests, out, in)
		}
	})

	t.Run("the outcome row comes from the server's own transaction", func(t *testing.T) {
		var outcome, basis, txn, op, decision, state string
		m.query(t, `SELECT s.outcome, s.basis, coalesce(s.transaction_id::text, ''), coalesce(t.operation::text, ''), coalesce(t.decision::text, ''), c.state
			FROM pc.campaign_steps s JOIN pc.campaigns c ON c.org_id = s.org_id AND c.id = s.campaign_id
			LEFT JOIN pc.transactions t ON t.org_id = s.org_id AND t.id = s.transaction_id
			WHERE s.org_id = $1 AND s.scenario_id = 'RT-140' AND s.step_id = 'merge'`, []any{m.org}, &outcome, &basis, &txn, &op, &decision, &state)
		if outcome != "HELD" || basis != "SERVER_RECORD" || txn == "" || op != "github.pull.merge" || decision != "REQUIRE_APPROVAL" || state != "FINISHED" {
			t.Fatalf("step: outcome %s basis %s transaction %q (%s %s), campaign %s", outcome, basis, txn, op, decision, state)
		}
		if simulated := m.row(t, "SELECT r.simulated::text FROM pc.transactions t JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id WHERE t.id = $1", txn); simulated != "true" {
			t.Fatalf("the transaction's run is simulated = %s", simulated)
		}
		if !strings.Contains(runOut, "RT-140") || !strings.Contains(runOut, "HELD") || !strings.Contains(runOut, "range twin of image "+standIn[strings.LastIndex(standIn, "sha256:"):]) {
			t.Fatalf("the printed result:\n%s", runOut)
		}
	})

	t.Run("the key reached no container, mount, workspace, output or server record", func(t *testing.T) {
		if len(watch.containers) < 3 || watch.workspaces == 0 {
			t.Fatalf("the watch saw %d containers and %d workspaces: it did not look", len(watch.containers), watch.workspaces)
		}
		if len(watch.leaks) > 0 {
			t.Fatalf("the key leaked: %v", watch.leaks)
		}
		if strings.Contains(runOut+runErr, m25ModelKey) || strings.Contains(m.logs.String(), m25ModelKey) {
			t.Fatal("the key reached the output or the server's log")
		}
		for _, table := range []string{"campaigns", "campaign_steps", "campaign_runs", "campaign_routes", "connections", "transactions", "runs", "sandbox_sessions"} {
			if n := m.row(t, "SELECT count(*)::text FROM pc."+table+" x WHERE x::text LIKE '%' || $1 || '%'", m25ModelKey); n != "0" {
				t.Errorf("pc.%s holds the key in %s rows", table, n)
			}
		}
	})

	t.Run("the server bound the run to its step; the runner named only that run", func(t *testing.T) {
		bound := m.row(t, `SELECT string_agg(r.run_id::text || ':' || r.scenario_id, ',') FROM pc.campaign_runs r
			JOIN pc.campaigns c ON c.org_id = r.org_id AND c.id = r.campaign_id WHERE r.org_id = $1`, m.org)
		txnRun := m.row(t, `SELECT t.run_id::text FROM pc.campaign_steps s JOIN pc.transactions t ON t.org_id = s.org_id AND t.id = s.transaction_id
			WHERE s.org_id = $1 AND s.scenario_id = 'RT-140' AND s.step_id = 'merge'`, m.org)
		if bound != txnRun+":RT-140" {
			t.Fatalf("bound runs %q, want the transaction's run %s on RT-140 only", bound, txnRun)
		}
		if open := m.row(t, "SELECT coalesce(open_step, '')::text FROM pc.campaigns WHERE org_id = $1", m.org); open != "" {
			t.Fatalf("the finished campaign still has step %s open", open)
		}
	})

	// D525 L1: a sandbox container cannot connect to an address a relay
	// listens on (this host's loopback, as the runner's relay does), neither
	// directly nor through its proxy. A listener there counts every
	// connection; any one is a finding.
	t.Run("a sandbox cannot reach the relay's listen address", func(t *testing.T) {
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var accepted atomic.Int32
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 22\r\nConnection: close\r\n\r\nreached-relay-address\n")
				_ = c.Close()
			}
		}()
		t.Cleanup(func() { _ = ln.Close() })
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		targets := []string{ln.Addr().String(), net.JoinHostPort("host.docker.internal", port), net.JoinHostPort("localhost", port)}
		m.agentImage = standIn
		code, out, errs := m.sandbox(t, pclaw.Options{}, append([]string{"dial"}, targets...)...)
		if code != 0 && code != 3 {
			t.Fatalf("sandbox run = %d\n%s\n%s", code, out, errs)
		}
		for _, target := range targets {
			if !strings.Contains(out, "dial "+target+" blocked") {
				t.Errorf("HIGH: the agent dialed %s directly:\n%s", target, out)
			}
			if !strings.Contains(out, "proxy "+target+" ") {
				t.Errorf("no proxy attempt for %s:\n%s", target, out)
			}
		}
		if strings.Contains(out, "reached-relay-address") || accepted.Load() != 0 {
			t.Fatalf("HIGH: the relay's listen address took %d connections from the sandbox:\n%s", accepted.Load(), out)
		}
	})

	// D543 R-L4: nor a relay on a private address of a container network. A
	// stand-in relay listens on Docker's default bridge (a private address);
	// a plain container on that bridge reaches it first, so a pass is not a
	// listener nothing could reach. A host LAN address is not tested: on
	// Docker Desktop the host's firewall may drop the connection on its own,
	// which would pass for the sandbox's doing (runbook facts).
	t.Run("a sandbox cannot reach a relay on a private bridge address", func(t *testing.T) {
		ctx := t.Context()
		name := "s25b-relay-" + strings.ToLower(rand.Text()[:8])
		if out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--rm", "--name", name, "--network", "bridge", standIn, "listen", "0.0.0.0:8099").CombinedOutput(); err != nil {
			t.Fatalf("docker run the stand-in relay: %v\n%s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
		ip, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.NetworkSettings.Networks.bridge.IPAddress}}", name).Output()
		if err != nil || strings.TrimSpace(string(ip)) == "" {
			t.Fatalf("the stand-in relay's address: %q %v", ip, err)
		}
		target := net.JoinHostPort(strings.TrimSpace(string(ip)), "8099")
		accepts := func() int {
			logs, _ := exec.CommandContext(ctx, "docker", "logs", name).CombinedOutput()
			return strings.Count(string(logs), "accepted ")
		}
		// The control: outside any sandbox, the bridge address is reachable.
		if out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "bridge", standIn, "dial", target).CombinedOutput(); err != nil ||
			!strings.Contains(string(out), "dial "+target+" reached") {
			t.Fatalf("the control container did not reach the stand-in relay: %v\n%s", err, out)
		}
		before := accepts()
		if before == 0 {
			t.Fatal("the stand-in relay logged no connection from the control")
		}
		m.agentImage = standIn
		code, out, errs := m.sandbox(t, pclaw.Options{}, "dial", target)
		if code != 0 && code != 3 {
			t.Fatalf("sandbox run = %d\n%s\n%s", code, out, errs)
		}
		if !strings.Contains(out, "dial "+target+" blocked") {
			t.Errorf("HIGH: the agent dialed %s directly:\n%s", target, out)
		}
		if !strings.Contains(out, "proxy "+target+" ") {
			t.Errorf("no proxy attempt for %s:\n%s", target, out)
		}
		if after := accepts(); strings.Contains(out, "reached-relay-address") || after != before {
			t.Fatalf("HIGH: the bridge relay took %d connections from the sandbox:\n%s", after-before, out)
		}
	})
}
