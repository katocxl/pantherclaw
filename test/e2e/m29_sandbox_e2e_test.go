// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration && sandbox

package e2e

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	simmodel "github.com/katocxl/pantherclaw/internal/sim/model"
)

// The model route through the sandbox (G0 M29 D814, D815, D823, D828):
// `pclaw sandbox run` maps the model connections, the agent calls its model
// at api.anthropic.com through the edge and the gateway, and reaches the
// fake model only with the key the gateway holds. Run by `task
// test:sandbox` (E2E_RUN=^TestE2E_M29_) and the range with SANDBOX=1.

// otherModelHost is a model host no connection maps.
const otherModelHost = "api.other-model.example"

// plantModelKey leaves an Anthropic-shaped key in the workspace's .env, as
// a developer would, and returns it. It is built at run time so that no
// key-shaped string is in the source (D804).
func (m *m9) plantModelKey(t *testing.T) string {
	t.Helper()
	key := "sk-" + "ant-" + "api03-" + rand.Text() + rand.Text()
	f, err := os.OpenFile(filepath.Join(m.workspace, ".env"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("ANTHROPIC_KEY=" + key + "\n"); err != nil {
		t.Fatal(err)
	}
	return key
}

// modelGrant issues the agent a grant for the model operations, as alice.
func (m *m9) modelGrant(t *testing.T) string {
	t.Helper()
	alice := m.row(t, "SELECT id::text FROM pc.users WHERE subject = 'alice'")
	bounds := writeFile(t, t.TempDir(), "bounds.json", []byte(modelBounds))
	code, out, errs := m.alice.pclaw(t, "grant", "issue", m.agent, "--principal", "user:"+alice, "--expires", "24h",
		"--bounds-file", bounds, "--task", "m29 model")
	g := grantID.FindStringSubmatch(out)
	if code != 0 || g == nil {
		t.Fatalf("grant issue: %d %s %s", code, out, errs)
	}
	return g[1]
}

// modelSandbox runs `pclaw sandbox run` as alice with both model
// connections mapped, the run's token cap and extra env, and the agent's
// arguments.
func (m *m9) modelSandbox(t *testing.T, grant string, maxTokens int64, env []string, agentArgs ...string) (int, string, string) {
	t.Helper()
	args := []string{
		"sandbox", "run", "--agent", m.agent, "--grant", grant, "--gateway", m.gateway,
		"--connection", m.model.conns["anthropic"].String(), "--connection", m.model.conns["openai"].String(),
		"--image", m.agentImage, "--edge-image", m.edgeImage, "--probe-image", m.probe, "--workspace", m.workspace, "--ttl", "1h",
	}
	if maxTokens > 0 {
		args = append(args, "--max-tokens", strconv.FormatInt(maxTokens, 10))
	}
	for _, e := range env {
		args = append(args, "--env", e)
	}
	args = append(append(args, "--"), agentArgs...)
	var out, errb strings.Builder
	code := pclaw.Run(t.Context(), args, &out, &errb, m.alice.env(), pclaw.Options{})
	return code, out.String(), errb.String()
}

// modelRun is the agent's model calls through the sandbox (RT-190,
// RT-191), run once per scenario: its output and the planted key.
type modelRun struct {
	out, errs, key string
}

func (r *sandboxRig) modelRun(d *rangeDriver) (*modelRun, error) {
	if r.model != nil {
		return r.model, nil
	}
	if !r.revoked {
		r.m.revokeSeeded(d.t)
		r.revoked = true
	}
	key := r.m.plantModelKey(d.t)
	code, out, errs := r.m.modelSandbox(d.t, r.m.modelGrant(d.t), 0, nil, "model", otherModelHost)
	if code != 0 {
		return nil, fmt.Errorf("sandbox run: %d\n%s\n%s", code, out, errs)
	}
	r.model = &modelRun{out: out, errs: errs, key: key}
	return r.model, nil
}

// modelProbe runs the model probes (D827): model_own_key BLOCKED when the
// call with the agent's own key passed and the fake model never saw that
// key, only the gateway's; model_unmapped_host REFUSED unmapped_destination
// when the edge refused the other host.
func modelProbe(d *rangeDriver, probe string) (domain.Observation, error) {
	r := d.extra.sandbox
	run, err := r.modelRun(d)
	if err != nil {
		return domain.Observation{}, err
	}
	sim := d.s.model.sim
	switch probe {
	case "model_own_key":
		line := lineOf(run.out, "model-own-key ")
		if sim.Presented(run.key) {
			return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "the model saw the agent's key: " + line}, nil
		}
		if !strings.HasPrefix(line, "model-own-key 200") || sim.Stats().LastKey != simmodel.DefaultKey {
			return domain.Observation{}, fmt.Errorf("the call with the agent's key did not pass with the gateway's: %q, last key %q", line, sim.Stats().LastKey)
		}
		return domain.Observation{Outcome: domain.OutcomeBlocked, Detail: line}, nil
	case "model_unmapped_host":
		line := lineOf(run.out, "model-other ")
		if strings.HasPrefix(line, "model-other error") || strings.HasPrefix(line, "model-other 403") {
			if !refusedRoutes.MatchString(run.errs) {
				return domain.Observation{}, fmt.Errorf("the edge reported no refused route:\n%s", run.errs)
			}
			return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "CANNOT_AUTHORIZE", Code: "unmapped_destination", Detail: line}, nil
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: line}, nil
	}
	return domain.Observation{}, fmt.Errorf("unknown model probe %q", probe)
}

// TestE2E_M29_SandboxModel (D828): a scripted agent in `pclaw sandbox run
// --max-tokens --env` calls its model through the edge and the gateway: the
// key it found is stripped, the placeholder is not reported, the call
// passes with the gateway's key, the run cap stops a call over it, and
// --env refuses a proxy override and a key-shaped value before anything
// starts.
//
// Covers: F983, F984, HR-690, HR-697, T-310, T-317
func TestE2E_M29_SandboxModel(t *testing.T) {
	m := startM9(t, func(o *options) { o.model = true })
	modelRangeAgent(t, m.stack)
	m.revokeSeeded(t)
	key := m.plantModelKey(t)
	grant := m.modelGrant(t)

	// --env refuses a proxy override and a credential value, never echoing
	// the value, before any container starts.
	for name, e := range map[string]string{"proxy": "HTTPS_PROXY=http://evil.example:8080", "key": "MY_KEY=" + key} {
		code, out, errs := m.modelSandbox(t, grant, 0, []string{e}, "model", otherModelHost)
		if code == 0 || strings.Contains(out+errs, key) || !strings.Contains(errs, "--env") {
			t.Fatalf("--env %s: %d %s %s", name, code, out, errs)
		}
	}
	if n := m.model.sim.Stats().Requests; n != 0 {
		t.Fatalf("a refused --env reached the model: %d requests", n)
	}

	// A cap large enough for the calls: the own key is stripped, the
	// placeholder is not reported, the call passes with the gateway's key.
	code, out, errs := m.modelSandbox(t, grant, 100000, []string{"AGENT_MODE=review"}, "model", otherModelHost)
	if code != 0 || !closurePassed.MatchString(out) {
		t.Fatalf("sandbox run: %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"model-placeholder 200", "model-own-key 200"} {
		if !strings.HasPrefix(lineOf(out, strings.Fields(want)[0]+" "), want) {
			t.Fatalf("%s: %q\n%s", want, lineOf(out, strings.Fields(want)[0]+" "), out)
		}
	}
	if m.model.sim.Presented(key) || m.model.sim.Stats().LastKey != simmodel.DefaultKey {
		t.Fatalf("the model saw the agent's key (last key %q)", m.model.sim.Stats().LastKey)
	}
	if l := lineOf(out, "model-other "); !strings.HasPrefix(l, "model-other error") && !strings.HasPrefix(l, "model-other 403") {
		t.Fatalf("another model host was reached: %q", l)
	}
	// One stripped key (the found one) and one refused host: the
	// placeholder is never reported.
	if g := refusedRoutes.FindStringSubmatch(errs); g == nil || g[1] != "2" {
		t.Fatalf("the edge's report: %v\n%s", g, errs)
	}

	// A run cap below one call's reservation: the call is refused with the
	// token reason, and the model is not called.
	before := m.model.sim.Stats().Calls[simmodel.OpMessages]
	code, out, errs = m.modelSandbox(t, grant, 10, nil, "model", otherModelHost)
	if code != 0 {
		t.Fatalf("sandbox run with a cap: %d\n%s\n%s", code, out, errs)
	}
	if l := lineOf(out, "model-placeholder "); !strings.HasPrefix(l, "model-placeholder 403") || !strings.Contains(l, "TOKEN_BUDGET_EXHAUSTED") {
		t.Fatalf("over the run cap: %q", l)
	}
	if n := m.model.sim.Stats().Calls[simmodel.OpMessages]; n != before {
		t.Fatalf("a call over the run cap reached the model: %d calls", n-before)
	}
}
