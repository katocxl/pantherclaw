// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/detection/engine"
	dpack "github.com/katocxl/pantherclaw/internal/detection/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	"github.com/katocxl/pantherclaw/internal/threatmap/adapters/pgthreatmap"
	tmapp "github.com/katocxl/pantherclaw/internal/threatmap/app"
)

// The exit journey's techniques, chosen from the shipped mappings (G0 M28
// exit end-to-end):
//   - m28X, ATLAS AML.T0050, is mapped to no built-in rule, signal kind or
//     Prevent control: its Detect lane is the Hub rule org.hub.shell_merge_attempt
//     alone (Hub item pc.detect.shell-merge-attempt), and it is a matrix
//     technique, so a drop of its lane is a snapshot drop.
//   - m28Y, ATLAS AML.T0053, is tested by the coding-agent library scenarios
//     RT-001, RT-002 and RT-019, which pass against the range's simulators.
const (
	m28X       = "AML.T0050"
	m28XItem   = "pc.detect.shell-merge-attempt"
	m28XRule   = "org.hub.shell_merge_attempt"
	m28Y       = "AML.T0053"
	m28LaneHit = "pc.threatmap.lane_lost"
)

// TestE2E_M28_ThreatMap is M28's exit journey (G0 M28, tracker "Exit
// end-to-end"), steps 1–4, on a Business org's range stack with a Hub:
//  1. A Hub detection rule mapping X is installed and published, and one
//     receipt drives its input: X's Detect is EVIDENCED and X is green.
//  2. The rule is disabled: X's Detect is GAP RULE_OFF, X's status drops, the
//     snapshot writes audit.threatmap.lane_lost and pc.threatmap.lane_lost
//     raises an alert for it; a second snapshot raises no other.
//  3. `pclaw redteam run --technique Y`: Y's Test is PASSED from
//     server-observed results, and Y's status is unchanged by it.
//  4. `pclaw threats export report --framework attack` builds a pack that
//     `pclaw verify` passes; the same pack with threat_map.json edited after
//     signing fails.
//
// The snapshot and detection engine run in the test on the stack's database,
// as M10's and M27's journeys run theirs, so each step reads its own result.
//
// Covers: F960, F961, F962, F968, F970, F972, F973, HR-680, HR-685, HR-687, HR-688, HR-689, T-300, T-302
func TestE2E_M28_ThreatMap(t *testing.T) {
	kit := newHubKit(t)
	d := newRangeDriver(t)
	d.hubKey, d.business = kit.pub, true
	if _, err := d.Setup(context.Background(), domain.Scenario{ID: "RT-000", Requires: []string{"github", "payments", "person"}}); err != nil {
		t.Fatal(err)
	}
	r := &rangeStack{d: d}
	r.buildRangeThroughTheProduct(exitBounds, exitRequirements)
	r.seedEnvelopeBudget(t)
	s := d.s
	ctx := context.Background()
	d.admin.login(t, s.org.String(), "")
	rc := connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 30 * time.Second, Transport: keyBearer{bearerOf(t, d.admin)},
	}, s.apiURL))
	threats := pantherclawv1connect.NewThreatMapServiceClient(rc)
	detections := pantherclawv1connect.NewDetectionServiceClient(rc)
	technique := func(id string) *pb.ThreatTechniqueDetail {
		t.Helper()
		res, err := threats.GetThreatTechnique(ctx, &pb.GetThreatTechniqueRequest{
			Framework: pb.ThreatFramework_THREAT_FRAMEWORK_ATLAS, TechniqueId: id,
		})
		if err != nil {
			t.Fatalf("GetThreatTechnique %s: %v", id, err)
		}
		return res.GetTechnique()
	}

	// The detection engine and the snapshot job, in the test.
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	rulesPack, err := dpack.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	eng := &engine.Engine{
		Pool: s.pool, Builtin: rulesPack.Rules, PackVersion: rulesPack.Version, Env: env, Raiser: &alerts.Raiser{}, Sink: &failures.Sink{},
		Ents: ents{billing.Business},
	}
	detect := func() {
		t.Helper()
		for range 100 {
			if _, err := ledger.ChainAll(ctx, s.pool, s.org, 1000); err != nil {
				t.Fatal(err)
			}
			res, err := eng.Process(ctx, s.org)
			if err != nil {
				t.Fatal(err)
			}
			if res.Events == 0 && res.To == res.From {
				return
			}
		}
		t.Fatal("the detection feed did not drain")
	}
	snap := &tmapp.Snapshotter{Pool: s.pool, Ents: ents{billing.Business}, Store: pgthreatmap.Store{}}
	snapshot := func() {
		t.Helper()
		if _, err := snap.Run(ctx, s.org); err != nil {
			t.Fatal(err)
		}
		detect()
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		n, err := strconv.Atoi(s.row(t, sql, args...))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	// 1. Install the Hub rule; a person publishes the install's own version.
	site := kit.build(2)
	if code := pclaw.Run(ctx, []string{"hub", "install", m28XItem, "--source", site}, io.Discard, io.Discard,
		d.admin.env("PANTHERCLAW_HUB_DEV_KEY", kit.pub), pclaw.Options{}); code != 0 {
		t.Fatalf("hub install %s: %d", m28XItem, code)
	}
	ruleID := s.row(t, "SELECT id::text FROM pc.custom_detection_rules WHERE rule_id = $1 AND state = 'DRAFT'", m28XRule)
	if _, err := detections.PublishCustomRule(ctx, &pb.PublishCustomRuleRequest{Id: ruleID}); err != nil {
		t.Fatalf("publish %s: %v", m28XRule, err)
	}
	snapshot() // the day's first snapshot: X's lanes before
	if code, rep := s.refund(t, ids.NewV7(), "1.00"); code >= 500 {
		t.Fatalf("the refund that drives the rule's input: %d %+v", code, rep)
	}
	eventually(t, time.Minute, "X's Detect lane to be EVIDENCED", func() (bool, error) {
		detect()
		return technique(m28X).GetDetect().GetState() == pb.ThreatLaneState_THREAT_LANE_STATE_EVIDENCED, nil
	})
	x := technique(m28X)
	hub := slices.IndexFunc(x.GetDetect().GetRules(), func(r *pb.ThreatRule) bool { return r.GetRuleId() == m28XRule })
	if x.GetCell().GetStatus() != pb.ThreatStatus_THREAT_STATUS_EVIDENCED || hub < 0 || x.GetDetect().GetRules()[hub].GetSource() != pb.ThreatRuleSource_THREAT_RULE_SOURCE_HUB {
		t.Fatalf("X after the Hub rule saw input: %v", x)
	}
	snapshot() // X EVIDENCED is the day's newest snapshot

	// 2. The rule is disabled: X's Detect drops, once per scope that has it.
	if _, err := detections.DisableCustomRule(ctx, &pb.DisableCustomRuleRequest{Id: ruleID, Reason: "m28 exit: blind the technique"}); err != nil {
		t.Fatal(err)
	}
	x = technique(m28X)
	if x.GetDetect().GetState() != pb.ThreatLaneState_THREAT_LANE_STATE_GAP || !slices.Contains(x.GetDetect().GetReasons(), "RULE_OFF") ||
		x.GetCell().GetStatus() == pb.ThreatStatus_THREAT_STATUS_EVIDENCED {
		t.Fatalf("X with its rule off: %v", x)
	}
	const lost = `SELECT count(*)::text FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.threatmap.lane_lost'`
	const lostX = lost + ` AND convert_from(body, 'UTF8') LIKE '%` + m28X + `%' AND convert_from(body, 'UTF8') LIKE '%DETECT%'`
	const raised = `SELECT count(*)::text FROM pc.alerts WHERE org_id = $1 AND rule_id = '` + m28LaneHit + `'`
	before := count(lost, s.org.String())
	snapshot()
	drops := count(lost, s.org.String()) - before
	if n := count(lostX, s.org.String()); drops < 1 || n != drops {
		t.Fatalf("lane_lost: %d new, %d of them X's Detect", drops, n)
	}
	alertsX := count(raised, s.org.String())
	if alertsX != drops {
		t.Fatalf("%d %s alerts for %d drops of X's Detect", alertsX, m28LaneHit, drops)
	}
	// Each alert's target is X's Detect lane in one evaluated scope on the
	// day: atlas:<scope_key>:AML.T0050:DETECT:<day>, one per scope (D719a).
	sorted := func(csv string) []string {
		out := strings.Split(csv, ",")
		slices.Sort(out)
		return out
	}
	want := sorted(s.row(t, `SELECT string_agg('atlas:' || scope_key || ':`+m28X+`:DETECT:' || day::text, ',') FROM pc.threat_map_snapshots
		WHERE org_id = $1 AND framework = 'atlas' AND day = (SELECT max(day) FROM pc.threat_map_snapshots WHERE org_id = $1)`, s.org.String()))
	got := sorted(s.row(t, `SELECT coalesce(string_agg(x->>'id', ','), '') FROM pc.alerts a CROSS JOIN jsonb_array_elements(a.subjects) x
		WHERE a.org_id = $1 AND a.rule_id = '`+m28LaneHit+`' AND x->>'type' = 'resource'`, s.org.String()))
	if len(want) != drops || !slices.Equal(got, want) {
		t.Fatalf("lane_lost alert targets %v, want %v (one per evaluated scope, %d drops)", got, want, drops)
	}
	snapshot()
	if n, a := count(lost, s.org.String())-before, count(raised, s.org.String()); n != drops || a != alertsX {
		t.Fatalf("a second snapshot: %d lane_lost, %d alerts (want %d, %d)", n, a, drops, alertsX)
	}

	// 3. The range tests Y; a passed test is never evidence.
	y := technique(m28Y)
	if y.GetTest().GetState() == pb.ThreatTestState_THREAT_TEST_STATE_PASSED {
		t.Fatalf("Y's Test before the range: %v", y.GetTest())
	}
	if code, out, errs, _ := r.run(t, scenarioDir(t), "--technique", m28Y); code != 0 {
		t.Fatalf("pclaw redteam run --technique %s: %d\n%s\n%s", m28Y, code, out, errs)
	}
	after := technique(m28Y)
	if after.GetTest().GetState() != pb.ThreatTestState_THREAT_TEST_STATE_PASSED {
		t.Fatalf("Y's Test after the range: %v", after.GetTest())
	}
	if after.GetCell().GetStatus() != y.GetCell().GetStatus() {
		t.Errorf("Y's status moved with its test: %s -> %s", y.GetCell().GetStatus(), after.GetCell().GetStatus())
	}

	// 4. The signed report verifies offline; edited after signing, it fails.
	p := s.proof(t)
	if code, out, errs := d.admin.pclaw(t, "threats", "export", "report", "--framework", "attack"); code != 0 {
		t.Fatalf("threats export report: %d %s %s", code, out, errs)
	}
	packID := s.row(t, "SELECT id::text FROM pc.evidence_packs WHERE scope_kind = 'threat_map' AND threat_framework = 'attack-enterprise'")
	eventually(t, 2*time.Minute, "the threat map pack to be built", func() (bool, error) {
		return s.row(t, "SELECT state FROM pc.evidence_packs WHERE id = $1", packID) == "READY", nil
	})
	file := filepath.Join(t.TempDir(), "threat-map.zip")
	if code, out, errs := d.admin.pclaw(t, "pack", "download", packID, "--out", file); code != 0 {
		t.Fatalf("pack download: %d %s %s", code, out, errs)
	}
	code, rep := p.verify(t, file)
	if code != 0 || !all(rep, "threatmap.report", bundle.Passed) || !all(rep, "threatmap.lanes", bundle.Passed) {
		t.Fatalf("pclaw verify the threat map pack: %d %+v", code, rep.Checks)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	edited := filepath.Join(t.TempDir(), "edited.zip")
	if err := os.WriteFile(edited, m28FlipFirstTechnique(t, raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, rep := p.verify(t, edited); code == 0 || !slices.Contains(statuses(rep, "pack.item"), bundle.Failed) {
		t.Fatalf("an edited threat map verified: %d %+v", code, rep.Checks)
	}
}

// m28FlipFirstTechnique returns the pack with the first technique of its
// threat_map.json shown with another status, not signed again.
func m28FlipFirstTechnique(t *testing.T, raw []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if f.Name == pack.ThreatMapPath {
			var doc map[string]any
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			techs, _ := doc["techniques"].([]any)
			if len(techs) == 0 {
				t.Fatal("threat_map.json lists no technique")
			}
			first, _ := techs[0].(map[string]any)
			if first["status"] == "EVIDENCED" {
				first["status"] = "GAP"
			} else {
				first["status"] = "EVIDENCED"
			}
			if b, err = json.Marshal(doc); err != nil {
				t.Fatal(err)
			}
		}
		w, err := zw.Create(f.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
