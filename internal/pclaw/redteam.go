// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/redteam/adapters/live"
	rtapp "github.com/katocxl/pantherclaw/internal/redteam/app"
	rtdomain "github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// pclaw redteam (G0 M12, PN-009; HR-223..HR-226): the adversarial range.
//
// `run` starts a range for the range agent of a range instance, runs the
// scenarios against simulated targets through the live driver, records each
// scenario's result with the server and writes an unsigned summary. It
// never executes a delegated allow, and runs person steps only with
// --interactive. With --baseline it first verifies a baseline pack offline
// (as pclaw verify does) and then exits 1 on any FAIL or regression (D11).
// Exit codes: 0 clean, 1 a FAIL or a regression, 2 usage or infrastructure.

func init() {
	commands["redteam run"] = command{
		usage: "redteam run --scenarios DIR --workload-file FILE --gateway URL [--suite coding-agent|platform|all] [--run ID] " +
			"[--token-file FILE] [--role ROLE=CONNECTION]… [--fixture NAME=VALUE]… [--provides github,payments,mcp] " +
			"[--interactive] [--baseline PACK --trust FILE] [--out DIR]",
		run: redteamRun,
	}
	commands["redteam report"] = command{usage: "redteam report RANGE_ID --out PACK.zip", run: redteamReport}
	commands["redteam list"] = rpc("redteam list [--agent ID]", 0, func(fs *flag.FlagSet) call {
		agent := fs.String("agent", "", "only this range agent's ranges")
		n, tok := paging(fs)
		return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
			return c.ranges.ListRanges(ctx, &pantherclawv1.ListRangesRequest{RangeAgentId: *agent, PageSize: size(n), PageToken: *tok})
		}
	})
}

// failExit ends a command with exit code 2: usage or infrastructure.
func failExit(format string, args ...any) error {
	return &exitError{code: 2, msg: "pclaw: " + fmt.Sprintf(format, args...)}
}

var (
	roleRe    = regexp.MustCompile(`^[a-z0-9-]{1,40}=[a-z0-9-]{1,63}$`)
	fixtureRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}=.{0,256}$`)
	suites    = []string{"coding-agent", "platform", "all"}
)

// runOptions are the flags of redteam run.
type runOptions struct {
	dir, suite, keyFile, gateway, run, tokenFile string
	roles, fixtures                              list
	provides, baseline, trust, out               string
	interactive                                  bool
}

func redteamRun(ctx context.Context, a *app, args []string) error {
	var o runOptions
	fs := flag.NewFlagSet("redteam run", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fs.StringVar(&o.dir, "scenarios", "", "directory of RT-###-*.yaml scenario files")
	fs.StringVar(&o.suite, "suite", "coding-agent", "coding-agent, platform or all")
	fs.StringVar(&o.keyFile, "workload-file", "", "the range instance's enrolled workload key file")
	fs.StringVar(&o.gateway, "gateway", "", "the gateway's public URL")
	fs.StringVar(&o.run, "run", "", "the range instance's run (default: the key file's)")
	fs.StringVar(&o.tokenFile, "token-file", "", "a workload token to use instead of issuing one")
	fs.Var(&o.roles, "role", "bind a scenario connection role to a simulated connection: ROLE=CONNECTION (repeatable; unbound roles use their own name)")
	fs.Var(&o.fixtures, "fixture", "a ${fixture.NAME} value the simulators hold: NAME=VALUE (repeatable)")
	fs.StringVar(&o.provides, "provides", "", "the simulators set up (github,payments,mcp); default: the roles bound by --role")
	fs.BoolVar(&o.interactive, "interactive", false, "run person steps: print what to approve and wait for you")
	fs.StringVar(&o.baseline, "baseline", "", "a baseline assurance pack: fail on any regression from it")
	fs.StringVar(&o.trust, "trust", "", "trust file for verifying the baseline pack")
	fs.StringVar(&o.out, "out", ".", "directory for summary-<range>.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case fs.NArg() != 0 || o.dir == "" || o.keyFile == "" || o.gateway == "":
		return errUsage
	case !slices.Contains(suites, o.suite):
		return failExit("--suite must be one of %s", strings.Join(suites, ", "))
	case o.baseline != "" && o.trust == "":
		return failExit("--baseline needs --trust: the baseline pack is verified offline first")
	}
	for _, r := range o.roles {
		if !roleRe.MatchString(r) {
			return failExit("--role %q must be ROLE=CONNECTION", r)
		}
	}
	for _, f := range o.fixtures {
		if !fixtureRe.MatchString(f) {
			return failExit("--fixture %q must be NAME=VALUE", f)
		}
	}
	gw, err := checkServer(o.gateway)
	if err != nil {
		return failExit("--gateway must be a base URL using https (http only for localhost)")
	}

	set, err := rtapp.LoadDir(o.dir)
	if err != nil {
		return failExit("%v", err)
	}
	set = slices.DeleteFunc(set, func(l rtapp.Loaded) bool { return o.suite != "all" && l.Scenario.Suite != o.suite })
	if len(set) == 0 {
		return failExit("no scenarios of suite %s in %s", o.suite, o.dir)
	}

	// The baseline is checked before anything runs, so a bad baseline never
	// costs a range.
	var base *baseline
	if o.baseline != "" {
		if base, err = loadBaseline(o.baseline, o.trust); err != nil {
			return failExit("baseline: %v", err)
		}
	}

	kf, err := workloadclient.ReadKeyFile(o.keyFile)
	if err != nil {
		return failExit("%v", err)
	}
	inst, err := pap.ParseInstance(kf.Identifier)
	if err != nil {
		return failExit("the key file is not enrolled yet: run pclaw workload enroll")
	}
	run := o.run
	if run == "" {
		run = kf.RunID
	}
	if !uuidRe.MatchString(run) {
		return failExit("--run must be the range instance's run id (pclaw run start)")
	}
	key, err := kf.Key()
	if err != nil {
		return failExit("%v", err)
	}
	tokens, err := a.proxyTokens(ctx, kf, o.tokenFile)
	if err != nil {
		return failExit("%v", err)
	}
	c, err := a.clients()
	if err != nil {
		return failExit("%v", err)
	}

	rt := a.http.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	roles := map[string]string{}
	caps := map[rtapp.Capability]bool{}
	for _, r := range o.roles {
		role, conn, _ := strings.Cut(r, "=")
		roles[role] = conn
		caps[rtapp.Capability(role)] = true
	}
	for p := range strings.SplitSeq(o.provides, ",") {
		if p = strings.TrimSpace(p); p != "" {
			caps[rtapp.Capability(p)] = true
		}
	}
	fixture := rtapp.Fixture{}
	for _, f := range o.fixtures {
		name, value, _ := strings.Cut(f, "=")
		fixture[name] = value
	}
	cfg := live.Config{
		Gateway: gw, Run: run, Roles: roles, Fixture: fixture, Capabilities: caps,
		Client: &http.Client{
			Transport:     &workloadclient.Transport{Key: key, Base: rt, Token: tokens},
			Timeout:       2 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		Txns: txnReader{tx: c.transactions, approvals: c.approvals, run: run},
	}
	if o.interactive {
		cfg.Operator = ttyOperator{a: a}
	}

	decls := make([]*pantherclawv1.RangeScenarioDecl, len(set))
	digests := map[string]string{}
	for i, l := range set {
		s := l.Scenario
		decls[i] = &pantherclawv1.RangeScenarioDecl{
			Id: s.ID, Digest: l.Digest, Tier: s.Tier, Category: s.Category, Suite: s.Suite, Title: s.Title,
		}
		digests[s.ID] = l.Digest
	}
	start := &pantherclawv1.StartRangeRequest{
		RangeAgentId: inst.Agent.String(), Scenarios: decls, RunnerVersion: runnerVersion(),
	}
	if base != nil && uuidRe.MatchString(base.rangeID) {
		start.BaselineRangeId = base.rangeID
	}
	started, err := c.ranges.StartRange(ctx, start)
	if err != nil {
		return failExit("%v", describe(err))
	}
	rangeID := started.GetRangeId()

	runner := &rtapp.Runner{Driver: live.New(cfg)}
	var results []rtdomain.Result
	for _, l := range set {
		res := runner.Run(ctx, l.Scenario)
		results = append(results, res)
		if _, err := c.ranges.RecordResult(ctx, recordRequest(rangeID, res)); err != nil {
			return failExit("recording %s: %v", res.ScenarioID, describe(err))
		}
	}
	fin, err := c.ranges.FinishRange(ctx, &pantherclawv1.FinishRangeRequest{RangeId: rangeID})
	if err != nil {
		return failExit("%v", describe(err))
	}

	var cmp *rtdomain.Comparison
	if base != nil {
		c := rtdomain.Compare(base.entries, rtapp.Entries(results))
		cmp = &c
	}
	sum := newSummary(rangeID, fin.GetRange(), set, results, cmp)
	if err := writeSummary(o.out, sum); err != nil {
		return failExit("writing the summary: %v", err)
	}
	printTable(a, sum)

	gate := 0
	for _, r := range results {
		if r.Verdict == rtdomain.VerdictFail || r.Verdict == rtdomain.VerdictError { // an ERROR fails closed (D30)
			gate = 1
		}
	}
	if cmp != nil && cmp.ExitCode() != 0 {
		gate = 1
	}
	if gate != 0 {
		return &exitError{code: 1, msg: gateMessage(results, cmp)}
	}
	return nil
}

func runnerVersion() string {
	v := version.Get().String("pclaw")
	if len(v) > 64 {
		v = v[:64]
	}
	return v
}

func gateMessage(results []rtdomain.Result, cmp *rtdomain.Comparison) string {
	var fails []string
	for _, r := range results {
		if r.Verdict == rtdomain.VerdictFail || r.Verdict == rtdomain.VerdictError {
			fails = append(fails, r.ScenarioID+" ("+string(r.Verdict)+")")
		}
	}
	msg := "pclaw: the range gate failed:"
	if len(fails) > 0 {
		msg += " " + strings.Join(fails, ", ") + ";"
	}
	if cmp != nil && len(cmp.Regressions) > 0 {
		var rs []string
		for _, r := range cmp.Regressions {
			rs = append(rs, r.ID+" ("+string(r.Now)+")")
		}
		msg += " regressed from the baseline: " + strings.Join(rs, ", ") + ";"
	}
	return strings.TrimSuffix(msg, ";")
}

// recordRequest is a scenario's result as the server records it. A step's
// observed side is what the driver saw; where the expectation matched, the
// expected reason and outcome are sent so the server's own comparison
// agrees with the runner's (a concurrent step is judged by the runner).
func recordRequest(rangeID string, res rtdomain.Result) *pantherclawv1.RecordResultRequest {
	verdicts := map[rtdomain.Verdict]pantherclawv1.RangeVerdict{
		rtdomain.VerdictPass: pantherclawv1.RangeVerdict_RANGE_VERDICT_PASS, rtdomain.VerdictFail: pantherclawv1.RangeVerdict_RANGE_VERDICT_FAIL,
		rtdomain.VerdictError: pantherclawv1.RangeVerdict_RANGE_VERDICT_ERROR, rtdomain.VerdictSkipped: pantherclawv1.RangeVerdict_RANGE_VERDICT_SKIPPED,
	}
	req := &pantherclawv1.RecordResultRequest{
		RangeId: rangeID, ScenarioId: res.ScenarioID, ScenarioDigest: res.Digest, Verdict: verdicts[res.Verdict],
	}
	for _, s := range res.Steps {
		obs := s.Observed
		observed := &pantherclawv1.RangeExpect{Outcome: string(obs.Outcome), Reason: obs.Reason, Code: obs.Code}
		if s.Matched {
			if s.Expect.Outcome != "" {
				observed.Outcome = string(s.Expect.Outcome)
			}
			if s.Expect.Reason != "" {
				observed.Reason = s.Expect.Reason
			}
		}
		if len(obs.Each) > 0 && s.Expect.Outcome == "" {
			observed.Outcome = ""
		}
		step := &pantherclawv1.RangeStepInput{
			StepId:   s.StepID,
			Expect:   &pantherclawv1.RangeExpect{Outcome: string(s.Expect.Outcome), Reason: s.Expect.Reason, Code: s.Expect.Code},
			Observed: observed,
		}
		if uuidRe.MatchString(obs.TransactionID) {
			step.TransactionId = obs.TransactionID
		}
		if uuidRe.MatchString(obs.ProbeReportID) {
			step.ProbeReportId = obs.ProbeReportID
		}
		if hrRe.MatchString(s.Expect.DecisiveControl) {
			step.DecisiveControl = s.Expect.DecisiveControl
		}
		req.Steps = append(req.Steps, step)
	}
	return req
}

var hrRe = regexp.MustCompile(`^HR-[0-9]{3}$`)

// summary is the unsigned summary.json: what this run saw, for the person
// who ran it. The signed assurance report is `redteam report`.
type summary struct {
	Statement     string          `json:"statement"`
	Unsigned      bool            `json:"unsigned"`
	RangeID       string          `json:"range_id"`
	RunnerVersion string          `json:"runner_version"`
	SetDigest     string          `json:"scenario_set_digest"`
	Counts        map[string]int  `json:"counts"`
	Results       []summaryResult `json:"results"`
	Regressions   []string        `json:"regressions,omitempty"`
	Changed       []string        `json:"changed_since_baseline,omitempty"`
}

type summaryResult struct {
	ID       string `json:"id"`
	Digest   string `json:"digest"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Tier     string `json:"tier"`
	Verdict  string `json:"verdict"`
	Detail   string `json:"detail,omitempty"`
	Steps    int    `json:"steps_run"`
}

const summaryStatement = "Tested-control evidence against simulated targets, recorded by this runner. Unsigned. Not a compliance certification."

func newSummary(rangeID string, r *pantherclawv1.Range, set []rtapp.Loaded, results []rtdomain.Result, cmp *rtdomain.Comparison) summary {
	digests := map[string]string{}
	s := summary{Statement: summaryStatement, Unsigned: true, RangeID: rangeID, RunnerVersion: r.GetRunnerVersion(), Counts: map[string]int{}}
	for i, l := range set {
		digests[l.Scenario.ID] = l.Digest
		res := results[i]
		s.Counts[string(res.Verdict)]++
		s.Results = append(s.Results, summaryResult{
			ID: l.Scenario.ID, Digest: l.Digest, Title: l.Scenario.Title, Category: l.Scenario.Category,
			Tier: l.Scenario.Tier, Verdict: string(res.Verdict), Detail: res.Detail, Steps: len(res.Steps),
		})
	}
	s.SetDigest = rtdomain.SetDigest(digests)
	if cmp != nil {
		for _, rg := range cmp.Regressions {
			s.Regressions = append(s.Regressions, rg.ID+" "+string(rg.Now))
		}
		s.Changed = cmp.Changed
	}
	return s
}

func writeSummary(dir string, s summary) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	b, err := json.Marshal(s, json.Deterministic(true))
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(dir, "summary-"+s.RangeID+".json"), append(b, '\n'))
}

func printTable(a *app, s summary) {
	w := a.stdout
	_, _ = fmt.Fprintf(w, "Range %s (%s)\n%s\n\n", s.RangeID, s.RunnerVersion, s.Statement)
	_, _ = fmt.Fprintf(w, "%-8s %-8s %-11s %s\n", "ID", "VERDICT", "CATEGORY", "TITLE")
	for _, r := range s.Results {
		_, _ = fmt.Fprintf(w, "%-8s %-8s %-11s %s\n", r.ID, r.Verdict, r.Category, r.Title)
		if r.Verdict != string(rtdomain.VerdictPass) && r.Detail != "" {
			_, _ = fmt.Fprintf(w, "         %s\n", r.Detail)
		}
	}
	var parts []string
	for _, v := range []rtdomain.Verdict{rtdomain.VerdictPass, rtdomain.VerdictFail, rtdomain.VerdictError, rtdomain.VerdictSkipped} {
		parts = append(parts, fmt.Sprintf("%d %s", s.Counts[string(v)], v))
	}
	_, _ = fmt.Fprintf(w, "\n%s\n", strings.Join(parts, ", "))
	if len(s.Regressions) > 0 {
		_, _ = fmt.Fprintf(w, "Regressions from the baseline: %s\n", strings.Join(s.Regressions, ", "))
	}
	if len(s.Changed) > 0 {
		_, _ = fmt.Fprintf(w, "Scenarios changed since the baseline (still compared): %s\n", strings.Join(s.Changed, ", "))
	}
}

// baseline is a verified baseline pack's scenario verdicts.
type baseline struct {
	rangeID string
	entries []rtdomain.Entry
}

// maxAssurance bounds assurance.json.
const maxAssurance = 4 << 20

// loadBaseline verifies a baseline assurance pack offline against the trust
// file, exactly as pclaw verify does, and reads its scenario verdicts from
// assurance.json. A pack that fails any check is no baseline.
func loadBaseline(packPath, trustPath string) (*baseline, error) {
	trustRaw, err := readLimited(trustPath, bundle.MaxTrustBytes)
	if err != nil {
		return nil, err
	}
	trust, err := bundle.ParseTrust(trustRaw)
	if err != nil {
		return nil, err
	}
	raw, err := readLimited(packPath, bundle.MaxBundleBytes)
	if err != nil {
		return nil, err
	}
	if !bundle.IsPack(raw) {
		return nil, errors.New(packPath + " is not an evidence pack")
	}
	if report := bundle.VerifyPack(raw, bundle.Options{Trust: trust}); report.Failed() {
		return nil, fmt.Errorf("%s failed verification (%d checks failed); run pclaw verify for the report", packPath, report.Count(bundle.Failed))
	}
	files, err := pack.Read(raw)
	if err != nil {
		return nil, err
	}
	var doc []byte
	for p, data := range files {
		if path.Base(p) == "assurance.json" {
			doc = data
			break
		}
	}
	if doc == nil || len(doc) > maxAssurance {
		return nil, errors.New(packPath + " is not an assurance report (no assurance.json)")
	}
	var a struct {
		Range struct {
			ID string `json:"id"`
		} `json:"range"`
		RangeID   string `json:"range_id"`
		Scenarios []struct {
			ID      string `json:"id"`
			Digest  string `json:"digest"`
			Verdict string `json:"verdict"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(doc, &a); err != nil || len(a.Scenarios) == 0 {
		return nil, errors.New("assurance.json holds no scenarios")
	}
	b := &baseline{rangeID: cmpOr(a.Range.ID, a.RangeID)}
	for _, s := range a.Scenarios {
		b.entries = append(b.entries, rtdomain.Entry{
			ID: s.ID, Digest: strings.TrimPrefix(s.Digest, "sha256:"), Verdict: rtdomain.Verdict(s.Verdict),
		})
	}
	return b, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func redteamReport(ctx context.Context, a *app, args []string) error {
	if len(args) < 1 {
		return errUsage
	}
	fs := flag.NewFlagSet("redteam report", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	out := fs.String("out", "", "file to write (must not exist)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		return errUsage
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	res, err := c.ranges.ExportAssuranceReport(ctx, &pantherclawv1.ExportAssuranceReportRequest{RangeId: args[0]})
	if err != nil {
		return err
	}
	return downloadPack(ctx, a, c, res.GetPackId(), *out)
}

// txnReader reads a transaction's state for the live driver.
type txnReader struct {
	tx        pantherclawv1connect.TransactionServiceClient
	approvals pantherclawv1connect.ApprovalServiceClient
	run       string
}

func (r txnReader) State(ctx context.Context, id string) (live.TxnState, error) {
	ev, err := r.tx.GetTransactionEvidence(ctx, &pantherclawv1.GetTransactionEvidenceRequest{Id: id})
	if err != nil {
		return live.TxnState{}, err
	}
	var s live.TxnState
	switch ev.GetTransaction().GetEffectState() {
	case pantherclawv1.EffectState_EFFECT_STATE_CONFIRMED:
		s.Effect = "CONFIRMED"
	case pantherclawv1.EffectState_EFFECT_STATE_UNKNOWN:
		s.Effect = "UNKNOWN"
	}
	s.Decision = map[pantherclawv1.Decision]string{
		pantherclawv1.Decision_DECISION_ALLOW: "ALLOW", pantherclawv1.Decision_DECISION_ALLOW_WITH_OBLIGATIONS: "ALLOW",
		pantherclawv1.Decision_DECISION_REQUIRE_APPROVAL: "HOLD", pantherclawv1.Decision_DECISION_REQUIRE_STEP_UP: "HOLD",
		pantherclawv1.Decision_DECISION_DENY: "DENY", pantherclawv1.Decision_DECISION_CANNOT_AUTHORIZE: "CANNOT_AUTHORIZE",
	}[ev.GetTransaction().GetDecision()]
	if recs := ev.GetDecisionReceipts(); len(recs) > 0 {
		s.Receipt = receiptParts(recs[len(recs)-1].GetReceiptJws())
	}
	list, err := r.approvals.ListApprovalRequests(ctx, &pantherclawv1.ListApprovalRequestsRequest{RunId: &r.run, PageSize: 200})
	if err != nil {
		return live.TxnState{}, err
	}
	for _, q := range list.GetRequests() {
		if q.GetTransactionId() != id {
			continue
		}
		switch q.GetState() {
		case pantherclawv1.ApprovalState_APPROVAL_STATE_APPROVED, pantherclawv1.ApprovalState_APPROVAL_STATE_CONSUMED:
			s.Approved = true
		case pantherclawv1.ApprovalState_APPROVAL_STATE_DECLINED:
			s.Declined = true
		default:
		}
	}
	return s, nil
}

// ttyOperator asks the person at the terminal to decide a held transaction.
type ttyOperator struct{ a *app }

func (o ttyOperator) Decide(_ context.Context, txn, role string, approve bool) error {
	verb := "APPROVE"
	if !approve {
		verb = "DECLINE"
	}
	_, _ = fmt.Fprintf(o.a.stdout, "\nA person must %s transaction %s as %s.\n"+
		"Open the pending approvals in the PantherClaw console, check it shows SIMULATED, and decide it.\nPress Enter when done: ", verb, txn, role)
	_, err := bufio.NewReader(o.a.stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// receiptParts reads which parts a decision receipt (a compact JWS) carries:
// the grant (a checklist line about it), the policy version, the package
// version (the pinned definition's digest), the facts and the simulated mark.
func receiptParts(jws string) map[string]bool {
	segs := strings.Split(jws, ".")
	if len(segs) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return nil
	}
	var p struct {
		Checklist []struct {
			Check string `json:"check"`
		} `json:"checklist"`
		Basis struct {
			Policy     string `json:"policy"`
			Definition string `json:"definition"`
			Facts      string `json:"facts"`
		} `json:"basis"`
		Simulated bool `json:"simulated"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return nil
	}
	out := map[string]bool{
		"policy_version":  p.Basis.Policy != "" && p.Basis.Policy != "none",
		"package_version": p.Basis.Definition != "",
		"facts":           p.Basis.Facts != "",
		"simulated":       p.Simulated,
	}
	for _, it := range p.Checklist {
		if strings.Contains(strings.ToLower(it.Check), "grant") {
			out["grant"] = true
		}
	}
	return out
}
