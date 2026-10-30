// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/ecsfacts"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	awssim "github.com/katocxl/pantherclaw/internal/sim/aws"
	tdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
	pcawsecs "github.com/katocxl/pantherclaw/packages/pc-aws-ecs"
)

type openContainment struct{ Containment }

func (openContainment) Check() (int64, error)    { return 1, nil }
func (openContainment) Connection(string) string { return "" }

type ecsFixture struct {
	e    *Engine
	conn *control.Connection
	sim  *awssim.Server
	pkg  *defs.Package
}

func newECSFixture(t *testing.T) *ecsFixture {
	t.Helper()
	const secret = "simulated/base+secret0123456789"
	sim := awssim.New(secret, "", []string{"*"}, awssim.Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	plain, err := credentials.AWSSigV4{
		V: 1, AccessKeyID: awssim.BaseKeyID, SecretAccessKey: []byte(secret), RoleARN: awssim.RoleARN,
		STSURL: srv.URL, STSRegion: awssim.Region, Region: awssim.Region, Service: "ecs",
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p, err := manifest.Decode(pcawsecs.Package)
	if err != nil {
		t.Fatal(err)
	}
	return &ecsFixture{
		sim: sim, pkg: p,
		e: &Engine{
			broker: &plainOpener{plain: plain}, allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
			clients: map[string]clientEntry{}, tokenClients: map[string]clientEntry{}, log: pclog.Discard(), containment: openContainment{},
			factTimeout: 5 * time.Second,
		},
		conn: &control.Connection{
			GatewayConnection: &pb.GatewayConnection{Id: "c", Kind: "http", State: "ACTIVE", BaseUrl: srv.URL, AccessMode: "pantherclaw_held"}, Package: p,
			Credential: &pb.SealedCredential{
				Kind: credentials.KindAWSSigV4, AllowedHosts: []string{u.Host}, Header: "Authorization", Scheme: credentials.AWSSigV4Scheme,
			},
		},
	}
}

func deployTarget() actionir.Target {
	return actionir.Target{Type: "aws_ecs_service", ID: awssim.ServiceTarget, Account: awssim.Account}
}

// deploy dispatches a deploy of revision on target and returns the status.
func (f *ecsFixture) deploy(t *testing.T, target actionir.Target, revision int) (int, error) {
	t.Helper()
	def, _ := f.pkg.Definition("aws.ecs.service.deploy")
	raw, err := json.Marshal(map[string]string{"task_definition": awssim.TaskDefinition(revision), "deployment_controller": "ECS"})
	if err != nil {
		t.Fatal(err)
	}
	a := actionir.Parsed{Action: actionir.ActionIR{Operation: def.Operation, Target: target, Params: raw}}
	p, err := f.e.prepare(context.Background(), f.conn, def, a, "01920000-0000-7000-8000-000000000009")
	if err != nil {
		t.Fatal(err)
	}
	_, release, _, err := f.e.credential(context.Background(), f.conn, def, target, p.req, p.client, "")
	if err != nil {
		return 0, err
	}
	defer release()
	res, err := p.client.Do(p.req)
	return res.Status, err
}

// verify is the gateway's read of a task the server would lease.
func (f *ecsFixture) verify(t *testing.T, op, mode string, params map[string]string) (Observation, error) {
	t.Helper()
	req, err := json.Marshal(verifyRequest{Mode: mode, Target: actionir.Target{Type: "aws_ecs_service", ID: awssim.ServiceTarget}, Params: params})
	if err != nil {
		t.Fatal(err)
	}
	return f.e.VerifyEffect(context.Background(), f.conn, Lease{Connection: "c", Purpose: "verification", Operation: op, Request: req})
}

// rollout is what the server would assess from a read of the rollout.
func (f *ecsFixture) rollout(t *testing.T, revision int) tdomain.Assessment {
	t.Helper()
	o, err := f.verify(t, "aws.ecs.service.deployments.read", "lookup", map[string]string{"task_definition": awssim.TaskDefinition(revision)})
	if err != nil {
		t.Fatal(err)
	}
	def, _ := f.pkg.Definition("aws.ecs.service.rollout")
	at := time.Now()
	return tdomain.Assess(def.Verifier, tdomain.PurposeConsequence, nil, tdomain.Observation{
		HTTPStatus: o.HTTPStatus, Found: o.Found, Complete: o.Complete, Fields: o.Fields, At: at,
	}, at)
}

// TestHR525_ADeployRunsInASessionOfItsOneServiceAndAction: the write's
// session allows UpdateService on the target's ARN and nothing else, each
// read's allows DescribeServices, and a target in another account is
// refused before AWS hears of it (D270, T-225).
// Covers: HR-525, T-225
func TestHR525_ADeployRunsInASessionOfItsOneServiceAndAction(t *testing.T) {
	f := newECSFixture(t)
	if status, err := f.deploy(t, deployTarget(), 2); err != nil || status != 200 {
		t.Fatalf("deploy: %d %v", status, err)
	}
	if f.sim.ServiceTaskDefinition() != awssim.TaskDefinition(2) {
		t.Fatalf("the service runs %s", f.sim.ServiceTaskDefinition())
	}
	calls := f.sim.Calls()
	write := calls[len(calls)-1]
	if write.Action != "UpdateService" || write.Key != "session" || !slices.Equal(write.Policy, []string{"ecs:UpdateService"}) ||
		write.Resource != "arn:aws:ecs:"+awssim.Region+":"+awssim.Account+":service/"+awssim.ServiceTarget {
		t.Fatalf("write %+v", write)
	}
	if _, err := f.verify(t, "aws.ecs.service.read", "reference", map[string]string{}); err != nil {
		t.Fatal(err)
	}
	calls = f.sim.Calls()
	if read := calls[len(calls)-1]; read.Action != "DescribeServices" || !slices.Equal(read.Policy, []string{"ecs:DescribeServices"}) {
		t.Fatalf("read %+v", read)
	}

	n := len(f.sim.Calls())
	other := deployTarget()
	other.Account = "999999999999"
	if _, err := f.deploy(t, other, 3); !errors.Is(err, errAWSAccount) {
		t.Fatalf("another account: %v", err)
	}
	if len(f.sim.Calls()) != n {
		t.Fatal("a refused deploy reached AWS")
	}
	// A session for one service cannot touch another, whatever it signs.
	other = deployTarget()
	other.ID = awssim.Cluster + "/api"
	if status, err := f.deploy(t, other, 3); err != nil || status == 200 {
		t.Fatalf("another service: %d %v", status, err)
	}
	if f.sim.ServiceTaskDefinition() != awssim.TaskDefinition(2) {
		t.Fatal("the deploy changed the service")
	}
}

// TestHR191_TheRolloutIsConfirmedOnlyByECSReportingItComplete: the deploy's
// verifier shows the revision and captures it, and the rollout it starts is
// pending while in progress, confirmed only when ECS says COMPLETED, and a
// person's question when it failed, when deployments of that revision
// disagree, or when ECS reports no state at all (D284).
// Covers: HR-191, HR-190, F756
func TestHR191_TheRolloutIsConfirmedOnlyByECSReportingItComplete(t *testing.T) {
	f := newECSFixture(t)
	if status, err := f.deploy(t, deployTarget(), 2); err != nil || status != 200 {
		t.Fatalf("deploy: %d %v", status, err)
	}
	o, err := f.verify(t, "aws.ecs.service.read", "reference", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	def, _ := f.pkg.Definition("aws.ecs.service.deploy")
	got := tdomain.Assess(def.Verifier, tdomain.PurposeFollowUp, tdomain.Expected{"/services/0/taskDefinition": awssim.TaskDefinition(2)},
		tdomain.Observation{HTTPStatus: o.HTTPStatus, Found: o.Found, Complete: o.Complete, Fields: o.Fields, At: time.Now()}, time.Now())
	if got.State != tdomain.Confirmed || got.Level != defs.LevelDomainEffect {
		t.Fatalf("the deploy: %+v from %+v", got, o)
	}

	if a := f.rollout(t, 2); a.State != tdomain.PropagationPending || a.Final {
		t.Fatalf("in progress: %+v", a)
	}
	if a := f.rollout(t, 3); a.State != tdomain.PropagationPending || a.Reason != tdomain.ReasonNotFoundYet {
		t.Fatalf("not started: %+v", a)
	}

	f.sim.SetRollout(awssim.RolloutCompleted)
	if a := f.rollout(t, 2); a.State != tdomain.Confirmed || !a.Final {
		t.Fatalf("completed: %+v", a)
	}

	f.sim.SetRollout(awssim.RolloutFailed)
	if a := f.rollout(t, 2); !a.NeedsPerson || !a.Final || a.State == tdomain.Confirmed {
		t.Fatalf("failed: %+v", a)
	}

	f.sim.SetRollout("")
	if a := f.rollout(t, 2); a.State == tdomain.Confirmed || a.Final {
		t.Fatalf("no state: %+v", a)
	}
	if tdomain.AtDeadline(tdomain.Assessment{ObjectFound: true, Reason: tdomain.ReasonStatusOther}) != tdomain.Unknown {
		t.Fatal("no state at the deadline must stay unknown, for a person")
	}

	// Two deployments of the revision that differ: neither one wins.
	f.sim.SetRollout(awssim.RolloutCompleted)
	f.sim.AddDeployment(awssim.TaskDefinition(2), awssim.RolloutFailed)
	if a := f.rollout(t, 2); !a.NeedsPerson || a.State == tdomain.Confirmed {
		t.Fatalf("a disagreement: %+v", a)
	}
}

// TestHR190_TheGatewayPostsOnlyDescribeServices: the gateway refuses, without
// a request, any other POST a package may name as a verification read, even
// one that reached it past package validation (D283).
// Covers: HR-190
func TestHR190_TheGatewayPostsOnlyDescribeServices(t *testing.T) {
	const op = "aws.ecs.service.read"
	for name, change := range map[string]func(*defs.Definition){
		"UpdateService": func(d *defs.Definition) {
			d.Dispatch.HTTP.Headers["X-Amz-Target"] = "AmazonEC2ContainerServiceV20141113.UpdateService"
		},
		"a near match": func(d *defs.Definition) {
			d.Dispatch.HTTP.Headers["X-Amz-Target"] = defs.ECSDescribeServicesTarget + "X"
		},
		"a write":        func(d *defs.Definition) { d.Access = defs.AccessWrite },
		"another target": func(d *defs.Definition) { d.Dispatch.HTTP.Encoding = defs.EncodingJSON },
	} {
		t.Run(name, func(t *testing.T) {
			f := newECSFixture(t)
			read, _ := f.pkg.Definition(op)
			change(read)
			if read.VerificationRead() {
				t.Fatal("it passed as a verification read")
			}
			if _, err := f.verify(t, op, "reference", map[string]string{}); !errors.Is(err, ErrNotReviewedRead) {
				t.Fatalf("VerifyEffect: %v", err)
			}
			if _, ok := f.e.readWith(context.Background(), f.conn, read, deployTarget(), nil, ""); ok {
				t.Fatal("readWith sent it")
			}
			if len(f.sim.Calls()) != 0 {
				t.Fatalf("AWS heard %+v", f.sim.Calls())
			}
		})
	}
}

// TestHR191_TheControllerFactIsWhatECSNames: the deploy's fact is the
// controller DescribeServices names, read before the decision, and unread
// when the service names none or cannot be read: never ECS by default (D284,
// HR-160).
// Covers: HR-191, HR-160
func TestHR191_TheControllerFactIsWhatECSNames(t *testing.T) {
	report := func(f *ecsFixture) map[string]map[string]any {
		var got []*pb.FactObservation
		f.e.reportFacts = func(_ context.Context, _ string, obs []*pb.FactObservation) error {
			got = obs
			return nil
		}
		tried, err := f.e.reportECSFacts(context.Background(), f.conn, actionir.ActionIR{Operation: "aws.ecs.service.deploy", Target: deployTarget()})
		if !tried || err != nil || len(got) != 1 || got[0].GetName() != ecsfacts.ServiceController || got[0].GetSubjectId() != awssim.ServiceTarget {
			t.Fatalf("report %v %v %+v", tried, err, got)
		}
		var v map[string]map[string]any
		if err := json.Unmarshal(got[0].GetValue(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	f := newECSFixture(t)
	if v := report(f); v["object"]["type"] != "ECS" {
		t.Fatalf("%v", v)
	}
	f.sim.SetController("CODE_DEPLOY")
	if v := report(f); v["object"]["type"] != "CODE_DEPLOY" {
		t.Fatalf("%v", v)
	}
	f.sim.SetController("")
	if v := report(f); v["object"]["type"] != nil || v["object"]["unread"] == nil {
		t.Fatalf("%v", v)
	}
	if tried, _ := f.e.reportECSFacts(context.Background(), f.conn, actionir.ActionIR{Operation: "aws.ecs.service.read"}); tried {
		t.Fatal("a read needs no fact")
	}
}

// countingHost is a host that is not AWS, which counts what reaches it.
func countingHost(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"services":[{"status":"ACTIVE"}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

// attackFixture is a connection to a host that is not AWS, bound by its
// seal along with STS, so that only the rule a case breaks can stop the read:
// change runs last, and a static credential opens as a token it may place.
func attackFixture(t *testing.T, op string, change func(*ecsFixture, *defs.Definition)) (*ecsFixture, *defs.Definition, *atomic.Int32) {
	t.Helper()
	f := newECSFixture(t)
	host, hits := countingHost(t)
	sts, _ := url.Parse(f.conn.GetBaseUrl())
	u, _ := url.Parse(host.URL)
	f.conn.BaseUrl = host.URL
	f.conn.Credential.AllowedHosts = []string{u.Host, sts.Host}
	read, _ := f.pkg.Definition(op)
	change(f, read)
	if f.conn.Credential != nil && f.conn.Credential.GetKind() == credentials.KindStatic {
		f.conn.Credential.AllowedHosts = []string{u.Host}
		f.e.broker = &plainOpener{plain: []byte("static-token-not-real")}
	}
	return f, read, hits
}

// TestHR190_TheAttackFixtureReachesItsHost is the control for the attack
// test: left alone, the read does reach the host, so each case below is
// refused for the rule it breaks.
// Covers: HR-190
func TestHR190_TheAttackFixtureReachesItsHost(t *testing.T) {
	f, read, hits := attackFixture(t, "aws.ecs.service.deployments.read", func(*ecsFixture, *defs.Definition) {})
	if _, ok := f.e.readWith(context.Background(), f.conn, read, deployTarget(), nil, ""); !ok || hits.Load() != 1 {
		t.Fatalf("read %v, %d requests", ok, hits.Load())
	}
}

// TestHR190_AWriteShapedPOSTIsNeverAVerificationRead is the attack from the
// review of #496: a package read that names the exact target but also sends
// a method override, a query and an action's param, to a host that is not
// AWS, under a static credential. Each part alone is refused, and nothing
// reaches the host (D290).
// Covers: HR-190, T-225
func TestHR190_AWriteShapedPOSTIsNeverAVerificationRead(t *testing.T) {
	const op = "aws.ecs.service.deployments.read"
	param := map[string]string{"task_definition": awssim.TaskDefinition(2)}
	for name, change := range map[string]func(*ecsFixture, *defs.Definition){
		"the whole attack": func(f *ecsFixture, d *defs.Definition) {
			f.pkg.Name, f.pkg.Publisher = "acme.tools", "acme"
			h := d.Dispatch.HTTP
			h.Headers["X-HTTP-Method-Override"], h.Query, h.Body["cmd"] = "DELETE", map[string]string{"force": "target.id"}, "params.task_definition"
			f.conn.Credential = &pb.SealedCredential{Kind: credentials.KindStatic, Header: "Authorization", Scheme: "Bearer"}
		},
		"an extra header": func(_ *ecsFixture, d *defs.Definition) { d.Dispatch.HTTP.Headers["X-HTTP-Method-Override"] = "DELETE" },
		"a query": func(_ *ecsFixture, d *defs.Definition) {
			d.Dispatch.HTTP.Query = map[string]string{"force": "target.id"}
		},
		"a param in the body": func(_ *ecsFixture, d *defs.Definition) { d.Dispatch.HTTP.Body["cmd"] = "params.task_definition" },
		"a literal in the body": func(_ *ecsFixture, d *defs.Definition) {
			d.Dispatch.HTTP.Body["cmd"] = "literal.drop-all-tables"
		},
		"an idempotency header": func(_ *ecsFixture, d *defs.Definition) { d.Dispatch.HTTP.IdempotencyHeader = "Idempotency-Key" },
		"an org package":        func(f *ecsFixture, _ *defs.Definition) { f.pkg.Name = "acme.tools" },
		"another publisher":     func(f *ecsFixture, _ *defs.Definition) { f.pkg.Publisher = "acme" },
		"a static credential": func(f *ecsFixture, _ *defs.Definition) {
			f.conn.Credential = &pb.SealedCredential{Kind: credentials.KindStatic, Header: "Authorization", Scheme: "Bearer"}
		},
		"no credential":       func(f *ecsFixture, _ *defs.Definition) { f.conn.Credential = nil },
		"an unsealed mode":    func(f *ecsFixture, _ *defs.Definition) { f.conn.AccessMode = "none" },
		"another access mode": func(f *ecsFixture, _ *defs.Definition) { f.conn.AccessMode = "target_enforced" },
	} {
		t.Run(name, func(t *testing.T) {
			f, read, hits := attackFixture(t, op, change)
			o, _ := f.verify(t, op, "lookup", param)
			if o.Found || o.HTTPStatus != 0 {
				t.Fatalf("observed %+v", o)
			}
			if _, ok := f.e.readWith(context.Background(), f.conn, read, deployTarget(), param, ""); ok {
				t.Fatal("readWith sent it")
			}
			if hits.Load() != 0 {
				t.Fatalf("the host heard %d requests", hits.Load())
			}
		})
	}
}

// TestHR190_TheExceptionNeedsASessionSealedForECS: a held AWS credential
// sealed for another service never reads, and neither does one whose seal
// does not bind the connection's host (D290).
// Covers: HR-190, HR-060
func TestHR190_TheExceptionNeedsASessionSealedForECS(t *testing.T) {
	const op = "aws.ecs.service.read"
	f := newECSFixture(t)
	plain, err := credentials.AWSSigV4{
		V: 1, AccessKeyID: awssim.BaseKeyID, SecretAccessKey: []byte("simulated/base+secret0123456789"), RoleARN: awssim.RoleARN,
		STSURL: f.conn.GetBaseUrl(), STSRegion: awssim.Region, Region: awssim.Region, Service: "iam",
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	f.e.broker = &plainOpener{plain: plain}
	if o, err := f.verify(t, op, "reference", map[string]string{}); err != nil || o.Found {
		t.Fatalf("sealed for iam: %+v %v", o, err)
	}
	if len(f.sim.Calls()) != 0 {
		t.Fatalf("AWS heard %+v", f.sim.Calls())
	}

	f = newECSFixture(t)
	f.conn.Credential.AllowedHosts = []string{"ecs.us-east-1.amazonaws.com"}
	if o, err := f.verify(t, op, "reference", map[string]string{}); err != nil || o.Found {
		t.Fatalf("an unbound host: %+v %v", o, err)
	}
	if len(f.sim.Calls()) != 0 {
		t.Fatalf("AWS heard %+v", f.sim.Calls())
	}
}
