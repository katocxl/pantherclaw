// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http/httptest"
	"regexp"
	"slices"
	"testing"
	"time"

	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/sim/aws"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// capAWSECS: an agent deploying through pc.aws.ecs. The harness only: on a
// live range it would be a real deploy (G0 M20 D286).
const capAWSECS app.Capability = "aws.ecs.deploy"

const (
	awsSecret       = "simulated/base+secret0123456789"
	awsOtherAccount = "999999999999"
)

var seededAWSECS = regexp.MustCompile(`seeded aws-ecs connection ([0-9a-f-]{36}) `)

// awsSim is the AWS simulator of a stack and the seeded connection "aws-ecs"
// to it.
type awsSim struct {
	sim  *aws.Server
	url  string
	conn ids.UUID
}

func startAWSSim(t *testing.T) *awsSim {
	t.Helper()
	s := aws.New(awsSecret, "", []string{"*"}, aws.Faults{}, pclog.Discard())
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &awsSim{sim: s, url: srv.URL}
}

func (a *awsSim) seeded(t *testing.T, out string) {
	t.Helper()
	m := seededAWSECS.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("dev seed output %q", out)
	}
	a.conn = mustUUID(t, m[1])
}

// sealAWSECS seals the simulator's base key for the connection, as pclaw seal
// does, and returns the configuration version the gateway must reach.
func (s *stack) sealAWSECS(t *testing.T) int64 {
	t.Helper()
	plain, err := creddomain.AWSSigV4{
		V: 1, AccessKeyID: aws.BaseKeyID, SecretAccessKey: []byte(awsSecret), RoleARN: aws.RoleARN,
		STSURL: s.aws.url, STSRegion: aws.Region, Region: aws.Region, Service: "ecs",
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	id := ids.NewV7()
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'aws-gateway-admin')", s.org.UUID(), id)
	admin := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: id},
		Bindings: []td.Binding{{Role: td.RoleGatewayAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	svc := credapp.New(s.pool, nil)
	k, err := svc.GetSealingKey(admin, s.aws.conn)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k.Binding.Kind = creddomain.KindAWSSigV4
	sealed, err := pccrypto.Seal(pub, k.Binding.Info(), creddomain.AAD, plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutCredential(admin, credapp.PutInput{
		Connection: s.aws.conn, BrokerKey: mustUUID(t, k.Binding.BrokerKey), Version: k.Binding.Version, Sealed: sealed,
		AllowedHosts: k.Binding.AllowedHosts, Header: k.Binding.Header, Scheme: k.Binding.Scheme, Kind: creddomain.KindAWSSigV4,
	}); err != nil {
		t.Fatal(err)
	}
	return s.configVersion(t, k.Gateway)
}

// setupAWSECS gives the scenario's agent a grant over the simulator's three
// services, and names them to scenarios.
func (d *rangeDriver) setupAWSECS() {
	if !requires(d.sc, string(capAWSECS)) {
		return
	}
	if d.fix == nil {
		d.fix = app.Fixture{}
	}
	d.fix["aws_account"], d.fix["aws_other_account"], d.fix["aws_cluster"] = aws.Account, awsOtherAccount, aws.Cluster
	d.fix["aws_service"], d.fix["aws_classic_service"], d.fix["aws_codedeploy_service"] = aws.Service, aws.ClassicService, aws.CodeDeployService
	d.fix["aws_task_definition"] = aws.TaskDefinition(2)
	d.ownGrant(`{"operations": ["aws.ecs.service.deploy", "aws.ecs.service.read", "aws.ecs.service.rollout", "aws.ecs.service.deployments.read"],
		"targets": {"aws_ecs_service": {"ids": ["`+aws.ServiceTarget+`", "`+aws.Cluster+"/"+aws.ClassicService+`", "`+aws.Cluster+"/"+aws.CodeDeployService+`"]}}}`, "")
}

// consequenceOf is the transaction opened as a consequence of txn, or "".
func (s *stack) consequenceOf(t *testing.T, txn string) string {
	t.Helper()
	var out string
	s.query(t, `SELECT coalesce((SELECT to_transaction_id::text FROM pc.transaction_links
		WHERE from_transaction_id = $1 AND kind = 'consequence'), '')`, []any{txn}, &out)
	return out
}

// waitDownstreamRead is the wait for downstream_read: it hurries the
// consequence of txn's verification until the gateway has read it, then
// observes the action's downstream state: CONFIRMED only if that read
// confirmed it, UNKNOWN otherwise. No read within the time is an error,
// never UNKNOWN: this step proves a read that did not confirm.
func (d *rangeDriver) waitDownstreamRead(ctx context.Context, txn string, maxSeconds int) (domain.Observation, error) {
	s, deadline := d.s, time.Now().Add(time.Duration(maxSeconds)*time.Second)
	for {
		if c := s.consequenceOf(d.t, txn); c != "" {
			s.db.AdminExec(d.t, "UPDATE pc.verifications SET next_at = now() WHERE transaction_id = $1 AND state = 'PENDING'", mustUUID(d.t, c))
			var reads int
			s.query(d.t, "SELECT count(*) FROM pc.observations WHERE transaction_id = $1 AND found", []any{c}, &reads)
			if reads > 0 {
				var state string
				s.query(d.t, "SELECT coalesce(downstream_state, '') FROM pc.transactions WHERE id = $1", []any{txn}, &state)
				if state == "CONFIRMED" {
					return domain.Observation{Outcome: domain.OutcomeConfirmed, TransactionID: txn}, nil
				}
				return domain.Observation{Outcome: domain.OutcomeUnknown, TransactionID: txn, Detail: "downstream state " + state}, nil
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return domain.Observation{}, fmt.Errorf("the consequence of %s was not read within %d s", txn, maxSeconds)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ecsDeploy has the agent deploy to service in account through the MCP tool.
func (d *rangeDriver) ecsDeploy(t *testing.T, service, account string, revision int) domain.Observation {
	t.Helper()
	args, err := json.Marshal(map[string]string{
		"account_id": account, "cluster": aws.Cluster, "service": service, "task_definition": aws.TaskDefinition(revision),
	})
	if err != nil {
		t.Fatal(err)
	}
	obs, _, err := d.callOnce(callWith{Face: "mcp", Connection: "aws-ecs", Tool: "aws_ecs_deploy_service", Args: args}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

func newECSDriver(t *testing.T, id string) (*rangeDriver, *stack) {
	t.Helper()
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, awsECS: true})
	d := newRangeDriver(t)
	d.s, d.people = s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	d.sc = domain.Scenario{ID: id, Requires: []string{string(capAWSECS)}}
	d.setupAWSECS()
	return d, s
}

const (
	ecsEffect     = "SELECT coalesce(effect_state, '') FROM pc.transactions WHERE id = $1"
	ecsDownstream = "SELECT coalesce(downstream_state, '') FROM pc.transactions WHERE id = $1"
)

// TestHR451_ARolloutIsVerifiedFromECSsOwnRecord is the deploy's M17 path on
// the real stack (HR-190, HR-451, G0 M20 D286): the credential is sealed and
// stored, the verifier's POST read runs, the confirmed deploy opens its
// rollout as a consequence transaction in Postgres from the revision it
// captured, and the deploy stays downstream PENDING until ECS reports the
// rollout complete.
//
// Covers: HR-190, HR-451, HR-525, F756
func TestHR451_ARolloutIsVerifiedFromECSsOwnRecord(t *testing.T) {
	d, s := newECSDriver(t, "M20-ECS")
	obs := d.ecsDeploy(t, aws.Service, aws.Account, 2)
	if obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("deploy: %+v", obs)
	}
	if s.aws.sim.ServiceTaskDefinition() != aws.TaskDefinition(2) {
		t.Fatalf("the service runs %s", s.aws.sim.ServiceTaskDefinition())
	}
	s.eventually(t, "CONFIRMED", ecsEffect, obs.TransactionID)
	s.eventually(t, "PENDING", ecsDownstream, obs.TransactionID)
	consequence := s.consequenceOf(t, obs.TransactionID)
	if consequence == "" {
		t.Fatal("no consequence transaction for the rollout")
	}
	var op, target, param string
	s.query(t, "SELECT operation, target_id FROM pc.transactions WHERE id = $1", []any{consequence}, &op, &target)
	if op != "aws.ecs.service.rollout" || target != aws.ServiceTarget {
		t.Fatalf("consequence %s %s", op, target)
	}
	s.query(t, `SELECT request->'params'->>'task_definition' FROM pc.verifications WHERE transaction_id = $1`, []any{mustUUID(t, consequence)}, &param)
	if param != aws.TaskDefinition(2) {
		t.Fatalf("the rollout looks for %q", param)
	}

	// In progress: read, and still pending.
	hurry := func() {
		s.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() WHERE transaction_id = $1 AND state = 'PENDING'", mustUUID(t, consequence))
	}
	reads := func() (n int) {
		s.query(t, "SELECT count(*) FROM pc.observations WHERE transaction_id = $1", []any{consequence}, &n)
		return n
	}
	for end := time.Now().Add(20 * time.Second); reads() == 0; time.Sleep(200 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the rollout was not read")
		}
		hurry()
	}
	var state string
	s.query(t, ecsDownstream, []any{obs.TransactionID}, &state)
	if state != "PENDING" {
		t.Fatalf("a rollout in progress: downstream %s", state)
	}

	s.aws.sim.SetRollout(aws.RolloutCompleted)
	hurry()
	s.eventually(t, "CONFIRMED", ecsEffect, consequence)
	s.eventually(t, "CONFIRMED", ecsDownstream, obs.TransactionID)

	var actions []string
	for _, c := range s.aws.sim.Calls() {
		if c.Key == "session" && !slices.Contains(actions, c.Action) {
			actions = append(actions, c.Action)
		}
		if c.Action == "UpdateService" && (len(c.Policy) != 1 || c.Policy[0] != "ecs:UpdateService") {
			t.Fatalf("the deploy's session: %+v", c)
		}
	}
	if !slices.Contains(actions, "DescribeServices") || !slices.Contains(actions, "UpdateService") {
		t.Fatalf("calls: %v", actions)
	}
}

// TestHR191_ARolloutWithNoStateGoesToAPerson: when ECS reports no rollout
// state, nothing confirms the rollout, and at the end of its window a person
// is asked: the deploy's downstream state is UNCONFIRMED (D284).
//
// Covers: HR-191, HR-451
func TestHR191_ARolloutWithNoStateGoesToAPerson(t *testing.T) {
	d, s := newECSDriver(t, "M20-ECS-CLASSIC")
	obs := d.ecsDeploy(t, aws.ClassicService, aws.Account, 2)
	if obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("deploy: %+v", obs)
	}
	s.eventually(t, "CONFIRMED", ecsEffect, obs.TransactionID)
	s.eventually(t, "PENDING", ecsDownstream, obs.TransactionID)
	consequence := s.consequenceOf(t, obs.TransactionID)
	if consequence == "" {
		t.Fatal("no consequence transaction for the rollout")
	}
	s.db.AdminExec(t, `UPDATE pc.verifications SET next_at = now(), deadline_at = now() WHERE transaction_id = $1 AND state = 'PENDING'`, mustUUID(t, consequence))
	s.eventually(t, "UNCONFIRMED", ecsDownstream, obs.TransactionID)
	var state string
	s.query(t, ecsEffect, []any{consequence}, &state)
	if state == "CONFIRMED" {
		t.Fatal("a rollout with no state was confirmed")
	}
}

// TestT225_ADeployInAnotherAccountNeverReachesAWS: a deploy naming another
// account than the role's is refused at the gateway: AWS never sees it, the
// service does not change, and no rollout is opened (HR-525).
//
// Covers: HR-525, T-225
func TestT225_ADeployInAnotherAccountNeverReachesAWS(t *testing.T) {
	d, s := newECSDriver(t, "M20-ECS-ACCOUNT")
	obs := d.ecsDeploy(t, aws.Service, awsOtherAccount, 2)
	if obs.Outcome == domain.OutcomeAllow {
		t.Fatalf("deploy: %+v", obs)
	}
	if s.aws.sim.ServiceTaskDefinition() != aws.TaskDefinition(1) {
		t.Fatal("the service changed")
	}
	for _, c := range s.aws.sim.Calls() {
		if c.Action == "UpdateService" {
			t.Fatalf("AWS heard %+v", c)
		}
	}
}

// TestHR191_AnotherControllerIsNeverDeployedTo: a service under another
// deployment controller is CANNOT_AUTHORIZE, and nothing is sent.
//
// Covers: HR-191
func TestHR191_AnotherControllerIsNeverDeployedTo(t *testing.T) {
	d, s := newECSDriver(t, "M20-ECS-CONTROLLER")
	obs := d.ecsDeploy(t, aws.CodeDeployService, aws.Account, 2)
	if obs.Outcome != domain.OutcomeCannotAuthorize || !slices.Contains(obs.Reasons, "VERIFIER_UNSUPPORTED") {
		t.Fatalf("deploy: %+v", obs)
	}
	for _, c := range s.aws.sim.Calls() {
		if c.Action == "UpdateService" {
			t.Fatalf("AWS heard %+v", c)
		}
	}
}
