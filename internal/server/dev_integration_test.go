// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// serve starts cmdServe with cfgPath and returns the API base URL.
func serve(t *testing.T, cfgPath string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	addrCh := make(chan string, 1)
	done := make(chan error, 1)
	var logs bytes.Buffer
	go func() {
		done <- cmdServe(ctx, []string{"--config", cfgPath}, &logs, noEnv, func(a string) { addrCh <- a })
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("graceful shutdown did not finish")
		}
	})
	select {
	case a := <-addrCh:
		return "http://" + a
	case err := <-done:
		t.Fatalf("serve exited early: %v\n%s", err, logs.String())
	case <-time.After(60 * time.Second):
		t.Fatal("server did not start")
	}
	return ""
}

var (
	seededOrg        = regexp.MustCompile(`seeded org ([0-9a-f-]{36}) `)
	seededConnection = regexp.MustCompile(`seeded connection ([0-9a-f-]{36}) `)
)

// devConn is the payments connection of the last seed with a gateway.
var devConn ids.UUID

// seed runs `dev seed` and returns the org, the gateway enrollment file
// ("" without withGateway), the workload key file and the fact provider's
// API key file. With a gateway it also seeds the payments connection and
// sets devConn. The same configuration (and so the same key-encryption key)
// must serve afterwards: seeding a gateway creates the CA key.
func seed(t *testing.T, cfgPath, limit string, withGateway bool) (ids.OrgID, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	enrollFile, keyFile, factsFile := filepath.Join(dir, "gateway.json"), filepath.Join(dir, "workload.json"), filepath.Join(dir, "facts.key")
	var out, errb bytes.Buffer
	args := []string{
		"dev", "seed", "--config", cfgPath, "--org-name", "acme", "--budget-limit", limit,
		"--workload-out", keyFile, "--facts-key-out", factsFile,
	}
	if withGateway {
		args = append(args, "--gateway-out", enrollFile, "--target-url", "http://127.0.0.1:9")
	} else {
		enrollFile = ""
	}
	if code := Run(context.Background(), args, &out, &errb, noEnv); code != 0 {
		t.Fatalf("dev seed: %d %s", code, errb.String())
	}
	m := seededOrg.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("dev seed output %q", out.String())
	}
	if withGateway {
		c := seededConnection.FindStringSubmatch(out.String())
		if c == nil {
			t.Fatalf("dev seed output %q has no connection", out.String())
		}
		var err error
		if devConn, err = ids.ParseUUID(c[1]); err != nil {
			t.Fatal(err)
		}
	}
	if code := Run(context.Background(), args, &out, &errb, noEnv); code == 0 {
		t.Fatal("dev seed overwrote an existing key file")
	}
	return ids.MustParse[ids.Org](m[1]), enrollFile, keyFile, factsFile
}

// gatewayAt opens the mTLS gateway listener on addr.
func gatewayAt(addr string) func(map[string]any) {
	return func(c map[string]any) {
		c["gateway_api"] = map[string]any{"addr": addr, "hostnames": []string{"127.0.0.1"}, "url": "https://" + addr}
	}
}

// enrollGateway enrolls from a dev enrollment file and returns the
// gateway's mTLS control client.
func enrollGateway(t *testing.T, enrollFile string) *control.Client {
	t.Helper()
	b, err := os.ReadFile(enrollFile)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		APIURL   string `json:"api_url"`
		Token    string `json:"token"`
		CASHA256 string `json:"ca_sha256"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	id, err := control.Enroll(context.Background(), &http.Client{Timeout: 10 * time.Second}, f.APIURL, pclog.NewSecret(f.Token), f.CASHA256)
	if err != nil {
		t.Fatal(err)
	}
	return control.NewClient(id, "", "", 10*time.Second, pclog.Discard())
}

// workload is the seeded PAP/1 workload, acting through a gateway.
type workload struct {
	kf    workloadclient.KeyFile
	key   ed25519.PrivateKey
	inst  pap.Instance
	env   string
	token string
}

// seededWorkload reads the key file and gets a workload token from base.
func seededWorkload(t *testing.T, base, keyFile string) workload {
	t.Helper()
	kf, err := workloadclient.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := kf.Key()
	inst, err := pap.ParseInstance(kf.Identifier)
	if err != nil {
		t.Fatal(err)
	}
	wc := pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(
		&http.Client{Timeout: 10 * time.Second, Transport: &workloadclient.Transport{Key: key}}, base)))
	res, err := wc.IssueToken(context.Background(), &pantherclawv1.IssueTokenRequest{Identifier: kf.Identifier})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(res.GetWorkloadToken(), ".")[1])
	var claims struct {
		PAP struct {
			Env string `json:"env"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return workload{kf: kf, key: key, inst: inst, env: claims.PAP.Env, token: res.GetWorkloadToken()}
}

// refund is a refund of ch_1 by the seeded workload, mapped by the
// reference package.
func refund(t *testing.T, org ids.OrgID, wl workload, amount string) []byte {
	t.Helper()
	pkg, err := manifest.Decode(mockpayments.Package)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	p, err := m.MCP(context.Background(), mapping.Context{
		Org: org.String(), Env: wl.env, RunID: wl.kf.RunID, ActionID: ids.NewV7().String(), AgentInstance: wl.inst.Instance.String(),
		Connection: devConn.String(),
	}, "create_refund", []byte(`{"charge":"ch_1","amount":"`+amount+`","currency":"USD","reason":"duplicate"}`))
	if err != nil {
		t.Fatal(err)
	}
	return p.Canonical
}

// refundable reports ch_1 as refundable with the seeded fact provider's
// API key.
func refundable(t *testing.T, base, factsFile string) {
	t.Helper()
	key, err := os.ReadFile(factsFile)
	if err != nil {
		t.Fatal(err)
	}
	facts := pantherclawv1connect.NewFactServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 10 * time.Second, Transport: bearer{strings.TrimSpace(string(key))},
	}, base)))
	res, err := facts.PutFacts(context.Background(), &pantherclawv1.PutFactsRequest{Observations: []*pantherclawv1.FactObservation{{
		Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectId: "ch_1", Value: []byte(`{"bool": true}`),
		ObserveTime: timestamppb.Now(),
	}}})
	if err != nil || !res.GetResults()[0].GetAccepted() {
		t.Fatalf("PutFacts = %v, %v", res, err)
	}
}

type bearer struct{ tok string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

// creds are the PAP/1 credentials of one workload request, as a gateway
// would forward them.
func (wl workload) creds(t *testing.T, nonce string) *pantherclawv1.WorkloadCredentials {
	t.Helper()
	const url = "http://127.0.0.1:8090/v1/refunds"
	body := []byte(`{"charge":"ch_1","amount":"30.00","currency":"USD"}`)
	proof, err := pap.NewProof(wl.key, pap.ProofParams{Method: "POST", URL: url, Body: body, Token: wl.token, Nonce: nonce, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return &pantherclawv1.WorkloadCredentials{WorkloadToken: wl.token, Proof: proof, BodySha256: sum[:], Htm: "POST", Htu: url}
}

func authorize(client pantherclawv1connect.AuthorityServiceClient, action []byte, creds *pantherclawv1.WorkloadCredentials) (*pantherclawv1.AuthorizeResponse, error) {
	return client.Authorize(context.Background(), &pantherclawv1.AuthorizeRequest{ActionIr: action, Workload: creds})
}

// publicAt serves on addr and makes it the public URL, so workload proofs
// name the address they are sent to.
func publicAt(addr string) func(map[string]any) {
	return func(c map[string]any) {
		c["http"] = map[string]any{"addr": addr}
		c["auth"] = map[string]any{"public_url": "http://" + addr}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

// TestHR181_AGatewayEnrolledByDevSeedAuthorizesOverMTLS: a gateway enrolled
// from `dev seed --gateway-out` calls the Authority over mTLS as its org;
// without a certificate, or on the public API, it is refused; and the
// worker's sweeper releases an undispatched permit.
func TestHR181_AGatewayEnrolledByDevSeedAuthorizesOverMTLS(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAll, publicAt(freeAddr(t)), gatewayAt(freeAddr(t)), func(c map[string]any) {
		c["authority"] = map[string]any{"permit_ttl": "1s"}
	})
	org, enrollFile, keyFile, factsFile := seed(t, cfgPath, "100.00", true)
	base := serve(t, cfgPath)
	ctl := enrollGateway(t, enrollFile)
	if ctl.Identity().Org != org {
		t.Fatalf("the enrolled gateway serves %s, want %s", ctl.Identity().Org, org)
	}
	client := ctl.Authority
	wl := seededWorkload(t, base, keyFile)
	refundable(t, base, factsFile)
	nonce, err := client.GetNonce(context.Background(), &pantherclawv1.GetNonceRequest{})
	if err != nil {
		t.Fatal(err)
	}

	// The public API never acts as a gateway, whatever credential is sent.
	public := pantherclawv1connect.NewAuthorityServiceClient(connect.NewClient(connecthttp.NewTransport(
		&http.Client{Timeout: 10 * time.Second, Transport: bearer{"pcg_not_a_gateway_credential"}}, base)))
	if _, err := authorize(public, refund(t, org, wl, "30.00"), wl.creds(t, nonce.GetNonce())); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("Authorize on the public API: %v, want Unauthenticated", err)
	}
	// Without the workload's credentials nothing is authorized (HR-021).
	if res, err := authorize(client, refund(t, org, wl, "30.00"), nil); err != nil ||
		res.GetDecision() != pantherclawv1.Decision_DECISION_CANNOT_AUTHORIZE {
		t.Fatalf("Authorize without workload credentials = %v, %v", res, err)
	}
	res, err := authorize(client, refund(t, org, wl, "30.00"), wl.creds(t, nonce.GetNonce()))
	if err != nil || res.GetDecision() != pantherclawv1.Decision_DECISION_ALLOW || res.GetPermit() == "" {
		t.Fatalf("Authorize = %v, %v", res, err)
	}
	// The seeded hold policy holds a refund over 50.00 USD for an approver,
	// with its wait handle (S02).
	held, err := authorize(client, refund(t, org, wl, "60.00"), wl.creds(t, nonce.GetNonce()))
	if err != nil || held.GetDecision() != pantherclawv1.Decision_DECISION_REQUIRE_APPROVAL || held.GetPermit() != "" ||
		held.GetWait().GetHandle() != held.GetTransactionId() || held.GetWait().GetState() != pantherclawv1.WaitState_WAIT_STATE_PENDING ||
		held.GetWait().GetApprovalRequestId() == "" {
		t.Fatalf("a refund over the hold limit = %v, %v", held, err)
	}
	// Another org's action is denied: the org comes from the certificate.
	other, err := authorize(client, refund(t, ids.New[ids.Org](), wl, "30.00"), wl.creds(t, nonce.GetNonce()))
	if err != nil || other.GetDecision() != pantherclawv1.Decision_DECISION_DENY {
		t.Fatalf("cross-org Authorize = %v, %v", other, err)
	}

	// The worker's sweeper releases the undispatched permit after its 1s TTL
	// and then applies the release to the budget row (ADR-0015).
	p := d.AppPool(t)
	deadline := time.Now().Add(30 * time.Second)
	for {
		var state string
		var free bool
		err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
			if err := tx.QueryRow(ctx, "SELECT state FROM pc.permits WHERE transaction_id = $1", res.GetTransactionId()).Scan(&state); err != nil {
				return err
			}
			return tx.QueryRow(ctx, "SELECT reserved = 0 AND reserved_count = 0 FROM pc.budget_accounts").Scan(&free)
		})
		if err != nil {
			t.Fatal(err)
		}
		if state == "RELEASED" && free {
			break
		}
		if time.Now().After(deadline) {
			if state == "RELEASED" {
				t.Fatal("released permit left its reservation")
			}
			t.Fatalf("permit still %s after 30s", state)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestIntAuthorityRefusedOnThePublicAPI(t *testing.T) {
	d := dbtest.New(t)
	base := serve(t, testConfig(t, d, RoleAPI))
	client := pantherclawv1connect.NewAuthorityServiceClient(connect.NewClient(connecthttp.NewTransport(
		&http.Client{Timeout: 10 * time.Second, Transport: bearer{"any-token-any-token-any-token-any"}}, base)))
	_, err := client.Authorize(context.Background(), &pantherclawv1.AuthorizeRequest{ActionIr: []byte(`{}`)})
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeUnauthenticated {
		t.Fatalf("Authorize on the public API = %v, want Unauthenticated", err)
	}
}

func TestIntDevSeedAudits(t *testing.T) {
	d := dbtest.New(t)
	org, _, _, _ := seed(t, testConfig(t, d, RoleAPI, gatewayAt("127.0.0.1:8443")), "50.00", true)
	var kinds []string
	err := d.AppPool(t).InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT kind, body FROM pc.ledger_entries ORDER BY id")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var kind string
			var body []byte
			if err := rows.Scan(&kind, &body); err != nil {
				return err
			}
			var v map[string]any
			if err := json.Unmarshal(body, &v); err != nil {
				return err
			}
			kinds = append(kinds, kind)
		}
		return rows.Err()
	})
	want := []string{
		// Importing the reviewed package opens its TOOL_REVIEW entry, which
		// activating it settles (G0 M5 part 2).
		"audit.dev.org_seeded", "audit.dev.workload_seeded", "audit.waitlist.entry_opened", "audit.package.imported",
		"audit.package.transitioned", "audit.policy.version_created", "audit.policy.published",
		"audit.dev.gateway_seeded", "audit.connection.created", "audit.facts.provider_registered", "audit.grant.issued", "audit.run.started",
	}
	if err != nil || !slices.Equal(kinds, want) {
		t.Fatalf("org ledger = %v, %v; want %v", kinds, err, want)
	}
}

// TestPN014_DevSeedSeedsTheHookConnection: dev seed --shell activates
// pc.shell, creates the kind-local connection "shell" in enforce mode
// through the connection checks, and issues a grant that also allows shell
// commands; without --gateway-out it is refused.
func TestPN014_DevSeedSeedsTheHookConnection(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAPI, gatewayAt("127.0.0.1:8443"))
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"dev", "seed", "--config", cfgPath, "--shell", "--workload-out", filepath.Join(dir, "w.json")},
		&out, &errb, noEnv); code == 0 || !strings.Contains(errb.String(), "--shell need --gateway-out") {
		t.Fatalf("--shell without a gateway = %d %s", code, errb.String())
	}
	out.Reset()
	args := []string{
		"dev", "seed", "--config", cfgPath, "--shell", "--gateway-out", filepath.Join(dir, "gw.json"), "--workload-out", filepath.Join(dir, "w.json"),
	}
	if code := Run(context.Background(), args, &out, &errb, noEnv); code != 0 || !strings.Contains(out.String(), "/hook/shell") {
		t.Fatalf("dev seed --shell = %d %s %s", code, out.String(), errb.String())
	}
	m := seededOrg.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("dev seed output %q", out.String())
	}
	org, err := ids.Parse[ids.Org](m[1])
	if err != nil {
		t.Fatal(err)
	}
	var conn, pkg, grant string
	err = d.AppPool(t).InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		if err := tx.QueryRow(ctx, `SELECT c.kind || ' ' || c.package || ' ' || c.access_mode || ' ' || c.state || ' ' || r.mode
			FROM pc.connections c JOIN pc.connection_routes r ON r.org_id = c.org_id AND r.connection_id = c.id
			WHERE c.name = 'shell'`).Scan(&conn); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT v.state FROM pc.package_versions v JOIN pc.tool_packages p
			ON p.org_id = v.org_id AND p.id = v.package_id WHERE p.name = 'pc.shell'`).Scan(&pkg); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT convert_from(bounds, 'UTF8') FROM pc.grant_revisions").Scan(&grant)
	})
	if err != nil || conn != "local pc.shell none ACTIVE enforce" || pkg != "ACTIVE" || !strings.Contains(grant, "shell.command.run") {
		t.Fatalf("seeded connection %q, package %q, grant %q: %v", conn, pkg, grant, err)
	}
}

// TestHR061_DevSeedSeedsACustodyConnection: dev seed --access-mode
// pantherclaw_held creates the payments connection with the credential
// placed as "Authorization: Bearer" and no credential yet (a person seals
// one); an unknown mode, or a mode without --target-url, is refused.
func TestHR061_DevSeedSeedsACustodyConnection(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAPI, gatewayAt("127.0.0.1:8443"))
	dir := t.TempDir()
	gw := func(n string) string { return filepath.Join(dir, n+".json") }
	var out, errb bytes.Buffer
	for name, args := range map[string][]string{
		"unknown mode":  {"--gateway-out", gw("a"), "--target-url", "http://127.0.0.1:9", "--access-mode", "agent_held"},
		"no target URL": {"--gateway-out", gw("b"), "--access-mode", "pantherclaw_held"},
	} {
		if code := Run(context.Background(), append([]string{"dev", "seed", "--config", cfgPath}, args...), &out, &errb, noEnv); code == 0 ||
			!strings.Contains(errb.String(), "--access-mode is") {
			t.Errorf("%s = %d %s", name, code, errb.String())
		}
		errb.Reset()
	}
	args := []string{"dev", "seed", "--config", cfgPath, "--gateway-out", gw("c"), "--target-url", "http://127.0.0.1:9", "--access-mode", "pantherclaw_held"}
	if code := Run(context.Background(), args, &out, &errb, noEnv); code != 0 || !strings.Contains(out.String(), "access pantherclaw_held") {
		t.Fatalf("dev seed --access-mode = %d %s %s", code, out.String(), errb.String())
	}
	m := seededOrg.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("dev seed output %q", out.String())
	}
	org, err := ids.Parse[ids.Org](m[1])
	if err != nil {
		t.Fatal(err)
	}
	var conn string
	var sealed int
	err = d.AppPool(t).InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		if err := tx.QueryRow(ctx, `SELECT access_mode || ' ' || credential_header || ' ' || credential_scheme
			FROM pc.connections WHERE name = 'payments'`).Scan(&conn); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.credentials").Scan(&sealed)
	})
	if err != nil || conn != "pantherclaw_held Authorization Bearer" || sealed != 0 {
		t.Fatalf("seeded connection %q with %d credentials: %v", conn, sealed, err)
	}
}
