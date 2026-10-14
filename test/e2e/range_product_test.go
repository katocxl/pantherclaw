// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
)

// buildRangeThroughTheProduct sets a range up the way an operator does, with
// the product's own commands and no database change (D42): a real grant shaped
// like the team's, `pclaw redteam setup` for the range agent, its simulated
// twins and its grant, a GitHub App sealed for the github twin, and an
// enrolled, admitted workload with a run on the range grant.
func (r *rangeStack) buildRangeThroughTheProduct(realGrantBounds, realGrantRequirements string) {
	t, d := r.d.t, r.d
	s := d.s
	d.bindRoles("agent_owner", "agent_admitter", "grant_issuer", "run_launcher", "gateway_admin", "security_admin", "policy_publisher")
	alice := s.row(t, "SELECT id::text FROM pc.users WHERE subject = 'alice'")
	var realAgent, team, env string
	s.query(t, "SELECT agent_id::text FROM pc.runs WHERE id = $1", []any{s.run}, &realAgent)
	s.query(t, "SELECT team_id::text, environment_id::text FROM pc.agents WHERE id = $1", []any{mustUUID(t, realAgent)}, &team, &env)
	// The team's real grant for its real agent: what the range grant is shaped like.
	like := d.issueGrantDepth(realAgent, realGrantBounds, "", realGrantRequirements, "1") // setup deepens it by one for agent.child

	code, out, errs := d.admin.pclaw(t, "redteam", "setup", "--name", "range", "--team", team, "--env", env, "--owner", alice,
		"--context", "service", "--twin", mockpayments.Name+"="+s.simURL, "--twin", pcgithub.Name+"="+s.gh.url, "--like-grant", like, "--yes")
	if code != 0 {
		t.Fatalf("pclaw redteam setup: %d\n%s\n%s", code, out, errs)
	}
	// The twins are simulated and point at loopback or private literals
	// (HR-221): read back from the server, not assumed.
	for _, twin := range []string{"payments-range", "github-range"} {
		var simulated bool
		var base string
		s.query(t, "SELECT simulated, base_url FROM pc.connections WHERE name = $1", []any{twin}, &simulated, &base)
		u, err := url.Parse(base)
		ip := net.ParseIP(strings.Trim(hostOf(u), "[]"))
		if err != nil || !simulated || ip == nil || !(ip.IsLoopback() || ip.IsPrivate()) {
			t.Fatalf("connection %s: simulated=%v base %q (%v), want a simulated connection at a loopback or private IP literal", twin, simulated, base, err)
		}
	}
	// The real `real` connection is made only now, so the setup copied the
	// team's real connections and not it.
	d.seedReal()
	// The GitHub twin holds the App too, as a gateway admin seals it.
	var twinID string
	s.query(t, "SELECT id::text FROM pc.connections WHERE name = 'github-range'", nil, &twinID)
	s.waitConfig(t, s.sealGitHubAppFor(t, mustUUID(t, twinID)))
	d.registerGatewayFacts("github.gateway.range", twinID)

	s.query(t, "SELECT id::text FROM pc.agents WHERE range_agent", nil, &r.agent)
	r.keyFile, r.instance = d.enrolThroughTheProduct(r.agent)
	s.query(t, "SELECT id::text FROM pc.grants WHERE agent_id = $1 AND state = 'ACTIVE'", []any{mustUUID(t, r.agent)}, &r.grant)
	r.run0 = d.startRun(r.agent, r.instance, r.grant)
}

func hostOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Hostname()
}

// enrolThroughTheProduct enrols and admits a workload for the agent with the
// CLI, as an owner does, and returns its key file and instance.
func (d *rangeDriver) enrolThroughTheProduct(agent string) (string, string) {
	t := d.t
	dir := t.TempDir()
	enrollFile, keyFile := filepath.Join(dir, "enroll.token"), filepath.Join(dir, "workload.json")
	must := func(args ...string) string {
		t.Helper()
		code, out, errs := d.admin.pclaw(t, args...)
		if code != 0 {
			t.Fatalf("pclaw %s: %d %s %s", strings.Join(args, " "), code, out, errs)
		}
		return out
	}
	must("agent", "enroll-token", agent, "--out", enrollFile)
	must("workload", "init", "--key-file", keyFile)
	o := must("workload", "enroll", "--key-file", keyFile, "--server", d.s.apiURL, "--enrollment-token-file", enrollFile)
	inst, fp := enrolledInstance.FindStringSubmatch(o), enrolledPrint.FindStringSubmatch(o)
	if inst == nil || fp == nil {
		t.Fatalf("enroll output %q", o)
	}
	must("instance", "admit", inst[1], "--fingerprint", fp[1])
	return keyFile, inst[1]
}

// sealGitHubAppFor seals the GitHub App for another connection (the range's
// twin), as a gateway admin does with `pclaw seal --github-app`, and returns
// the gateway configuration version that carries it.
func (s *stack) sealGitHubAppFor(t *testing.T, conn ids.UUID) int64 {
	t.Helper()
	admin := s.person(t, "range-github-admin", td.RoleGatewayAdmin)
	svc := credapp.New(s.pool, nil)
	k, err := svc.GetSealingKey(admin.ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(s.gh.key)})
	plain, err := creddomain.GitHubApp{V: 1, Issuer: s.gh.app, Installation: s.gh.installation, Account: s.gh.account, PrivateKey: pemKey}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	b := k.Binding
	b.Kind = creddomain.KindGitHubApp
	sealed, err := pccrypto.Seal(pub, b.Info(), creddomain.AAD, plain)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutCredential(admin.ctx, credapp.PutInput{
		Connection: conn, BrokerKey: mustUUID(t, b.BrokerKey), Version: b.Version, Sealed: sealed, AllowedHosts: b.AllowedHosts,
		Header: b.Header, Scheme: b.Scheme, Kind: creddomain.KindGitHubApp,
		GitHub: &creddomain.Installation{AppClientID: s.gh.app, ID: s.gh.installation, Account: s.gh.account},
	}); err != nil {
		t.Fatal(err)
	}
	return s.configVersion(t, k.Gateway)
}

// registerGatewayFacts registers the gateway as the provider of the facts the
// GitHub package names for a connection (the gateway reads them from GitHub
// before each decision), as an operator does with `pclaw fact-provider
// register --gateway --connection` for the range's twin.
func (d *rangeDriver) registerGatewayFacts(name, conn string) {
	t := d.t
	p, err := manifest.Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var facts []string
	for _, def := range p.Definitions {
		for _, pr := range def.Prerequisites {
			f := pr.Fact + ":object:" + def.Target.Type + ":1m"
			if !seen[f] {
				seen[f] = true
				facts = append(facts, f)
			}
		}
	}
	var gw string
	d.s.query(t, "SELECT gateway_id::text FROM pc.connections WHERE id = $1", []any{mustUUID(t, conn)}, &gw)
	args := []string{"fact-provider", "register", "--name", name, "--gateway", gw, "--connection", conn}
	for _, f := range facts {
		args = append(args, "--fact", f)
	}
	if code, out, errs := d.admin.pclaw(t, args...); code != 0 {
		t.Fatalf("pclaw fact-provider register: %d %s %s", code, out, errs)
	}
}
