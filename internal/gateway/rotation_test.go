// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/sim/github"
)

// rotationLease seals an App key for the connection as version 2, the
// way pclaw seal does for a rotation's candidate, and returns the lease of
// purpose that carries it.
func rotationLease(t *testing.T, h *harness, purpose string, key *rsa.PrivateKey, installation int64) dispatch.Lease {
	t.Helper()
	pub, err := pccrypto.ParseSealPublicKey(h.broker.key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	hosts := h.conn.GetAllowedHosts()
	bind := domain.Binding{
		Org: testOrg, Connection: connID, Version: 2, AllowedHosts: hosts, BrokerKey: "bk-1", Header: "Authorization", Scheme: "Bearer",
		Kind: domain.KindGitHubApp,
	}
	plain, err := domain.GitHubApp{
		V: 1, Issuer: "Iv23liGateway", Installation: installation, Account: "acme",
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := pccrypto.Seal(pub, bind.Info(), domain.AAD, plain)
	if err != nil {
		t.Fatal(err)
	}
	req, err := json.Marshal(domain.RotationLease{Rotation: "r-1", Credential: domain.RotationCredential{
		ID: "cand", Version: 2, BrokerKey: "bk-1", Sealed: blob, AllowedHosts: hosts, Header: "Authorization", Scheme: "Bearer",
		Kind: domain.KindGitHubApp,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return dispatch.Lease{
		Purpose: purpose, Connection: connID, Task: "01920000-0000-7000-8000-00000000ac01", Operation: "github.app.rotation",
		Request: req, Secret: []byte("the lease's secret"),
	}
}

// probe gives the gateway one rotation lease and returns its report, or
// none.
func probe(t *testing.T, h *harness, l dispatch.Lease) (domain.Probe, bool) {
	t.Helper()
	fv := &fakeVerifications{leases: []dispatch.Lease{l}}
	h.gw.verifications = fv
	h.gw.verifyDue(context.Background())
	if len(fv.reports) == 0 {
		return domain.Probe{}, false
	}
	return domain.ProbeOf(fv.reports[0].Fields), true
}

func newAppKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestHR517_TheGatewayTestsACandidateOnlyFromItsLease: the candidate is
// in no configuration; the gateway opens it from the lease alone, asks
// GitHub who the App is and reads the installation with its JWT, mints no
// token, and reports a pass. A key GitHub does not know fails, and a lease
// sealed for another installation is refused without a request.
// Covers: F424
func TestHR517_TheGatewayTestsACandidateOnlyFromItsLease(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w))
	candidate := newAppKey(t)
	w.sim.AddAppKey(&candidate.PublicKey)
	if p, ok := probe(t, h, rotationLease(t, h, dispatch.PurposeRotationTest, candidate, 7)); !ok || !p.TestPassed() {
		t.Fatalf("a registered candidate: %+v %v", p, ok)
	}
	if len(w.sim.Tokens()) != 0 {
		t.Fatal("a rotation test minted a token")
	}
	paths := []string{}
	for _, r := range w.sim.Requests() {
		if r.User != "alice" {
			paths = append(paths, r.Method+" "+r.Path)
		}
	}
	if strings.Join(paths, ",") != "GET /app,GET /app/installations/7" {
		t.Fatalf("the test sent %v", paths)
	}
	if p, ok := probe(t, h, rotationLease(t, h, dispatch.PurposeRotationTest, newAppKey(t), 7)); !ok || p.TestPassed() || p.AppStatus != http.StatusUnauthorized {
		t.Fatalf("an unknown key: %+v %v", p, ok)
	}
	before := len(w.sim.Requests())
	if _, ok := probe(t, h, rotationLease(t, h, dispatch.PurposeRotationTest, candidate, 8)); ok || len(w.sim.Requests()) != before {
		t.Fatal("a lease for another installation was used")
	}
	if h.conn.Credential.GetVersion() != 1 {
		t.Fatal("the configuration changed")
	}
}

// TestHR520_TheGatewayConfirmsTheOldKeyIsRefused: before the old key is
// deleted on GitHub the confirmation reports GitHub's acceptance; after,
// its 401; a deletion GitHub has not applied yet, or an /app failure,
// reports no refusal (the sim's key-revocation faults).
// Covers: F424
func TestHR520_TheGatewayConfirmsTheOldKeyIsRefused(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w))
	confirm := rotationLease(t, h, dispatch.PurposeRotationConfirm, w.key, 7)
	if p, ok := probe(t, h, confirm); !ok || p.OldKeyRefused() || p.AppStatus != http.StatusOK || p.InstallationStatus != 0 {
		t.Fatalf("before deletion: %+v %v", p, ok)
	}
	w.sim.RevokeAppKey(&w.key.PublicKey)
	w.sim.SetFaults(github.Faults{KeepRevokedKeys: true})
	if p, _ := probe(t, h, confirm); p.OldKeyRefused() {
		t.Fatalf("a deletion GitHub has not applied counted: %+v", p)
	}
	w.sim.SetFaults(github.Faults{})
	if p, ok := probe(t, h, confirm); !ok || !p.OldKeyRefused() {
		t.Fatalf("after deletion: %+v %v", p, ok)
	}
	candidate := newAppKey(t)
	w.sim.AddAppKey(&candidate.PublicKey)
	w.sim.SetFaults(github.Faults{AppStatus: http.StatusInternalServerError})
	if p, _ := probe(t, h, rotationLease(t, h, dispatch.PurposeRotationTest, candidate, 7)); p.TestPassed() || p.OldKeyRefused() {
		t.Fatalf("an /app failure: %+v", p)
	}
}

// TestT224_ContainmentStopsRotationProbes: while the connection is
// quarantined on the containment stream no rotation probe is sent.
// Covers: F424
func TestT224_ContainmentStopsRotationProbes(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w))
	h.containment.mu.Lock()
	h.containment.conns[connID] = "QUARANTINED"
	h.containment.mu.Unlock()
	before := len(w.sim.Requests())
	if _, ok := probe(t, h, rotationLease(t, h, dispatch.PurposeRotationConfirm, w.key, 7)); ok || len(w.sim.Requests()) != before {
		t.Fatal("a probe was sent for a quarantined connection")
	}
}
