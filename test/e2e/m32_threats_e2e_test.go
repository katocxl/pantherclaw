// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// wantRefused checks a kube.probe observation.
func wantRefused(t *testing.T, what string, obs domain.Observation, err error, reason string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if obs.Outcome != domain.OutcomeRefused || obs.Reason != reason {
		t.Errorf("%s: %s %s (%s), want REFUSED %s", what, obs.Outcome, obs.Reason, obs.Detail, reason)
	}
}

// TestHR744_APodsRunStartsOnlyUnderItsEntrysRunGrant: the probe pod's
// instance starts the run of its own attested pod name under its issuer
// entry's run grant, launched by the instance through the entry; another
// pod name, an entry without a run grant and an instance enrolled other
// than by kubernetes attestation start nothing.
func TestHR744_APodsRunStartsOnlyUnderItsEntrysRunGrant(t *testing.T) {
	f := startKube(t)
	w, err := f.enrolPod(f.agentPod)
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.kc.StartPodRun(context.Background(), &pb.StartPodRunRequest{PodName: f.agentPod.name})
	if err != nil {
		t.Fatalf("the pod's own run: %v", err)
	}
	if n := f.count(t, `SELECT count(*)::int FROM pc.runs r JOIN pc.agent_instances i ON i.org_id = r.org_id AND i.id = r.instance_id
		WHERE r.org_id = $1 AND r.id = $2 AND r.agent_id = $3 AND r.grant_id = $4 AND r.task_ref = $5 AND r.principal_source = 'trusted_issuer'
		AND r.launcher_instance_id = r.instance_id AND r.launcher_issuer_id = i.issuer_revision_id
		AND r.actor_chain::text LIKE '%trusted_issuer%'`, mustUUID(t, res.GetRunId()), f.podAgent, f.grant, f.agentPod.name); n != 1 {
		t.Errorf("the pod run is not launched by the instance under the entry's grant (%d rows)", n)
	}
	for attack, reason := range map[string]string{
		"pod_run_other_name": "K8S_POD_NAME", "pod_run_without_grant": "K8S_NO_RUN_GRANT", "pod_run_not_kubernetes": "K8S_NOT_KUBERNETES_INSTANCE",
	} {
		obs, err := f.runAttack(t, attack)
		wantRefused(t, attack, obs, err, reason)
	}
	if n := f.count(t, "SELECT count(*)::int FROM pc.runs WHERE org_id = $1 AND launcher_issuer_id IS NOT NULL"); n != 1 {
		t.Errorf("%d pod runs, want 1", n)
	}
}

// TestT336_TheEdgeKeepsItsKeysInThePodAndRunsOnlyThePodsRun: the edge in
// kubernetes mode listens on loopback only, writes the session CA's
// certificate and nothing else, and its pod's run is the one it started
// under the entry's grant.
func TestT336_TheEdgeKeepsItsKeysInThePodAndRunsOnlyThePodsRun(t *testing.T) {
	f := startKube(t)
	addr, dir, stop := f.runEdge(t, f.agentPod)
	defer stop()
	if ap, err := netip.ParseAddrPort(addr); err != nil || !ap.Addr().IsLoopback() {
		t.Errorf("the edge listens on %s", addr)
	}
	f.waitCount(t, 1, "SELECT count(*)::int FROM pc.runs WHERE org_id = $1 AND agent_id = $2 AND task_ref = $3 AND grant_id = $4",
		f.podAgent, f.agentPod.name, f.grant)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "token" {
			continue // the projected token the test mounted
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if e.Name() != "ca.crt" || strings.Contains(string(b), "PRIVATE KEY") || !strings.Contains(string(b), "CERTIFICATE") {
			t.Errorf("the edge wrote %s: %.60q", e.Name(), b)
		}
	}
	if n := f.count(t, "SELECT count(*)::int FROM pc.agent_instances WHERE org_id = $1 AND agent_id = $2 AND enrolled_via = 'attestation' AND att_level >= 2", f.podAgent); n != 1 {
		t.Errorf("%d attested instances of the probe agent, want 1", n)
	}
}

// TestT338_AForgedOrReplayedKubeClosureRecordsNothing: a closure signed
// by the pod's key on a fresh nonce is recorded; one signed by another
// key, on a used nonce, with a nonce for another namespace or from a pod
// whose probe image is off the list is refused and records nothing.
func TestT338_AForgedOrReplayedKubeClosureRecordsNothing(t *testing.T) {
	f := startKube(t)
	obs, err := f.overstateAttack(t, "none")
	if err != nil || obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("an honest closure: %+v %v", obs, err)
	}
	const closures = "SELECT count(*)::int FROM pc.kube_closures WHERE org_id = $1"
	before := f.count(t, closures)
	for attack, reason := range map[string]string{
		"report_other_key": "K8S_CLOSURE_REJECTED", "report_nonce_replayed": "K8S_CLOSURE_REJECTED",
		"nonce_other_namespace": "K8S_NAMESPACE", "probe_image_off_list": "K8S_CLOSURE_REJECTED",
	} {
		obs, err := f.forgeAttack(t, attack)
		wantRefused(t, attack, obs, err, reason)
	}
	// Only the replay's first, honest report was recorded.
	if n := f.count(t, closures); n != before+1 {
		t.Errorf("%d kube closures recorded by the forgeries, want only the replayed report's first", n-before)
	}
}

// TestT339_AKubeClosureThatOverstatesContainmentFails: with the
// namespace's NetworkPolicy opened, no admission decision for a day, or a
// probe that got through, the closure is recorded FAILED.
func TestT339_AKubeClosureThatOverstatesContainmentFails(t *testing.T) {
	f := startKube(t)
	for _, attack := range []string{"network_policy_open", "probe_reached", "admission_not_seen"} {
		obs, err := f.overstateAttack(t, attack)
		wantRefused(t, attack, obs, err, "NOT_ENFORCED")
	}
	if n := f.count(t, "SELECT count(*)::int FROM pc.kube_closures WHERE org_id = $1 AND kind = 'sandbox' AND result = 'FAILED'"); n != 3 {
		t.Errorf("%d failed kube closures recorded, want 3", n)
	}
}

// TestHR741_AClosureIsTheSignerPodsOwnOfItsKind: an edge sidecar image
// off the list attests nothing; a non-kubernetes instance takes no nonce;
// a report naming another pod, on an expired nonce, a ninth outstanding
// nonce and a control report from the agent pod are refused and record
// nothing (D1218 H1, L2, item 5).
func TestHR741_AClosureIsTheSignerPodsOwnOfItsKind(t *testing.T) {
	f := startKube(t)
	const closures = "SELECT count(*)::int FROM pc.kube_closures WHERE org_id = $1"
	before := f.count(t, closures)
	obs, err := f.forgeAttack(t, "edge_image_off_list")
	wantRefused(t, "edge_image_off_list", obs, err, "attestation_insufficient")
	for attack, reason := range map[string]string{
		"closure_not_kubernetes": "K8S_NOT_KUBERNETES_INSTANCE", "report_other_pod": "K8S_CLOSURE_REJECTED",
		"nonce_expired": "K8S_CLOSURE_REJECTED", "nonce_flood": "K8S_CLOSURE_REJECTED", "control_from_agent_pod": "K8S_CLOSURE_REJECTED",
		"sandbox_from_release_namespace": "K8S_CLOSURE_REJECTED", "result_without_target": "K8S_CLOSURE_REJECTED",
	} {
		obs, err := f.forgeAttack(t, attack)
		wantRefused(t, attack, obs, err, reason)
	}
	if n := f.count(t, closures); n != before {
		t.Errorf("%d kube closures recorded by the refused reports", n-before)
	}
	// The release namespace's control probe passes as the control.
	if err := f.passControl(t); err != nil {
		t.Fatal(err)
	}
}

// TestHR742_AClosureWithAForgedProbeTargetRecordsNothing: a passing
// probe whose target is not the control's or the pod's node is refused
// (D1218 M2; T-339, RT-219); the same report with the cluster's targets
// passes.
func TestHR742_AClosureWithAForgedProbeTargetRecordsNothing(t *testing.T) {
	f := startKube(t)
	obs, err := f.forgedTarget(t)
	wantRefused(t, "probe_target_forged", obs, err, "K8S_CLOSURE_REJECTED")
	if n := f.count(t, "SELECT count(*)::int FROM pc.kube_closures WHERE org_id = $1 AND kind = 'sandbox'"); n != 0 {
		t.Errorf("%d sandbox closures recorded by forged targets", n)
	}
	if obs, err := f.overstateAttack(t, "none"); err != nil || obs.Outcome != domain.OutcomeAllow {
		t.Errorf("the cluster's own targets: %+v %v", obs, err)
	}
}
