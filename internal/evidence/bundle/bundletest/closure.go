// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundletest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// ClosureOpts varies the closure AppendClosure records.
type ClosureOpts struct {
	// Forge names the kind of report (sandbox, control or canary) the
	// entry records the digest of a copy signed by a stranger's key, which
	// the bundle carries: an attacker who rewrote the ledger.
	Forge string
	// CrossSign names the kind of report signed with the other kind's key.
	CrossSign string
	// EditOutcome makes the entry say the named probe was reachable
	// although the signed reports say blocked.
	EditOutcome string
	// Session and Agent fix the closure's ids when set.
	Session, Agent, ID string
}

// Closure is a recorded sandbox closure: its ids, keys and the reports a
// bundle of it carries.
type Closure struct {
	ID, Session, Agent, Connection string
	// Runs are the probe_runs ids by kind (sandbox, control, canary).
	Runs map[string]string
	// ProbeKey signs the sandbox report and HostKey the others.
	ProbeKey, HostKey ed25519.PrivateKey
	Reports           []bundle.ProbeReport
}

// AppendClosure chains a sandbox.closure entry of a fresh closure whose
// probes ssh_push and planted_pat_push were blocked, with the control and
// canary reports that make it pass, and returns the closure. Bundles from
// Bundle carry its reports.
func (i *Issuer) AppendClosure(o ClosureOpts) *Closure {
	i.T.Helper()
	pub, probeKey, _ := ed25519.GenerateKey(rand.Reader)
	hpub, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	c := &Closure{
		ID: ids.NewV7().String(), Session: ids.NewV7().String(), Agent: ids.NewV7().String(), Connection: ids.NewV7().String(),
		Runs: map[string]string{}, ProbeKey: probeKey, HostKey: hostKey,
	}
	if o.ID != "" {
		c.ID = o.ID
	}
	if o.Session != "" {
		c.Session = o.Session
	}
	if o.Agent != "" {
		c.Agent = o.Agent
	}
	nonce := func() string { return strings.ReplaceAll(ids.NewV7().String(), "-", "") + "aa" }
	sandboxNonce, controlNonce := nonce(), nonce()
	base := func(kind, n string) report.Report {
		return report.Report{
			Format: report.Format, Session: c.Session, Nonce: n, Kind: kind, StartedAt: IssuedAt, FinishedAt: IssuedAt.Add(time.Second),
			Engine:  report.Engine{Version: "29.0.0", APIVersion: "1.50", Runtime: "runsc"},
			Network: report.Network{Name: "pc", Internal: true, GatewayModeIPv4: "isolated"},
			Config:  report.Config{Checks: []report.Check{{ID: "internal_network", OK: true}}}, Results: []report.Result{},
		}
	}
	sb := base(report.KindSandbox, sandboxNonce)
	sb.Results = []report.Result{
		{Name: "ssh_push", Role: report.RoleProbe, Expect: report.Blocked, Observed: report.Blocked},
		{Name: "planted_pat_push", Role: report.RoleProbe, Expect: report.Blocked, Observed: report.Blocked},
	}
	ctl := base(report.KindControl, controlNonce)
	ctl.Results = []report.Result{{Name: "gateway_control", Role: report.RolePositive, Expect: report.Reachable, Observed: report.Reachable}}
	cn := base(report.KindCanary, nonce())
	cn.Canary.Hits = []report.Hit{{Proto: "tcp", Port: 443, Marker: report.Marker(controlNonce), At: IssuedAt}}
	for kind, r := range map[string]report.Report{report.KindSandbox: sb, report.KindControl: ctl, report.KindCanary: cn} {
		key := hostKey
		if kind == report.KindSandbox {
			key = probeKey
		}
		if kind == o.Forge {
			_, key, _ = ed25519.GenerateKey(rand.Reader)
		}
		if kind == o.CrossSign {
			key = hostKey
			if kind != report.KindSandbox {
				key = probeKey
			}
		}
		compact, err := report.Sign(key, r)
		if err != nil {
			i.T.Fatal(err)
		}
		run := ids.NewV7().String()
		c.Runs[kind] = run
		c.Reports = append(c.Reports, bundle.ProbeReport{Run: run, Report: compact})
	}
	// Chain the closure entry; the forged copy's digest is what it records.
	type ref struct {
		Run    string `json:"run"`
		Kind   string `json:"kind"`
		SHA256 string `json:"sha256"`
	}
	type probe struct {
		Name    string `json:"name"`
		Outcome string `json:"outcome"`
	}
	var refs []ref
	for _, kind := range []string{report.KindSandbox, report.KindControl, report.KindCanary} {
		compact := c.Report(kind)
		sum := sha256.Sum256([]byte(compact))
		refs = append(refs, ref{Run: c.Runs[kind], Kind: kind, SHA256: hex.EncodeToString(sum[:])})
	}
	probes := []probe{
		{"canary_control", report.Reachable},
		{"external_canary", report.Blocked},
		{"gateway_control", report.Reachable},
		{"planted_pat_push", report.Blocked},
		{"ssh_push", report.Blocked},
	}
	for k := range probes {
		if probes[k].Name == o.EditOutcome {
			probes[k].Outcome = report.Reachable
		}
	}
	slices.SortStableFunc(probes, func(a, b probe) int { return strings.Compare(a.Name, b.Name) })
	i.AppendCoverageBody(bundle.ClosureKind, mustBody(i, map[string]any{
		"v": 1, "closure": c.ID, "session": c.Session, "agent": c.Agent, "connections": []string{c.Connection}, "result": "PASSED",
		"probe_key": base64.RawURLEncoding.EncodeToString(pub), "host_key": base64.RawURLEncoding.EncodeToString(hpub),
		"reports": refs, "probes": probes, "recorded_at": "2026-10-10T08:30:00.000000Z",
	}))
	i.Closures = append(i.Closures, c.Reports...)
	return c
}

// Report returns the compact JWS of the closure's report of kind.
func (c *Closure) Report(kind string) string {
	for _, r := range c.Reports {
		if r.Run == c.Runs[kind] {
			return r.Report
		}
	}
	return ""
}

func mustBody(i *Issuer, v any) []byte {
	i.T.Helper()
	b, err := domain.CanonicalBody(v)
	if err != nil {
		i.T.Fatal(err)
	}
	return b
}
