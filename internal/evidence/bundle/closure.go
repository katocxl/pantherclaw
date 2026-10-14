// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// ClosureKind is the ledger kind of a sandbox closure (G0 M12 D3, HR-227).
const ClosureKind = "sandbox.closure"

// ProbeReport is one probe report as signed: a compact JWS (typ
// pap-probe+jwt), by the id of its probe_runs row. A bundle carries the
// reports its sandbox.closure entries name.
type ProbeReport struct {
	Run    string `json:"run"`
	Report string `json:"report"`
}

// maxProbeReports bounds the reports of a bundle.
const maxProbeReports = 10_000

type closureReportRef struct {
	Run    string `json:"run"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

type closureProbe struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
}

// closureBody is the body of a sandbox.closure entry.
type closureBody struct {
	V           int                `json:"v"`
	Closure     string             `json:"closure"`
	Session     string             `json:"session"`
	Agent       string             `json:"agent"`
	Connections []string           `json:"connections"`
	Result      string             `json:"result"`
	ProbeKey    string             `json:"probe_key"`
	HostKey     string             `json:"host_key"`
	Reports     []closureReportRef `json:"reports"`
	Probes      []closureProbe     `json:"probes"`
	RecordedAt  string             `json:"recorded_at"`
}

// closureEntry is a verified sandbox.closure entry of the bundle.
type closureEntry struct {
	seq  int64
	body closureBody
	ok   bool // the body decoded
}

// verifiedRun is a probe report whose signature, digest and session
// verified against a closure entry's keys: what a range pack's probe steps
// are re-derived from (HR-224).
type verifiedRun struct {
	report report.Report
	agent  string
}

// derived is one probe as the signed reports say it.
type derived struct {
	name, expect, observed string
}

// closures checks every sandbox.closure entry against the probe reports
// the bundle carries (HR-227, T-095): each report must be present, match
// the digest the entry names, verify under the session key (sandbox) or
// host key (control, canary) the entry names, and belong to the entry's
// session; the entry's probe outcomes must be the ones the reports say. A
// missing or mismatching report is a failure, never not available.
func (v *verifier) closures() {
	reports := map[string]string{}
	for _, p := range v.b.ProbeReports {
		reports[p.Run] = p.Report
	}
	for _, c := range v.closureEntries {
		v.closure(c, reports)
	}
}

func decodeKey(s string) (ed25519.PublicKey, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return raw, err == nil && len(raw) == ed25519.PublicKeySize
}

func (v *verifier) closure(c closureEntry, reports map[string]string) {
	subject := "closure " + truncate(c.body.Closure)
	fail := func(format string, args ...any) { v.r.add("closure.reports", subject, Failed, format, args...) }
	if !c.ok || c.body.V != 1 {
		fail("the entry at seq %d is not a version 1 closure record", c.seq)
		return
	}
	b := c.body
	probeKey, ok1 := decodeKey(b.ProbeKey)
	hostKey, ok2 := decodeKey(b.HostKey)
	if !ok1 || !ok2 {
		fail("the entry's session or host key is not an Ed25519 public key")
		return
	}
	keys := map[string]ed25519.PublicKey{report.KindSandbox: probeKey, report.KindControl: hostKey, report.KindCanary: hostKey}
	got := map[string]report.Report{}
	bad := 0
	for _, ref := range b.Reports {
		key, known := keys[ref.Kind]
		compact, have := reports[ref.Run]
		_, dup := got[ref.Kind]
		switch {
		case !known || dup:
			fail("the entry names a report of kind %q more than once or of no known kind", truncate(ref.Kind))
		case !have:
			fail("the %s report %s is missing from the bundle", ref.Kind, truncate(ref.Run))
		default:
			sum := sha256.Sum256([]byte(compact))
			r, err := report.Verify(compact, key)
			switch {
			case hex.EncodeToString(sum[:]) != ref.SHA256:
				fail("the %s report %s is not the one the entry recorded: its SHA-256 differs", ref.Kind, truncate(ref.Run))
			case err != nil:
				fail("the %s report %s does not verify under the key the entry names: %v", ref.Kind, truncate(ref.Run), err)
			case r.Session != b.Session || r.Kind != ref.Kind:
				fail("the %s report %s is of another session or kind than the entry's", ref.Kind, truncate(ref.Run))
			default:
				got[ref.Kind] = r
				v.r.runs[ref.Run] = verifiedRun{report: r, agent: b.Agent}
				continue
			}
		}
		bad++
	}
	if bad == 0 {
		for _, kind := range []string{report.KindSandbox, report.KindControl, report.KindCanary} {
			if _, ok := got[kind]; !ok {
				fail("the entry names no %s report", kind)
				bad++
			}
		}
	}
	if bad > 0 {
		return
	}
	want := derive(got[report.KindSandbox], got[report.KindControl], got[report.KindCanary])
	if len(want) != len(b.Probes) {
		fail("the entry records %d probes, its reports hold %d", len(b.Probes), len(want))
		return
	}
	for i, d := range want {
		if b.Probes[i].Name != d.name || b.Probes[i].Outcome != d.observed {
			fail("probe %s: the entry says %s %s, its signed reports say %s %s", truncate(d.name),
				truncate(b.Probes[i].Name), truncate(b.Probes[i].Outcome), d.name, d.observed)
			return
		}
	}
	checksOK := !slices.ContainsFunc(got[report.KindControl].Config.Checks, func(k report.Check) bool { return !k.OK })
	v.r.add("closure.reports", subject, Passed, "the sandbox, control and canary reports verify, match the entry's digests and session, and say what it records")
	passed := checksOK
	for _, d := range want {
		passed = passed && d.observed == d.expect
		if d.observed == d.expect {
			v.r.add("closure.probe", subject+" "+d.name, Passed, "%s", d.observed)
		} else {
			v.r.add("closure.probe", subject+" "+d.name, Failed, "%s, expected %s", d.observed, d.expect)
		}
	}
	// Coverage also requires the whole probe catalog, so a closure may be
	// FAILED although every probe it holds met its expectation; PASSED needs
	// that at least.
	switch {
	case b.Result != "PASSED" && b.Result != "FAILED":
		v.r.add("closure.result", subject, Failed, "the entry says %q, not PASSED or FAILED", truncate(b.Result))
	case b.Result == "PASSED" && !passed:
		v.r.add("closure.result", subject, Failed, "the entry says PASSED, but its signed reports show a probe or configuration check that did not pass")
	default:
		v.r.add("closure.result", subject, Passed, "%s, consistent with its reports", b.Result)
	}
}

// derive lists the probes of a probe run as its signed reports say them,
// sorted by name as the closure's entry records them: the sandbox and
// control results, and the two the server computes from the canary's hits
// (external_canary: blocked unless a hit carries the sandbox run's marker;
// canary_control: reachable when one carries the control run's).
func derive(sandbox, control, canary report.Report) []derived {
	var out []derived
	for _, r := range append(slices.Clone(sandbox.Results), control.Results...) {
		out = append(out, derived{r.Name, r.Expect, r.Observed})
	}
	hits := func(marker string) bool {
		return slices.ContainsFunc(canary.Canary.Hits, func(h report.Hit) bool { return h.Marker == marker })
	}
	observed := func(reached bool) string {
		if reached {
			return report.Reachable
		}
		return report.Blocked
	}
	out = append(out,
		derived{"external_canary", report.Blocked, observed(hits(report.Marker(sandbox.Nonce)))},
		derived{"canary_control", report.Reachable, observed(hits(report.Marker(control.Nonce)))},
	)
	slices.SortStableFunc(out, func(a, b derived) int { return strings.Compare(a.name, b.name) })
	return out
}

// noteClosure keeps a closure entry whose hash verified.
func (v *verifier) noteClosure(e *Entry, body []byte) {
	c := closureEntry{seq: e.Seq}
	c.ok = json.Unmarshal(body, &c.body, json.RejectUnknownMembers(true)) == nil
	v.closureEntries = append(v.closureEntries, c)
}
