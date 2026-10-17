// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package actionir

import (
	"encoding/json/jsontext"
	"errors"
	"strings"
	"testing"
)

const (
	org = "01920000-0000-7000-8000-00000000000a"
	env = "01920000-0000-7000-8000-00000000000e"
	run = "01920000-0000-7000-8000-0000000000a1"
	act = "01920000-0000-7000-8000-0000000000b1"
	ins = "01920000-0000-7000-8000-0000000000c1"
	dig = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
)

func refund(amount string) ActionIR {
	return ActionIR{
		V: 1, Org: org, Env: env, RunID: run, ActionID: act, AgentInstance: ins,
		Operation:  OpRefundCreate,
		Definition: Definition{Package: "pc.mock-payments", Version: "1.0.0", Digest: dig},
		Channel:    "http", Route: "payments-refund",
		Target:    Target{Type: "payments.charge", ID: "ch_3Px001", Account: "acct_001"},
		Params:    jsontext.Value(`{"amount":{"value":"` + amount + `","currency":"USD"},"reason":"duplicate"}`),
		DedupeKey: "refund:ch_3Px001",
	}
}

const canonicalRefund = `{"action_id":"` + act + `","agent_instance":"` + ins + `","channel":"http","dedupe_key":"refund:ch_3Px001",` +
	`"definition":{"digest":"` + dig + `","package":"pc.mock-payments","version":"1.0.0"},"destinations":[],"env":"` + env + `",` +
	`"operation":"payments.refund.create","org":"` + org + `","params":{"amount":{"currency":"USD","value":"30.00"},"reason":"duplicate"},` +
	`"route":"payments-refund","run_id":"` + run + `","target":{"account":"acct_001","id":"ch_3Px001","type":"payments.charge"},"v":1}`

func TestEncodeIsCanonicalAndHashed(t *testing.T) {
	p, err := Encode(refund("30.00"))
	if err != nil {
		t.Fatal(err)
	}
	if string(p.Canonical) != canonicalRefund {
		t.Fatalf("canonical form:\n got %s\nwant %s", p.Canonical, canonicalRefund)
	}
	// Reordered keys and whitespace hash identically (RFC 8785).
	shuffled := strings.Replace(canonicalRefund, `{"action_id"`, `{ "v":1, "action_id"`, 1)
	shuffled = strings.Replace(shuffled, `,"v":1}`, `}`, 1)
	q, err := Parse([]byte(shuffled))
	if err != nil {
		t.Fatal(err)
	}
	if q.Hash != p.Hash {
		t.Fatal("equivalent JSON produced a different hash")
	}
	r, _ := Encode(refund("31.00"))
	if r.Hash == p.Hash {
		t.Fatal("different amounts produced the same hash")
	}
	params, m, err := Refund(p.Action)
	if err != nil || m.String() != "30.00 USD" || params.Reason != "duplicate" {
		t.Fatalf("Refund = %+v, %v, %v", params, m, err)
	}
}

func TestHR100_StrictParsing(t *testing.T) {
	cases := map[string]string{
		"duplicate key":     strings.Replace(canonicalRefund, `"channel":"http"`, `"channel":"http","channel":"mcp"`, 1),
		"unknown field":     strings.Replace(canonicalRefund, `"v":1}`, `"v":1,"admin":true}`, 1),
		"invalid utf8":      strings.Replace(canonicalRefund, "ch_3Px001", "ch_\xff", 1),
		"number amount":     strings.Replace(canonicalRefund, `"value":"30.00"`, `"value":30.00`, 1),
		"number in params":  strings.Replace(canonicalRefund, `"reason":"duplicate"`, `"reason":1`, 1),
		"version 2":         strings.Replace(canonicalRefund, `"v":1}`, `"v":2}`, 1),
		"bad uuid":          strings.Replace(canonicalRefund, run, "run-1", 1),
		"no destinations":   strings.Replace(canonicalRefund, `"destinations":[],`, ``, 1),
		"unknown channel":   strings.Replace(canonicalRefund, `"channel":"http"`, `"channel":"smtp"`, 1),
		"unpinned digest":   strings.Replace(canonicalRefund, dig, "sha256:abc", 1),
		"params not object": strings.Replace(canonicalRefund, `"params":{"amount":{"currency":"USD","value":"30.00"},"reason":"duplicate"}`, `"params":"x"`, 1),
		"trailing garbage":  canonicalRefund + `{}`,
		"deep nesting":      strings.Replace(canonicalRefund, `"reason":"duplicate"`, `"reason":`+strings.Repeat(`{"a":`, 20)+`"x"`+strings.Repeat(`}`, 20), 1),
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); !errors.Is(err, ErrAmbiguous) {
			t.Errorf("%s: err = %v, want ErrAmbiguous", name, err)
		}
	}
}

func TestHR102_IdentifiersAreNotNormalized(t *testing.T) {
	for name, id := range map[string]string{
		"cyrillic a": "ch_3Px0" + string(rune(0x0430)) + "1",
		"bidi":       "ch_" + string(rune(0x202e)) + "100",
		"zero width": "ch" + string(rune(0x200b)) + "_1",
		"space":      "ch 1",
		"control":    "ch_\x01",
		"fullwidth":  string(rune(0xff43)) + "h_1",
	} {
		a := refund("30.00")
		a.Target.ID = id
		if _, err := Encode(a); !errors.Is(err, ErrAmbiguous) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestHR103_RefundParamsAreNeverDefaulted(t *testing.T) {
	for name, params := range map[string]string{
		"missing amount":   `{"reason":"duplicate"}`,
		"missing currency": `{"amount":{"value":"30.00"},"reason":"duplicate"}`,
		"lowercase ccy":    `{"amount":{"value":"30.00","currency":"usd"},"reason":"duplicate"}`,
		"sub-cent":         `{"amount":{"value":"30.001","currency":"USD"},"reason":"duplicate"}`,
		"exponent":         `{"amount":{"value":"3e1","currency":"USD"},"reason":"duplicate"}`,
		"zero":             `{"amount":{"value":"0","currency":"USD"},"reason":"duplicate"}`,
		"negative":         `{"amount":{"value":"-5.00","currency":"USD"},"reason":"duplicate"}`,
		"unknown reason":   `{"amount":{"value":"30.00","currency":"USD"},"reason":"because"}`,
		"extra param":      `{"amount":{"value":"30.00","currency":"USD"},"reason":"duplicate","to":"acct_x"}`,
		"unsupported ccy":  `{"amount":{"value":"30.00","currency":"XYZ"},"reason":"duplicate"}`,
	} {
		a := refund("30.00")
		a.Params = jsontext.Value(params)
		p, err := Encode(a)
		if err != nil {
			continue // rejected at parse time is fine too
		}
		if _, _, err := Refund(p.Action); !errors.Is(err, ErrAmbiguous) {
			t.Errorf("%s: accepted", name)
		}
	}
	a := refund("30.00")
	a.Operation = "payments.charge.create"
	p, _ := Encode(a)
	if _, _, err := Refund(p.Action); !errors.Is(err, ErrAmbiguous) {
		t.Error("non-refund operation decoded as a refund")
	}
}

func TestLimits(t *testing.T) {
	if _, err := Parse(nil); !errors.Is(err, ErrAmbiguous) {
		t.Error("empty input accepted")
	}
	big := strings.Replace(canonicalRefund, `"reason":"duplicate"`, `"reason":"`+strings.Repeat("a", MaxStringBytes+1)+`"`, 1)
	if _, err := Parse([]byte(big)); !errors.Is(err, ErrAmbiguous) {
		t.Error("oversized string accepted")
	}
	if _, err := Parse([]byte(strings.Repeat(" ", MaxBytes+1))); !errors.Is(err, ErrAmbiguous) {
		t.Error("oversized document accepted")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(canonicalRefund))
	f.Add([]byte(`{"v":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err != nil {
			return
		}
		// Anything accepted must re-parse to the same hash from its canonical form.
		q, err := Parse(p.Canonical)
		if err != nil || q.Hash != p.Hash {
			t.Fatalf("canonical form not stable: %v", err)
		}
	})
}

// TestM14_Channels: an action may come through the authzen and a2a
// channels (G0 M14 D4).
func TestM14_Channels(t *testing.T) {
	for _, ch := range []string{"authzen", "a2a"} {
		if _, err := Parse([]byte(strings.Replace(canonicalRefund, `"channel":"http"`, `"channel":"`+ch+`"`, 1))); err != nil {
			t.Errorf("%s: %v", ch, err)
		}
	}
}
