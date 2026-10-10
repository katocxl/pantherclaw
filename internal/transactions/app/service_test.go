// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

func TestBackoffGrowsAndCaps(t *testing.T) {
	want := []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second, 135 * time.Second, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		if got := Backoff(i + 1); got != w {
			t.Errorf("attempt %d: %s, want %s", i+1, got, w)
		}
	}
}

func TestHR190_OnlyDeclaredFieldsMayBeReported(t *testing.T) {
	v := &defs.VerifierSpec{
		Expect: []defs.Expectation{{Field: "/amount", Equals: "params.amount.value"}},
		States: &defs.StateMap{Field: "/status", Confirmed: []string{"succeeded"}},
	}
	got := Declared(v)
	if len(got) != 2 || !got["/amount"] || !got["/status"] {
		t.Fatalf("declared %v", got)
	}
	s := &Service{Store: refuse{}}
	for name, r := range map[string]Report{
		"a bad pointer":    {Secret: make([]byte, 32), Fields: map[string]string{"amount": "1"}},
		"a long value":     {Secret: make([]byte, 32), Fields: map[string]string{"/amount": strings.Repeat("9", MaxFieldValue+1)}},
		"too many fields":  {Secret: make([]byte, 32), Fields: manyFields()},
		"a short secret":   {Secret: make([]byte, 31)},
		"a partial digest": {Secret: make([]byte, 32), ResponseDigest: make([]byte, 16)},
	} {
		if _, err := s.Report(context.Background(), ids.New[ids.Org](), ids.NewV7(), r); !errors.Is(err, ErrUndeclared) && !errors.Is(err, ErrLease) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func manyFields() map[string]string {
	m := map[string]string{}
	for i := range MaxFields + 1 {
		m["/f"+string(rune('a'+i))] = "x"
	}
	return m
}

type refuse struct{ Store }

func (refuse) Report(context.Context, ids.OrgID, ids.UUID, Report, Sign) (Applied, error) {
	return Applied{}, errors.New("the store was reached")
}

type signer struct{ payload []byte }

func (s *signer) Sign(typ string, payload []byte) (string, error) {
	s.payload = payload
	return "eyJ0eXAiOiIi" + "." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln", nil
}

// TestHR191_EffectReceiptsStateLevelBasisAndLimits: an effect receipt says
// the level required and achieved, its basis, the verifier, the limits and
// one result per declared effect kind; values appear as digests only.
func TestHR191_EffectReceiptsStateLevelBasisAndLimits(t *testing.T) {
	sg := &signer{}
	s := &Service{Receipts: sg, Issuer: "https://pc.example.test"}
	obs := ids.NewV7()
	d := &defs.Definition{
		Effects:     []defs.Effect{{Kind: "funds.transfer"}},
		SideEffects: []defs.Effect{{Kind: "notification.send"}},
	}
	signed, err := s.sign(Effect{
		Org: ids.New[ids.Org](), Transaction: ids.NewV7(), Seq: 2, State: domain.Confirmed, Required: defs.LevelAcceptance,
		Achieved: defs.LevelFollowUp, Basis: "verifier", Observations: []ids.UUID{obs},
		Verifier: &VerifierRef{Operation: "payments.refund.get", Establishes: "refund.exists"},
		Expected: map[string]string{"/amount": "30.00"}, Observed: map[string]string{"/amount": "30.00", "/status": "succeeded"},
		Effects: Effects(d, domain.Confirmed), Limits: "not that the money arrived", At: time.Unix(1_760_097_600, 0),
	})
	if err != nil || signed.JWS == "" || len(signed.Body) == 0 {
		t.Fatalf("signed %+v %v", signed, err)
	}
	var c struct {
		Jti string         `json:"jti"`
		Pap map[string]any `json:"pap"`
	}
	if err := json.Unmarshal(sg.payload, &c); err != nil {
		t.Fatal(err)
	}
	p := c.Pap
	effects, _ := json.Marshal(p["effects"], json.Deterministic(true))
	if !strings.HasSuffix(c.Jti, "/2") || p["state"] != "CONFIRMED" || p["achieved"] != "follow_up" || p["required"] != "acceptance" ||
		p["limits"] == nil || p["expected_sha256"] == nil || p["observed_sha256"] == nil || p["simulated"] != false ||
		string(effects) != `[{"kind":"funds.transfer","state":"CONFIRMED"},{"kind":"notification.send","state":"UNVERIFIABLE"}]` {
		t.Fatalf("claims %v", p)
	}
	if strings.Contains(string(sg.payload), "30.00") {
		t.Fatal("an observed value is in the receipt; only its digest belongs there")
	}
}
