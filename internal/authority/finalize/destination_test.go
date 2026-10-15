// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR079_TheDecisionReceiptRecordsTheDestinationClass: the decision
// receipt names the connection and its destination class, from the
// connection's record.
func TestHR079_TheDecisionReceiptRecordsTheDestinationClass(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	run := s.Run(g.ID, s.Alice)
	gw, err := ids.ParseUUID(s.Gateway.ID)
	if err != nil {
		t.Fatal(err)
	}
	conn := pipeline.Connection{
		ID: ids.NewV7(), Gateway: gw, Kind: "http", Package: "pc.mock-payments", State: "ACTIVE", AccessMode: "none",
		DefaultMode: pipeline.ModeEnforce, DestinationClass: "internal", Modes: map[string]string{},
	}
	s.W.PutConnection(conn)
	res := s.Authorize(throughConnection(t, s, run, conn.ID, pipelinetest.Refund("ch_1", "30.00")))
	if !res.Decision.Permits() {
		t.Fatalf("decision %s", res.Decision)
	}
	var receipt struct {
		Pap struct {
			Connection       string `json:"connection"`
			DestinationClass string `json:"destination_class"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(pipelinetest.Payload(res.Receipt), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Pap.Connection != conn.ID.String() || receipt.Pap.DestinationClass != "internal" {
		t.Fatalf("receipt %+v", receipt.Pap)
	}
}

// TestHR079_TheReceiptRecordsDisclosureLimits (M10 half): toward a public
// destination the decision receipt records each disclosure param's
// limits as an obligation.
func TestHR079_TheReceiptRecordsDisclosureLimits(t *testing.T) {
	s := pipelinetest.NewScenario(t, func(text string) string {
		enum := "        values: [duplicate, fraudulent, requested_by_customer]\n"
		if !strings.Contains(text, enum) {
			t.Fatal("the refund's reason param moved; update the fixture")
		}
		text = strings.Replace(text, enum, enum+"      memo:\n        type: text\n        disclosure: true\n        max_entropy: \"4.5\"\n", 1)
		return strings.Replace(text, "            reason: input.reason\n    dispatch:",
			"            reason: input.reason\n            memo: input.memo\n    dispatch:", 1)
	})
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	run := s.Run(g.ID, s.Alice)
	gw, err := ids.ParseUUID(s.Gateway.ID)
	if err != nil {
		t.Fatal(err)
	}
	conn := pipeline.Connection{
		ID: ids.NewV7(), Gateway: gw, Kind: "http", Package: "pc.mock-payments", State: "ACTIVE", AccessMode: "none",
		DefaultMode: pipeline.ModeEnforce, DestinationClass: "public", Modes: map[string]string{},
	}
	s.W.PutConnection(conn)
	res := s.Authorize(throughConnection(t, s, run, conn.ID,
		`{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate","memo":"thanks"}`))
	if !res.Decision.Permits() {
		t.Fatalf("decision %s", res.Decision)
	}
	var receipt struct {
		Pap struct {
			Obligations []struct {
				Kind       string `json:"kind"`
				Param      string `json:"param"`
				Max        string `json:"max"`
				MaxEntropy string `json:"max_entropy"`
			} `json:"obligations"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(pipelinetest.Payload(res.Receipt), &receipt); err != nil {
		t.Fatal(err)
	}
	if len(receipt.Pap.Obligations) != 1 || receipt.Pap.Obligations[0].Kind != "disclosure_limits" ||
		receipt.Pap.Obligations[0].Param != "memo" || receipt.Pap.Obligations[0].Max != "4096" || receipt.Pap.Obligations[0].MaxEntropy != "4.5" {
		t.Fatalf("receipt obligations %+v", receipt.Pap.Obligations)
	}
}
