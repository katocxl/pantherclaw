// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

const asiScenario = `apiVersion: pantherclaw.range/v1
id: ID
title: A scenario
category: boundary
suite: coding-agent
tier: community
attacker: A1
threats: [T-008]
rules: [HR-045]
ASI
steps:
  - id: one
    do: agent.call
    with:
      face: mcp
      connection: github
      tool: create_branch
      args: {}
    expect:
      outcome: DENY
`

func asiFile(id, tags string) []byte {
	return []byte(strings.NewReplacer("ID", id, "ASI\n", tags).Replace(asiScenario))
}

// TestD304_ASITagsAreAClosedList: a library scenario may name listed risks,
// once each, and nothing else.
// Covers: F898
func TestD304_ASITagsAreAClosedList(t *testing.T) {
	const why = "asi_why:\n  ASI02: \"Tool misuse (ASI02): it misuses a tool.\"\n  ASI10: \"Rogue agents (ASI10): it acts out of line.\"\n"
	s, err := domain.Parse(asiFile("RT-901", "asi: [ASI02, ASI10]\n"+why))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ASI) != 2 || len(s.ASIWhy) != 2 {
		t.Fatalf("tags: %v %v", s.ASI, s.ASIWhy)
	}
	for _, bad := range []string{
		"asi: [ASI11]\n", "asi: [ASI00]\n", "asi: [LLM01]\n", "asi: [ASI01, ASI01]\n",
		// D531: every tag says why, in one line, and only tags do.
		"asi: [ASI02, ASI10]\n",
		"asi: [ASI02]\n" + why,
		"asi: [ASI02, ASI03]\n" + why,
		"asi: [ASI02]\nasi_why:\n  ASI02: \"\"\n",
		"asi: [ASI02]\nasi_why:\n  ASI02: \"one\\ntwo\"\n",
		"asi: [ASI02]\nasi_why:\n  ASI02: \"" + strings.Repeat("x", 201) + "\"\n",
	} {
		if _, err := domain.Parse(asiFile("RT-901", bad)); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// TestT260_CustomerScenarioCarriesNoTag: a customer-authored scenario is the
// customer's word, so it cannot say which risk it exercised.
// Covers: F898
func TestT260_CustomerScenarioCarriesNoTag(t *testing.T) {
	if _, err := domain.Parse(asiFile("CX-901", "asi: [ASI02]\n")); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a customer scenario with a tag: %v", err)
	}
	if _, err := domain.Parse(asiFile("CX-901", "asi_why:\n  ASI02: \"Tool misuse (ASI02): x.\"\n")); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a customer scenario with a reason: %v", err)
	}
}
