// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package library is the PantherClaw scenario library as the server knows
// it (G0 M17 D125, HR-467): each shipped redteam/scenarios file's id, digest
// and tier, embedded in the build. A range accepts an RT scenario only when
// its declared digest is the library's, and takes its tier from here, never
// from the runner. library.json is generated from redteam/scenarios
// (`task range:library`); a test fails when the two differ.
package library

import (
	_ "embed"
	"encoding/json/v2"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/campaigns/domain"
)

// Entry is one library scenario.
type Entry struct {
	Digest string `json:"digest"`
	Tier   string `json:"tier"`
}

//go:embed library.json
var raw []byte

var entries = func() map[string]Entry {
	var m map[string]Entry
	if err := json.Unmarshal(raw, &m, json.RejectUnknownMembers(true)); err != nil {
		panic(fmt.Sprintf("library.json: %v", err))
	}
	return m
}()

// CampaignEntry is one library campaign (G0 M25 D310): its digest, and the
// attempts the server derives outcomes for, never the runner's.
type CampaignEntry struct {
	Digest   string           `json:"digest"`
	Tier     string           `json:"tier"`
	Attempts []domain.Attempt `json:"attempts"`
}

//go:embed campaigns.json
var campaignsRaw []byte

var campaigns = func() map[string]CampaignEntry {
	var m map[string]CampaignEntry
	if err := json.Unmarshal(campaignsRaw, &m, json.RejectUnknownMembers(true)); err != nil {
		panic(fmt.Sprintf("campaigns.json: %v", err))
	}
	return m
}()

// Campaign returns the library's campaign for an RT id.
func Campaign(id string) (CampaignEntry, bool) {
	e, ok := campaigns[id]
	return e, ok
}

// Lookup returns the library's entry for an RT id.
func Lookup(id string) (Entry, bool) {
	e, ok := entries[id]
	return e, ok
}

// All returns a copy of every entry, by id.
func All() map[string]Entry {
	out := make(map[string]Entry, len(entries))
	for k, v := range entries {
		out[k] = v
	}
	return out
}
