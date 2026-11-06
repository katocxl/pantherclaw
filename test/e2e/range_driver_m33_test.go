// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// M33 range setup (RT-220..RT-224; D1216): capability browser_agent is the
// browser and computer hook connections (dev seed --browser), a run on a
// grant naming every pc.browser and pc.computer operation, and the site list
// docs.example.com and shop.example.com with its subdomains, marked for the
// cloaking compare.
const capBrowserAgent = app.Capability("browser_agent")

// browserRoles are the M33 range roles and the dev seed's connections they
// are bound to, as `--role pc-browser=browser --role pc-computer=computer`
// binds them (D1220 (3); a role name has no underscore): a role named browser would also turn on the
// console capability browser (RT-060, RT-061).
var browserRoles = map[string]string{"pc-browser": "browser", "pc-computer": "computer"}

// browserTool reports whether a hook-face tool is a pc.browser or
// pc.computer one: the native host's and the computer-use wrappers' call,
// not Claude Code's.
func browserTool(tool string) bool { return strings.HasPrefix(tool, "browser_") || tool == "computer" }

// setupBrowserAgent lists the range's sites and starts the run on the
// browser grant.
func (d *rangeDriver) setupBrowserAgent(sc domain.Scenario) {
	if !requires(sc, string(capBrowserAgent)) {
		return
	}
	d.s.listBrowserSites(d.t, m33Site{host: "docs.example.com"}, m33Site{host: "shop.example.com", subdomains: true, compare: true})
	d.s.grantRun(d.t, m33Bounds, false)
}

// callBrowserHook asks the hook face as `pclaw browser host` does: a signed
// PAP/1 POST of the tool and its input, with the action id.
func (d *rangeDriver) callBrowserHook(conn string, w callWith, act ids.UUID) (domain.Observation, *callRec, error) {
	if c, ok := browserRoles[conn]; ok {
		conn = c
	}
	input := w.Args
	if len(input) == 0 {
		input = []byte("{}")
	}
	body, err := json.Marshal(map[string]any{"tool": w.Tool, "input": input})
	if err != nil {
		return domain.Observation{}, nil, err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, d.s.gateway+"/hook/"+url.PathEscape(conn), bytes.NewReader(body))
	if err != nil {
		return domain.Observation{}, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(gateway.HeaderRunID, d.runHeader())
	req.Header.Set(gateway.HeaderActionID, act.String())
	resp, err := d.client(w.Instance).Do(req)
	if err != nil {
		return domain.Observation{}, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var a struct {
		Decision      string   `json:"decision"`
		ErrorClass    string   `json:"error_class"`
		Code          string   `json:"code"`
		Reasons       []string `json:"reasons"`
		TransactionID string   `json:"transaction_id"`
		Held          bool     `json:"held"`
	}
	if err := json.Unmarshal(raw, &a, json.RejectUnknownMembers(false)); err != nil {
		return domain.Observation{}, nil, fmt.Errorf("hook face answered HTTP %d without JSON: %s", resp.StatusCode, raw)
	}
	// As the live driver reads the hook face (internal/redteam/adapters/live
	// hook and classify), so a scenario passes the same way on both.
	class := a.ErrorClass
	if a.Decision == "deny" && class == "" && !a.Held {
		class = "policy_denied"
	}
	first := a.Code
	if first == "" && len(a.Reasons) > 0 {
		first = a.Reasons[0]
	}
	obs := domain.Observation{TransactionID: a.TransactionID, Reasons: a.Reasons, Detail: string(capBytes(raw))}
	switch {
	case a.Held || class == "held":
		obs.Outcome, obs.Reason = domain.OutcomeHold, first
	case class == "":
		obs.Outcome, obs.Response = domain.OutcomeAllow, capBytes(raw)
	case class == "policy_denied":
		obs.Outcome, obs.Reason = domain.OutcomeDeny, first
	case class == "cannot_authorize" && len(a.Reasons) > 0:
		obs.Outcome, obs.Reason = domain.OutcomeCannotAuthorize, first
	case class == "tool_failed" || class == "target_refused":
		obs.Outcome, obs.Code = domain.OutcomeTargetRefused, a.Code
	default:
		obs.Outcome, obs.Code = domain.OutcomeRefused, a.Code
	}
	return obs, &callRec{act: act, txn: obs.TransactionID, obs: obs}, nil
}
