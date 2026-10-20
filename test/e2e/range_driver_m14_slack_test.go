// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// Slack range capabilities (G0 M14 D46): an agent posting through pc.slack,
// and a forged Slack interaction against the server.
const (
	capSlackPost        app.Capability = "slack.post"
	capSlackInteraction app.Capability = "slack.interaction_post"
)

// slackScenario reports whether a scenario needs the Slack simulator and
// the connection "slack".
func slackScenario(sc domain.Scenario) bool {
	return requires(sc, string(capSlackPost)) || requires(sc, string(capSlackInteraction))
}

// setupSlack gives the scenario's agent a grant of its own for pc.slack when
// it posts: it may post to the approvals and the shared channel and read
// channels, and nothing that would disclose outside the workspace (D25,
// HR-316).
func (d *rangeDriver) setupSlack() {
	if !requires(d.sc, string(capSlackPost)) {
		return
	}
	d.ownGrant(fmt.Sprintf(`{"operations": ["slack.message.post", "slack.channel.read"],
		"targets": {"slack_channel": {"ids": [%q, %q, %q]}},
		"destinations": {"ids": [%q, %q]}}`, slackApprovals, slackExternal, slackOutside, slackApprovals, slackExternal), "")
}

// slackForgedPaths are where a forged Slack interaction is sent: the paths a
// Slack app's interactivity, actions and events would use, none of which
// PantherClaw serves (HR-313).
var slackForgedPaths = []string{"/slack/interactions", "/slack/actions", "/api/slack/events", "/slack/events"}

// slackMutate is the Slack simulator's sim.mutate (D91). reaction and reply
// change only what Slack shows: a person reacts to, or answers, a message in
// the approvals channel, and nothing reaches PantherClaw. interaction_post
// sends a forged block_actions payload, an "approve" button press for the
// held request of args.step, to every Slack-shaped path of the server and to
// the request's approval path without a session; it observes REFUSED when
// every one was refused and the request still waits, else ALLOW.
func (d *rangeDriver) slackMutate(change string, args jsontext.Value) (domain.Observation, error) {
	var a struct {
		Step string `json:"step"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &a); err != nil {
			return domain.Observation{}, err
		}
	}
	request, err := d.slackHeldRequest(a.Step)
	if err != nil {
		return domain.Observation{}, err
	}
	sim := d.s.slack.sim
	switch change {
	case "reaction", "reply":
		// The person's activity is on a message in the channel: the
		// simulator's copy of what Slack shows. There is no card on a
		// Community server; the approvals channel's last message stands in.
		ts := ""
		if ms := sim.Messages(); len(ms) > 0 {
			ts = ms[len(ms)-1].TS
		}
		if change == "reaction" && ts != "" {
			sim.React(slackApprovals, ts, "white_check_mark")
		}
		return d.slackStillWaiting(request, nil)
	case "interaction_post":
		payload, _ := json.Marshal(map[string]any{
			"type": "block_actions", "team": map[string]string{"id": "T0SIMULATED"}, "user": map[string]string{"id": "U0ATTACKER1"},
			"actions": []map[string]string{{"action_id": "approve", "value": "approve:" + request}},
			"channel": map[string]string{"id": slackApprovals},
		})
		form := url.Values{"payload": {string(payload)}}.Encode()
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		c := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		var accepted []string
		paths := append(append([]string(nil), slackForgedPaths...), "/approvals/"+request+"/approve")
		for _, p := range paths {
			req, err := http.NewRequest(http.MethodPost, d.s.apiURL+p, strings.NewReader(form))
			if err != nil {
				return domain.Observation{}, err
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Slack-Request-Timestamp", ts)
			req.Header.Set("X-Slack-Signature", "v0=0000000000000000000000000000000000000000000000000000000000000000")
			resp, err := c.Do(req)
			if err != nil {
				return domain.Observation{}, err
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				accepted = append(accepted, p)
			}
		}
		return d.slackStillWaiting(request, accepted)
	}
	return domain.Observation{}, fmt.Errorf("slack change %q", change)
}

// slackHeldRequest is the approval request of an earlier held call.
func (d *rangeDriver) slackHeldRequest(step string) (string, error) {
	rec, err := d.stepRec(step)
	if err != nil {
		return "", err
	}
	if rec.txn == "" {
		return "", fmt.Errorf("step %s held nothing", step)
	}
	var id string
	d.s.query(d.t, "SELECT id::text FROM pc.approval_requests WHERE transaction_id = $1", []any{rec.txn}, &id)
	return id, nil
}

// slackStillWaiting observes REFUSED when nothing was accepted and the
// request still waits for a person on its page.
func (d *rangeDriver) slackStillWaiting(request string, accepted []string) (domain.Observation, error) {
	var state string
	d.s.query(d.t, "SELECT state FROM pc.approval_requests WHERE id = $1", []any{request}, &state)
	if len(accepted) > 0 || state != "PENDING" {
		return domain.Observation{
			Outcome: domain.OutcomeAllow, Detail: fmt.Sprintf("accepted at %v; request %s", accepted, state),
		}, nil
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Code: "no_slack_endpoint", Detail: "request " + state}, nil
}
