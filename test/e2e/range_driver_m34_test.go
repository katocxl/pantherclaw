// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"strings"
	"time"

	runtimeface "github.com/katocxl/pantherclaw/internal/gateway/runtime"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/sim/agentcore"
	"github.com/katocxl/pantherclaw/internal/sim/aws"
)

// runtimeProbe executes each M34 attack against an isolated simulated cloud
// account and the real gateway and server. A failed prerequisite is an
// error rather than a successful observation.
func (d *rangeDriver) runtimeProbe(st domain.Step) (domain.Observation, error) {
	var w struct {
		Attack string `json:"attack"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	t, s := d.t, d.s
	refused := func(reason string) domain.Observation {
		return domain.Observation{Outcome: domain.OutcomeRefused, Reason: reason}
	}
	switch w.Attack {
	case "missing_proof":
		event := toolEvent(t, agentcore.Target, "get_refund", map[string]any{"refund": "re_rt225"})
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+runtimeface.AgentCorePath, bytes.NewReader(event))
		if err != nil {
			return domain.Observation{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(runtimeface.HeaderGateway, agentcore.GatewayARN)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return domain.Observation{}, err
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			return domain.Observation{Outcome: domain.OutcomeAllow, Detail: fmt.Sprintf("status %d", res.StatusCode)}, nil
		}
		return refused("NO_WORKLOAD_PROOF"), nil
	case "other_account":
		rt := s.setupRuntimeAgent(t)
		other := gatewayARN(m34OtherAccount, "rt-226")
		s.runtimeConnection(t, "agentcore-other", other, agentcore.Target)
		act := ids.NewV7()
		answer := s.face(t, rt, other, act, toolEvent(t, agentcore.Target, "get_refund", map[string]any{"refund": "re_rt226"}))
		txn, _, _, _ := s.txnOf(t, rt.run, act)
		if answer.Pass || txn != "" || !strings.Contains(answer.Text, "does not match the account its interceptor proved") {
			return domain.Observation{Outcome: domain.OutcomeAllow, Detail: fmt.Sprintf("response %s; transaction %s", answer.Raw, txn)}, nil
		}
		return refused("RUNTIME_ACCOUNT_MISMATCH"), nil
	case "unseen_deploy":
		s.scheduleAgentCore(t)
		if state, detail := s.dailyScan(t, 1); state != "DONE" || detail != "{}" {
			return domain.Observation{}, fmt.Errorf("baseline scan %s: %s", state, detail)
		}
		eventually(t, time.Minute, "the baseline runtime alert", func() (bool, error) {
			return s.alertsOf(t, m34Rule) > 0, nil
		})
		before := s.alertsOf(t, m34Rule)
		s.m34.deployRuntime(t, "shadow_rt227")
		s.dueAgain(t)
		if state, detail := s.dailyScan(t, 2); state != "DONE" {
			return domain.Observation{}, fmt.Errorf("second scan %s: %s", state, detail)
		}
		deadline := time.Now().Add(time.Minute)
		for time.Now().Before(deadline) {
			count := s.row(t, "SELECT count(*)::text FROM pc.discoveries WHERE org_id = $1 AND source = 'aws_agentcore' AND observed->>'name' = 'shadow_rt227'", s.org)
			if count == "1" && s.alertsOf(t, m34Rule) == before+1 {
				return domain.Observation{Outcome: domain.OutcomeAllow, Reason: "RUNTIME_DISCOVERED"}, nil
			}
			time.Sleep(250 * time.Millisecond)
		}
		count := s.row(t, "SELECT count(*)::text FROM pc.discoveries WHERE org_id = $1 AND source = 'aws_agentcore' AND observed->>'name' = 'shadow_rt227'", s.org)
		return domain.Observation{Outcome: domain.OutcomeRefused, Detail: fmt.Sprintf("new discoveries %s; alerts %d -> %d", count, before, s.alertsOf(t, m34Rule))}, nil
	case "other_instance":
		d.ownGrant(ssmGrant, "")
		if obs := d.ssmSend(t, m34Instance, "id"); obs.Outcome != domain.OutcomeAllow || len(s.m34.acct.Commands()) != 1 {
			return domain.Observation{}, fmt.Errorf("granted command did not run: %+v", obs)
		}
		checkSSMSession(t, s.m34.ssmPolicies(), m34Instance)
		obs := d.ssmSend(t, aws.SecondInstance, "id")
		if obs.Outcome == domain.OutcomeAllow || len(s.m34.acct.Commands()) != 1 {
			return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "other instance command reached AWS"}, nil
		}
		return refused("OTHER_INSTANCE_DENIED"), nil
	case "stale_credential":
		s.scheduleAgentCore(t)
		state, detail := s.dailyScan(t, 1)
		count := s.row(t, "SELECT count(*)::text FROM pc.discoveries WHERE org_id = $1 AND source = 'aws_agentcore'", s.org)
		if state != "FAILED" || count != "0" {
			return domain.Observation{Outcome: domain.OutcomeAllow, Detail: fmt.Sprintf("state %s, discoveries %s, not scanned %s", state, count, detail)}, nil
		}
		return refused("STALE_SCAN_FAILED"), nil
	default:
		return domain.Observation{}, fmt.Errorf("unknown runtime attack %q", w.Attack)
	}
}
