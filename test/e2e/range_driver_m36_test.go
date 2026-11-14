// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	apapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/otlpexport"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func (d *rangeDriver) reachProbe(st domain.Step) (domain.Observation, error) {
	var w struct {
		Attack string `json:"attack"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	switch w.Attack {
	case "forged_trace":
		return reachForgedTrace()
	case "otlp_exfil":
		return reachOTLPExfil()
	case "fatigue_stamp":
		return reachFatigue()
	case "deputy_widen":
		return reachDeputy()
	case "push_leak":
		return reachPush()
	}
	return domain.Observation{}, fmt.Errorf("unknown attack %q", w.Attack)
}

func reachForgedTrace() (domain.Observation, error) {
	for _, bad := range []string{
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	} {
		if dispatch.ParseTraceparent(bad) != nil {
			return domain.Observation{Outcome: domain.OutcomeAllow, Reason: "TRACE_ACCEPTED"}, nil
		}
	}
	if dispatch.ParseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01") == nil {
		return domain.Observation{}, fmt.Errorf("a strict traceparent was rejected")
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "TRACE_IGNORED"}, nil
}

func reachOTLPExfil() (domain.Observation, error) {
	for _, raw := range []string{"http://127.0.0.1/v1/traces", "https://169.254.169.254/latest", "https://10.1.2.3/v1/traces"} {
		if err := otlpexport.CheckURL(raw, "pantherclaw.example", nil); err == nil {
			return domain.Observation{Outcome: domain.OutcomeAllow, Reason: "DESTINATION_ACCEPTED"}, nil
		}
	}
	if err := otlpexport.CheckURL("https://collector.example/v1/traces", "pantherclaw.example", nil); err != nil {
		return domain.Observation{}, err
	}
	if (billing.Entitlements{Edition: billing.Team}).OTLPExport() || !(billing.Entitlements{Edition: billing.Business}).OTLPExport() {
		return domain.Observation{Outcome: domain.OutcomeAllow, Reason: "EDITION_OPEN"}, nil
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "DESTINATION_REFUSED"}, nil
}

func reachFatigue() (domain.Observation, error) {
	n, err := (&apapp.Service{}).FlagFatigue(context.Background(), ids.New[ids.Org]())
	if err != nil {
		return domain.Observation{}, err
	}
	if n != 0 || apapp.FlagRateApprovals < 30 || apapp.FlagNoDeclineApprovals < 50 {
		return domain.Observation{Outcome: domain.OutcomeAllow, Reason: "FATIGUE_APPROVED"}, nil
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "FATIGUE_DOES_NOT_APPROVE"}, nil
}

func reachDeputy() (domain.Observation, error) {
	ok, _ := apdomain.Check(apdomain.Requirement{}, apdomain.Person{Enabled: false, UserID: ids.NewV7()}, apdomain.Context{}, ids.UUID{})
	if ok {
		return domain.Observation{Outcome: domain.OutcomeAllow, Reason: "DEPUTY_ELIGIBLE"}, nil
	}
	org := ids.New[ids.Org]()
	user := ids.NewV7()
	ctx := tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
			Bindings: []td.Binding{{Role: td.RoleApprover, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
		},
		Credential: tenancy.CredBrowserSession,
	})
	now := time.Now()
	_, err := (&apapp.Service{}).SetDeputy(ctx, nil, user, now, now.Add(time.Hour))
	if err == nil {
		return domain.Observation{Outcome: domain.OutcomeAllow, Reason: "SELF_DEPUTY"}, nil
	}
	if !errors.Is(err, apapp.ErrDeputyInvalid) {
		return domain.Observation{}, err
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "DEPUTY_NOT_ELIGIBLE"}, nil
}

func reachPush() (domain.Observation, error) {
	if _, err := ndomain.PushEndpointHost("https://evil.example/push"); err == nil {
		return domain.Observation{Outcome: domain.OutcomeAllow, Reason: "PUSH_HOST"}, nil
	}
	if _, err := ndomain.PushEndpointHost("https://fcm.googleapis.com/fcm/send/abc"); err != nil {
		return domain.Observation{}, err
	}
	raw, err := json.Marshal(ndomain.PushPayloadFor("https://pc.example", "approval.requested", "01920000-0000-7000-8000-000000000001", 1))
	if err != nil {
		return domain.Observation{}, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return domain.Observation{}, err
	}
	if len(doc) != 2 || strings.Contains(string(raw), "prompt") || strings.Contains(string(raw), "operation") {
		return domain.Observation{Outcome: domain.OutcomeAllow, Reason: "PUSH_LEAKED"}, nil
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "PUSH_LINK_ONLY"}, nil
}
