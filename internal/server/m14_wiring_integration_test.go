// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"reflect"
	"testing"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
)

// m14Required are the M14 instances each process role must wire (G0 M14
// D41): the kind configuration registry with the postgres kind (D64), the
// process's one grants service gated by edition for data scope (D11), and
// the notifications service with its edition source (Slack cards, D22) in
// every role; in the API also the API's grants and policy versions (D11),
// the AuthZEN enforcement points and decision endpoint (D26-D29), the
// postgres manifest confirm page (D84) and the Slack channel pages (D66).
var m14Required = map[string][]string{
	RoleAll: {
		"m14.kinds", "m14.grants.process", "m14.notifications", "m14.grants.api", "m14.policy.versions", "m14.authzen.points",
		"m14.authzen.endpoint", "m14.postgres.manifests",
	},
	RoleWorker: {"m14.kinds", "m14.grants.process", "m14.notifications"},
}

// m14WithSecurityKeys are wired only when security keys (WebAuthn) are
// configured, which the test configuration does not do: the Slack channel
// pages confirm a channel with a step-up (D66), like the M11 policy
// changes pages. TestE2E_M14_SlackApprovalCards serves them.
var m14WithSecurityKeys = []string{"m14.slack.page"}

// m14Kinds are the connection kinds whose configuration store the M14
// wiring registers (D64): a2a joins when its stream lands.
var m14Kinds = []string{capp.KindPostgres}

// TestM14_WiringComplete: the real server, started as one process (all)
// and as a worker-only process, wires every M14 instance its role needs,
// with the ports M14 added set (G0 M14 D41). In-process e2e tests build
// their own instances, so this is where a port left nil shows.
func TestM14_WiringComplete(t *testing.T) {
	for _, role := range []string{RoleAll, RoleWorker} {
		t.Run(role, func(t *testing.T) {
			got := serveAndRecord(t, role)
			for _, kind := range m14WithSecurityKeys {
				if len(got[kind]) != 0 && role == RoleWorker {
					t.Errorf("%s: a worker wires %s", role, kind)
				}
			}
			for _, kind := range m14Required[role] {
				if len(got[kind]) == 0 {
					t.Errorf("%s: the server wires no %s", role, kind)
				}
			}
			for _, v := range got["m14.kinds"] {
				for _, k := range m14Kinds {
					if _, ok := v.(*ports.KindConfigs).Get(k); !ok {
						t.Errorf("%s: no configuration store for %s connections", role, k)
					}
				}
			}
			for _, kind := range []string{"m14.grants.process", "m14.grants.api"} {
				for i, v := range got[kind] {
					if g, _ := v.(*grantsapp.Service); g == nil || g.Editions == nil {
						t.Errorf("%s: %s #%d has no edition source: data scope in grants is not gated (D11)", role, kind, i+1)
					}
				}
			}
			for i, v := range got["m14.policy.versions"] {
				if pv := v.(*policyapp.Versions); pv.Editions == nil {
					t.Errorf("%s: policy versions #%d have no edition source: data scope rules are not gated (D11)", role, i+1)
				}
			}
			for i, v := range got["m14.notifications"] {
				if reflect.ValueOf(v.(*napp.Service)).Elem().FieldByName("editions").IsNil() {
					t.Errorf("%s: notifications #%d have no edition source: Slack cards are not gated (D22)", role, i+1)
				}
			}
			for _, kind := range []string{"m14.authzen.endpoint", "m14.authzen.points", "m14.postgres.manifests"} {
				for i, v := range got[kind] {
					for _, gap := range m11NilPorts(v) {
						t.Errorf("%s: %s #%d: %s is nil", role, kind, i+1, gap)
					}
				}
			}
		})
	}
}
