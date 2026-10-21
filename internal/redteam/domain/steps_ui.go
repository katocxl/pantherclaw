// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"regexp"
	"slices"
)

// The UI phase's range steps (G0 UI D16; RT-062..RT-064): plan events the
// billing extension reports, a person's org procedure under the plan gate,
// and a server configuration check. Scenarios that use them require the
// "billing" capability: the stack runs with hosted plans.
//
//   - plan.event {status, edition?, age?}: the billing extension reports a
//     plan event for the org; age "older" reports one older than the last
//     applied. ALLOW when the plan changed to it, REFUSED otherwise (the
//     reason says why).
//   - person.rpc {procedure, as}: a person of the org calls procedure as
//     the plan gate sees it. ALLOW, REFUSED (PLAN_REQUIRED) or NOT_FOUND
//     (no such procedure is served).
//   - config.check {deployment, billing_mode}: a server configuration the
//     operator starts. ALLOW when start-up accepts it, REFUSED otherwise.
type (
	planEventWith struct {
		Status  string `json:"status"`
		Edition string `json:"edition,omitempty"`
		Age     string `json:"age,omitempty"`
	}
	personRPCWith struct {
		Procedure string `json:"procedure"`
		As        string `json:"as"`
	}
	configCheckWith struct {
		Deployment  string `json:"deployment"`
		BillingMode string `json:"billing_mode"`
	}
)

var (
	planStatuses  = []string{"NONE", "TRIALING", "ACTIVE", "PAST_DUE", "PAUSED", "CANCELED", "LAPSED", "COMP", "DEV"}
	planEditions  = []string{"", "team", "business", "enterprise", "development"}
	planAges      = []string{"", "older"}
	rpcRoles      = []string{"org_admin", "developer", "emergency_responder", "approver", "viewer"}
	procedureRE   = regexp.MustCompile(`^/pantherclaw\.v1\.[A-Z][A-Za-z]{1,63}/[A-Z][A-Za-z]{1,63}$`)
	deployments   = []string{"development", "staging", "production"}
	billingModes  = []string{"", "licence", "off", "external", "fake"}
	uiStepKinds   map[string]func(strict func(any) error) error
	uiStepKindSet = []string{"plan.event", "person.rpc", "config.check"}
)

func init() {
	capabilities = append(capabilities, "billing")
	StepKinds = append(StepKinds, uiStepKindSet...)
	for _, k := range uiStepKindSet {
		kindsNeedingEx[k] = true
	}
	uiStepKinds = map[string]func(strict func(any) error) error{
		"plan.event": func(strict func(any) error) error {
			var w planEventWith
			if err := strict(&w); err != nil {
				return err
			}
			if !slices.Contains(planStatuses, w.Status) || !slices.Contains(planEditions, w.Edition) || !slices.Contains(planAges, w.Age) {
				return fmt.Errorf("status must be one of %v, edition one of %v and age one of %v", planStatuses, planEditions, planAges)
			}
			return nil
		},
		"person.rpc": func(strict func(any) error) error {
			var w personRPCWith
			if err := strict(&w); err != nil {
				return err
			}
			if !procedureRE.MatchString(w.Procedure) || !slices.Contains(rpcRoles, w.As) {
				return fmt.Errorf("procedure must be a /pantherclaw.v1.Service/Method name and as one of %v", rpcRoles)
			}
			return nil
		},
		"config.check": func(strict func(any) error) error {
			var w configCheckWith
			if err := strict(&w); err != nil {
				return err
			}
			if !slices.Contains(deployments, w.Deployment) || !slices.Contains(billingModes, w.BillingMode) {
				return fmt.Errorf("deployment must be one of %v and billing_mode one of %v", deployments, billingModes)
			}
			return nil
		},
	}
}
