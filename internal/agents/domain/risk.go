// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// RiskTier is the risk tier people state for an agent (G0 M24 D230). The
// risk fields describe an agent; they grant nothing and no decision reads
// them.
type RiskTier string

// Risk tiers.
const (
	RiskUnset    RiskTier = "UNSET"
	RiskLow      RiskTier = "LOW"
	RiskMedium   RiskTier = "MEDIUM"
	RiskHigh     RiskTier = "HIGH"
	RiskCritical RiskTier = "CRITICAL"
)

// AIActRole is the EU AI Act role people state for an agent.
type AIActRole string

// EU AI Act roles.
const (
	AIActRoleUnset         AIActRole = "UNSET"
	AIActRoleProvider      AIActRole = "PROVIDER"
	AIActRoleDeployer      AIActRole = "DEPLOYER"
	AIActRoleNotApplicable AIActRole = "NOT_APPLICABLE"
)

// AIActRisk is the EU AI Act risk class people state for an agent.
type AIActRisk string

// EU AI Act risk classes.
const (
	AIActRiskUnset   AIActRisk = "UNSET"
	AIActRiskMinimal AIActRisk = "MINIMAL"
	AIActRiskLimited AIActRisk = "LIMITED"
	AIActRiskHigh    AIActRisk = "HIGH"
)

// RiskPatch changes the risk fields that are set; a nil DataClasses keeps
// them and an empty one clears them.
type RiskPatch struct {
	Tier        *RiskTier
	DataClasses []string
	Role        *AIActRole
	Risk        *AIActRisk
}

// Validate checks the patch's closed values against vocabulary, the data
// classes of the definitions format.
func (p RiskPatch) Validate(vocabulary []string) error {
	if p.Tier != nil && !slices.Contains([]RiskTier{RiskUnset, RiskLow, RiskMedium, RiskHigh, RiskCritical}, *p.Tier) {
		return fmt.Errorf("%w: unknown risk tier", ErrInvalid)
	}
	if p.Role != nil && !slices.Contains([]AIActRole{AIActRoleUnset, AIActRoleProvider, AIActRoleDeployer, AIActRoleNotApplicable}, *p.Role) {
		return fmt.Errorf("%w: unknown AI Act role", ErrInvalid)
	}
	if p.Risk != nil && !slices.Contains([]AIActRisk{AIActRiskUnset, AIActRiskMinimal, AIActRiskLimited, AIActRiskHigh}, *p.Risk) {
		return fmt.Errorf("%w: unknown AI Act risk class", ErrInvalid)
	}
	for _, c := range p.DataClasses {
		if !slices.Contains(vocabulary, c) {
			return fmt.Errorf("%w: data class %q is not one of %v", ErrInvalid, c, vocabulary)
		}
	}
	return nil
}

// Details are the change's values for the agent's history and the audit
// record; every one comes from a closed vocabulary.
func (p RiskPatch) Details() map[string]string {
	m := map[string]string{}
	if p.Tier != nil {
		m["risk_tier"] = string(*p.Tier)
	}
	if p.DataClasses != nil {
		m["data_classes"] = fmt.Sprint(p.DataClasses)
	}
	if p.Role != nil {
		m["ai_act_role"] = string(*p.Role)
	}
	if p.Risk != nil {
		m["ai_act_risk"] = string(*p.Risk)
	}
	return m
}
