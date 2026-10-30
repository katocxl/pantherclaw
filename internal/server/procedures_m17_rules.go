// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// rulesProcedures are ConsequenceRuleService's procedures (G0 M17 D112):
// proposing and retiring need consequence_rule.manage, reading package.read.
// The use cases add the people-only rule and the edition; the change
// itself waits for a second person (D107).
var rulesProcedures = map[string]td.Permission{
	pantherclawv1connect.ConsequenceRuleServiceProposeConsequenceRuleProcedure: td.PermConsequenceRuleManage,
	pantherclawv1connect.ConsequenceRuleServiceRetireConsequenceRuleProcedure:  td.PermConsequenceRuleManage,
	pantherclawv1connect.ConsequenceRuleServiceListConsequenceRulesProcedure:   td.PermPackageRead,
	pantherclawv1connect.ConsequenceRuleServiceGetConsequenceRuleProcedure:     td.PermPackageRead,
}

func init() { maps.Copy(procedurePermissions, rulesProcedures) }
