// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

func federatedGrant(req Requirement) Grant {
	return Grant{
		ID: NewGrantID(), Org: ids.New[ids.Org](), Revision: 1, State: StateActive,
		AgentID: ids.NewV7(), EnvironmentID: ids.NewV7(),
		Principal: Principal{Kind: PrincipalFederated, ID: ids.NewV7(), Peer: "pc:org/peer/agent/bot"},
		TaskRef:   "federation:pay", NotBefore: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		Grantor: Principal{Kind: PrincipalUser, ID: ids.NewV7()}, Basis: "grant.issue",
		Requirements: []Requirement{req},
	}
}

// TestHR776_ACrossOrgGrantCannotRequireAStepUp: an approval on a cross-org
// grant is issued, and a step-up is refused because the peer agent is not
// a person (D1024e).
func TestHR776_ACrossOrgGrantCannotRequireAStepUp(t *testing.T) {
	ok := federatedGrant(Requirement{
		Operations: Ops{"federation.message.receive"},
		Approval:   &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
		Reason:     "PEER_MESSAGE",
	})
	if err := ok.validate(nil); err != nil {
		t.Fatalf("approval grant: %v", err)
	}
	bad := federatedGrant(Requirement{
		Operations: Ops{"federation.message.receive"},
		StepUp:     &pdomain.StepUpRequirement{Subject: "principal", Method: "webauthn"},
		Reason:     "PEER_STEP_UP",
	})
	err := bad.validate(nil)
	if err == nil || !strings.Contains(err.Error(), "step-up") {
		t.Fatalf("step-up grant: %v", err)
	}
}
