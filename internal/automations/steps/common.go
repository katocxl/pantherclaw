// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package steps

import (
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Step reasons beyond D24's, stable codes.
const (
	ReasonOutsideScope = "OUTSIDE_PLATFORM_SCOPE"
	ReasonBadWith      = "WITH_INVALID"
	ReasonRunFailed    = "RUN_FAILED"
	ReasonNoEffect     = "NO_EFFECT"
	ReasonDelivery     = "DELIVERY_FAILED"
	ReasonGateEnded    = "GATE_INVALIDATED"
	ReasonConnection   = "CONNECTION_INACTIVE"
)

// Evidence and output ref kinds the engine records beside the Reflex
// kinds.
const (
	RefGrant           = "grant"
	RefLaunch          = "automation_launch"
	RefApprovalRequest = "approval_request"
	RefDelivery        = "automation_delivery"
	RefNotification    = "notification"
)

// Output keys.
const (
	OutGrant    = "grant_id"
	OutRun      = "run_id"
	OutLaunch   = "launch_id"
	OutRequest  = "request_id"
	OutDelivery = "delivery_id"
	OutUntil    = "until"
)

func failed(reason string) (autodomain.StepResult, error) {
	return autodomain.StepResult{State: autodomain.StepFailed, Reason: reason, Effect: autodomain.EffectNone}, nil
}

func unwired() (autodomain.StepResult, error) { return failed(engine.ReasonUnsupported) }

// reasonPattern is a stable code.
var reasonPattern = regexp.MustCompile(`^[A-Z][A-Z_]{1,63}$`)

// refusal turns a use case's refusal into the step's reason; anything
// that is not a refusal with a stable code is returned as an error (the
// transaction rolls back and the driver retries).
func refusal(err error) (string, bool) {
	var e *pcerr.Error
	if !errors.As(err, &e) {
		return "", false
	}
	if c := e.Code(); c == pcerr.Internal || c == pcerr.Unavailable {
		return "", false
	}
	if r := e.Reason(); reasonPattern.MatchString(r) {
		return r, true
	}
	return "", false
}

// inScope reports whether the version's `platform` section lists kind with
// scope (HR-279).
func inScope(def *autodomain.Definition, kind, scope string) bool {
	for _, p := range def.Authority.Platform {
		if p.Step == kind && slices.Contains(p.Scopes, scope) {
			return true
		}
	}
	return false
}

// own is the output a waiting step recorded when it started.
func own(sc autodomain.StepContext) map[string]string { return sc.Outputs[sc.Spec.ID] }

// stepOutput is an earlier step's output.
func stepOutput(sc autodomain.StepContext, step string) (map[string]string, bool) {
	o, ok := sc.Outputs[step]
	return o, ok
}

func parseID(s string) (ids.UUID, bool) {
	u, err := ids.ParseUUID(s)
	return u, err == nil && !u.IsZero()
}

func q(tx pgx.Tx) *dbq.Queries { return dbq.New(tx) }

func ref(kind string, id ids.UUID) reflexdomain.EvidenceRef {
	return reflexdomain.EvidenceRef{Kind: kind, ID: id}
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func parseRFC(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

// shadowed is a preview's would-be result: SHADOWED with the would-be
// decision in the output (HR-288).
func shadowed(out map[string]string) (autodomain.StepResult, error) {
	return autodomain.StepResult{State: autodomain.StepShadowed, Effect: autodomain.EffectNone, Output: out}, nil
}

// upstreamShadowed reports whether the step a wait refers to was only
// previewed: the wait has nothing to wait for.
func upstreamShadowed(sc autodomain.StepContext, step string) bool {
	o, ok := stepOutput(sc, step)
	return sc.Mode != autodomain.ModeLive || ok && o["shadow"] == "true"
}
