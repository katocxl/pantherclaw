// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/hex"
	"slices"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// RefusalSecretInPayload is the gateway's local refusal of an action that
// carried the dispatching connection's own static credential (HR-225).
const RefusalSecretInPayload = "secret_in_payload"

// RefusalElicitationRefused is the gateway's local refusal of an upstream
// server's elicitation that the reviewed mapping does not allow (G0 M15
// D33, D40).
const RefusalElicitationRefused = "elicitation_refused"

// ElicitationReasons are the reasons an elicitation refusal may carry.
var ElicitationReasons = []string{"url_mode", "undeclared_field", "type_mismatch", "duplicate_field", "too_many_fields", "injection_flagged"}

// ErrRefusalCode reports a local refusal code the server does not record.
var ErrRefusalCode = pcerr.New(pcerr.InvalidArgument, "REFUSAL_CODE_UNKNOWN", "the gateway reported an unknown local refusal code")

// ErrRefusalDetail reports refusal details that do not belong to the code.
var ErrRefusalDetail = pcerr.New(pcerr.InvalidArgument, "REFUSAL_DETAIL_INVALID", "the refusal's details do not fit its code")

// RefusalDetail is what an elicitation refusal adds (D40): its reason and
// the SHA-256 of the refused question, never the question.
type RefusalDetail struct {
	ElicitationReason string
	QuestionSHA256    []byte
}

// refusals are the audit event and reason code of each refusal code.
var refusals = map[string][2]string{
	RefusalSecretInPayload:    {"connection.secret_in_payload_refused", "SECRET_IN_PAYLOAD"},
	RefusalElicitationRefused: {"connection.elicitation_refused", "ELICITATION_REFUSED"},
}

// ReportLocalRefusal records that gateway refused an action through
// connection id on its own, so detections see it (G0 M12, HR-225; G0 M15
// D40): connection.secret_in_payload_refused or
// connection.elicitation_refused, with the gateway as actor and only
// machine metadata, the operation, the run and, for an elicitation, the
// reason and the question's SHA-256, never the payload, the secret or the
// question. The connection must be one the gateway serves (otherwise not
// found); a simulated connection's report is audited with simulated=true,
// a test event (HR-222).
func (s *Service) ReportLocalRefusal(ctx context.Context, org ids.OrgID, gateway, id ids.UUID, code, operation string, run ids.UUID,
	detail RefusalDetail,
) error {
	event, ok := refusals[code]
	if !ok {
		return ErrRefusalCode
	}
	switch {
	case code != RefusalElicitationRefused && (detail.ElicitationReason != "" || detail.QuestionSHA256 != nil):
		return ErrRefusalDetail
	case detail.ElicitationReason != "" && !slices.Contains(ElicitationReasons, detail.ElicitationReason):
		return ErrRefusalDetail
	case detail.QuestionSHA256 != nil && len(detail.QuestionSHA256) != 32:
		return ErrRefusalDetail
	}
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		conn, err := lock(ctx, dbq.New(tx), org, id)
		if err != nil {
			return err
		}
		if conn.GatewayID != gateway {
			return ErrNotFound
		}
		details := map[string]string{"code": code}
		if operation != "" {
			details["operation"] = operation
		}
		if !run.IsZero() {
			details["run_id"] = run.String()
		}
		if detail.ElicitationReason != "" {
			details["elicitation_reason"] = detail.ElicitationReason
		}
		if detail.QuestionSHA256 != nil {
			details["question_sha256"] = hex.EncodeToString(detail.QuestionSHA256)
		}
		if conn.Simulated {
			details["simulated"] = "true"
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: event[0], Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()},
			Outcome: audit.Denied, ReasonCode: event[1], Object: &audit.Object{Type: "connection", ID: id.String()},
			Details: details,
		})
		return err
	})
}
