// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

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

// ErrRefusalCode reports a local refusal code the server does not record.
var ErrRefusalCode = pcerr.New(pcerr.InvalidArgument, "REFUSAL_CODE_UNKNOWN", "the gateway reported an unknown local refusal code")

// ReportLocalRefusal records that gateway refused an action through
// connection id on its own, before asking the Authority, so detections see
// it (G0 M12, HR-225): connection.secret_in_payload_refused, with the
// gateway as actor and only machine metadata, the operation and the run,
// never the payload or the secret. The connection must be one the gateway
// serves (otherwise not found); a simulated connection's report is audited
// with simulated=true, a test event (HR-222).
func (s *Service) ReportLocalRefusal(ctx context.Context, org ids.OrgID, gateway, id ids.UUID, code, operation string, run ids.UUID) error {
	if code != RefusalSecretInPayload {
		return ErrRefusalCode
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
		if conn.Simulated {
			details["simulated"] = "true"
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "connection.secret_in_payload_refused", Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()},
			Outcome: audit.Denied, ReasonCode: "SECRET_IN_PAYLOAD", Object: &audit.Object{Type: "connection", ID: id.String()},
			Details: details,
		})
		return err
	})
}
