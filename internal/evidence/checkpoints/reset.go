// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package checkpoints

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// MaxResetReason caps the reason for a reset, which the audit ledger keeps
// as untrusted text.
const MaxResetReason = 500

// Errors from Reset.
var (
	ErrResetReason = fmt.Errorf("checkpoints: a reason of 1 to %d bytes without control or bidi characters is required", MaxResetReason)
	ErrNoOrg       = errors.New("checkpoints: no such organization")
)

// Cleared is the failure a reset cleared.
type Cleared struct {
	Code     string
	Seq      int64 // 0 when the failure named no position
	FailedAt time.Time
}

// Reset clears org's FAILED integrity status after an operator
// investigated (G0 M7 design decision 8). In one transaction it sets the
// status back to OK and forgets the last verification, writes
// evidence.integrity_reset with the cleared failure and reason to the org's
// audit ledger, and notifies org and security admins. Nothing is repaired:
// the checkpoint dispatcher lists the org again, and the next checkpoint
// verifies the previous one, the tiles and every link since it again, while
// the next daily verification walks the whole chain. If anything is still
// broken, the org fails again and is reported again.
//
// An org that is not FAILED is left unchanged and nothing is audited: Reset
// returns false.
func (s *Service) Reset(ctx context.Context, org ids.OrgID, actor domain.Actor, reason string) (Cleared, bool, error) {
	if !resetReasonOK(reason) {
		return Cleared{}, false, ErrResetReason
	}
	var out Cleared
	var done bool
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		out, done = Cleared{}, false
		q := dbq.New(tx)
		if _, err := q.GetOrg(ctx, org); db.IsNoRows(err) {
			return ErrNoOrg
		} else if err != nil {
			return err
		}
		old, err := q.ResetEvidenceIntegrity(ctx, org)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		if old.FailureCode == nil || old.FailedAt == nil {
			return errors.New("checkpoints: a FAILED status without its failure")
		}
		out, done = Cleared{Code: *old.FailureCode, FailedAt: *old.FailedAt}, true
		details := map[string]string{
			"failure_code": out.Code, "failed_at": out.FailedAt.UTC().Format(time.RFC3339), "reason": reason,
		}
		if old.FailedSeq.Valid {
			out.Seq = old.FailedSeq.Int64
			details["failed_seq"] = strconv.FormatInt(out.Seq, 10)
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "evidence.integrity_reset", Actor: actor, Outcome: audit.Success,
			Object: &audit.Object{Type: "evidence_log", ID: org.String()}, Details: details,
		}); err != nil {
			return err
		}
		if s.Notify == nil {
			return nil
		}
		_, err = s.Notify.Enqueue(ctx, tx, napp.Message{
			Org: org, Type: "security.evidence_integrity_reset", Params: map[string]string{"reason": out.Code},
		})
		return err
	})
	if errors.Is(err, ErrNoOrg) {
		return Cleared{}, false, fmt.Errorf("%w %s", ErrNoOrg, org)
	} else if err != nil {
		return Cleared{}, false, fmt.Errorf("checkpoints: reset org %s: %w", org, err)
	}
	if done {
		s.log().WarnContext(ctx, "evidence.integrity_reset", slog.String("org", org.String()),
			slog.String("actor", actor.ID), slog.String("code", out.Code), slog.Int64("seq", out.Seq))
	}
	return out, done, nil
}

// resetReasonOK accepts 1..MaxResetReason bytes of UTF-8 text that is not
// blank and holds no control or bidi characters (the reason is shown in
// terminals and audit views).
func resetReasonOK(r string) bool {
	if len(r) > MaxResetReason || !utf8.ValidString(r) || strings.TrimSpace(r) == "" {
		return false
	}
	for _, c := range r {
		if c < 0x20 || (c >= 0x7f && c <= 0x9f) || (c >= 0x200b && c <= 0x200f) || (c >= 0x202a && c <= 0x202e) ||
			(c >= 0x2066 && c <= 0x2069) || c == 0x2028 || c == 0x2029 {
			return false
		}
	}
	return true
}
