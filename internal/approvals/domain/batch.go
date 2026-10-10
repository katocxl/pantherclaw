// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Batch review (HR-175, decision 9, Team edition): a person may decline
// any set of up to 25 waiting requests for one operation at once, and
// approve at once only homogeneous low-risk holds. Each request still gets
// its own response, audit event and later consumption.

// MaxBatch caps a batch.
const MaxBatch = 25

// Why a request cannot be approved in a batch.
const (
	BatchNotAHold           = "NOT_A_HOLD"
	BatchMixed              = "MIXED_ACTIONS"
	BatchNotReversible      = "NOT_REVERSIBLE"
	BatchNotSingleApprover  = "NOT_SINGLE_APPROVER"
	BatchNoValue            = "NO_SINGLE_VALUE"
	BatchOverCeiling        = "OVER_BATCH_CEILING"
	reversibilityReversible = "reversible"
)

// Batchable reports whether a held action may be approved in a batch
// (decision 9): its definition is reversible; its one requirement is a
// single approver, neither independent nor a step-up; and its value, the
// definition's one money parameter, is at or below the org's ceiling for
// that currency. A ceiling that is not set turns batch approval off, and an
// action without a single money value is always reviewed alone.
func Batchable(reqs []Requirement, reversibility string, value *money.Money, ceilings map[string]string) (bool, string) {
	if reversibility != reversibilityReversible {
		return false, BatchNotReversible
	}
	if len(reqs) != 1 || reqs[0].Kind != KindApproval || reqs[0].Count != 1 || reqs[0].Independent {
		return false, BatchNotSingleApprover
	}
	if value == nil {
		return false, BatchNoValue
	}
	limit, ok := ceilings[string(value.Currency)]
	if !ok {
		return false, BatchOverCeiling
	}
	ceiling, err := money.ParseMoney(limit, string(value.Currency))
	if err != nil {
		return false, BatchOverCeiling
	}
	if c, err := value.Cmp(ceiling); err != nil || c > 0 {
		return false, BatchOverCeiling
	}
	return true, ""
}
