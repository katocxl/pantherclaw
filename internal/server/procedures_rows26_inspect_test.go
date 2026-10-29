// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"testing"

	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestInspectBudgetsSkipsUnreadableGrants: a grant whose budget the caller
// may not read, or that is gone, leaves its lines without remaining and
// the inspection goes on; any other error still fails it (rows26 D25).
// Covers: F227
func TestInspectBudgetsSkipsUnreadableGrants(t *testing.T) {
	readable, denied, gone, account := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	limit := money.MustParse("100")
	state := func(_ context.Context, g domain.GrantID) ([]grantsapp.AccountState, error) {
		switch g.String() {
		case denied.String():
			return nil, td.ErrPermissionDenied(td.PermBudgetRead)
		case gone.String():
			return nil, grantsapp.ErrGrantNotFound
		case readable.String():
			return []grantsapp.AccountState{{
				BudgetAccount: grantsapp.BudgetAccount{ID: account, Spent: money.MustParse("30"), Reserved: money.MustParse("5")},
				Limit:         &limit,
			}}, nil
		}
		return nil, errors.New("database down")
	}
	b := inspectBudgets{state: state}
	got, err := b.Remaining(context.Background(), []ids.UUID{denied, gone, readable})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[account] != "65" {
		t.Errorf("remaining = %v, want only %s: 65", got, account)
	}
	if _, err := b.Remaining(context.Background(), []ids.UUID{ids.NewV7()}); err == nil {
		t.Error("another error was swallowed")
	}
}
