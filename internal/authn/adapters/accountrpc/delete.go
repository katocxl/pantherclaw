// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package accountrpc

import (
	"context"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// AccountDeleter deletes the signed-in hosted account (G0 M13 D34,
// HR-394).
type AccountDeleter interface {
	DeleteAccount(ctx context.Context) error
}

// WithAccountDeleter serves DeleteAccount with d (hosted servers).
func (h *Handler) WithAccountDeleter(d AccountDeleter) *Handler {
	h.del = d
	return h
}

var errNoAccounts = pcerr.New(pcerr.FailedPrecondition, "ACCOUNTS_DISABLED", "this server has no hosted accounts")

// DeleteAccount implements AccountServiceHandler.
func (h *Handler) DeleteAccount(ctx context.Context, _ *pantherclawv1.DeleteAccountRequest) (*pantherclawv1.DeleteAccountResponse, error) {
	if h.del == nil {
		return nil, errNoAccounts
	}
	if err := h.del.DeleteAccount(ctx); err != nil {
		return nil, err
	}
	return &pantherclawv1.DeleteAccountResponse{}, nil
}
