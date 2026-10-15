// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package stepup checks the WebAuthn step-up that activates an export
// destination or a Shared Signals transmitter (G0 M10 D35, D37; HR-259,
// HR-261): a person, whose browser session stepped up with one of their
// own active security keys within the last five minutes by the database
// clock. It is the kill switch's check (response/app) for other pages.
package stepup

import (
	"context"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Within is how fresh a step-up must be.
const Within = 5 * time.Minute

// ErrStepUp reports a missing, stale or foreign step-up.
var ErrStepUp = pcerr.New(pcerr.PermissionDenied, "STEP_UP_REQUIRED",
	"verify with one of your security keys on this page first")

// StepUp is a browser session's last step-up.
type StepUp struct {
	Credential ids.UUID
	At         time.Time
}

// Check verifies that c is a person whose step-up su is fresh at now (the
// database clock) and was made with one of their own ACTIVE keys.
func Check(ctx context.Context, tx db.TenantTx, c tenancy.Caller, su StepUp, now time.Time) error {
	if !c.Human() || su.Credential.IsZero() || su.At.IsZero() || now.Sub(su.At) > Within || su.At.After(now.Add(time.Minute)) {
		return ErrStepUp
	}
	k, err := dbq.New(tx).CredentialOfUser(ctx, c.Org, su.Credential, c.Principal.ID)
	if db.IsNoRows(err) {
		return ErrStepUp
	} else if err != nil {
		return err
	}
	if k.State != "ACTIVE" {
		return ErrStepUp
	}
	return nil
}

// Is reports whether err is a step-up refusal.
func Is(err error) bool { return errors.Is(err, ErrStepUp) }
