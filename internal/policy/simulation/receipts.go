// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package simulation

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strings"
)

// notCompactJWS is the replay's error for a stored receipt that is not a
// compact JWS (replay.original).
const notCompactJWS = "replay: the decision receipt is not a compact JWS"

// receiptUnreadable reports the replay's own errors on one stored decision
// receipt that does not parse: not a compact JWS, its payload not base64,
// or its claims not JSON (D38). Only these make the decision unevaluable
// (INPUTS_UNREADABLE); every other error (the database, the pool, the
// network, the context or anything unnamed) fails the step, which River
// retries, so an outage never counts decisions as unreadable.
func receiptUnreadable(err error) bool {
	var b64 base64.CorruptInputError
	var sem *json.SemanticError
	var syn *jsontext.SyntacticError
	return errors.As(err, &b64) || errors.As(err, &sem) || errors.As(err, &syn) || strings.HasSuffix(err.Error(), notCompactJWS)
}
