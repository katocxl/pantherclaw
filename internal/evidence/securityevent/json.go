// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securityevent

import (
	"encoding/json/jsontext"
	"encoding/json/v2"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// A security event has one wire contract in the outbox, operator export
// and structured log: UUID strings. Raw ids.UUID is a byte array and would
// otherwise default to base64 under JSON v2. Keep the override local to
// this reviewed projection rather than changing unrelated JSON contracts.
type eventJSON Event

var uuidMarshalers = json.MarshalFunc(func(u ids.UUID) ([]byte, error) {
	return json.Marshal(u.String())
})

var uuidUnmarshalers = json.UnmarshalFunc(func(raw []byte, u *ids.UUID) error {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return err
	}
	parsed, err := ids.ParseUUID(text)
	if err != nil {
		return err
	}
	*u = parsed
	return nil
})

func (e Event) MarshalJSONTo(enc *jsontext.Encoder) error {
	return json.MarshalEncode(enc, eventJSON(e), json.WithMarshalers(uuidMarshalers))
}

func (e *Event) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return json.UnmarshalDecode(dec, (*eventJSON)(e), json.WithUnmarshalers(uuidUnmarshalers))
}
