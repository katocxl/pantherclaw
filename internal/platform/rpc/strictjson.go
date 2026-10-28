// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpc

import (
	"bytes"
	"context"
	"errors"
	"io"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectproto"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// errUnknownField names no field and echoes nothing from the request.
var errUnknownField = errors.New("the request has a field this server does not know")

// strictJSON is the JSON codec (application/json and application/connect+json)
// with unknown fields refused (HR-100). Binary protobuf keeps ignoring them,
// so binary clients stay forward compatible; JSON clients need a server at
// least as new as they are.
type strictJSON struct {
	*connectproto.JSONCodec
	lenient protojson.UnmarshalOptions
}

func newStrictJSON() strictJSON {
	c := connectproto.NewJSONCodec()
	lenient := c.UnmarshalOptions
	c.UnmarshalOptions.DiscardUnknown = false
	return strictJSON{JSONCodec: c, lenient: lenient}
}

// UnmarshalRead refuses unknown fields with a fixed error; any other
// decoding error is reported as before.
func (c strictJSON) UnmarshalRead(ctx context.Context, src io.Reader, msg any) error {
	data, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	err = c.JSONCodec.UnmarshalRead(ctx, bytes.NewReader(data), msg)
	if err == nil {
		return nil
	}
	if m, ok := msg.(proto.Message); ok {
		// Only an unknown field separates the strict and lenient parses.
		probe := m.ProtoReflect().New().Interface()
		if c.lenient.Unmarshal(data, probe) == nil {
			return errUnknownField
		}
	}
	return err
}

var _ connect.StableCodec = strictJSON{}
