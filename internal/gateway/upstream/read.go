// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package upstream

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
)

// ReadParams is the canonical form of a resources/read, independent of the
// protocol version and the JSON-RPC id: what BeginDispatch records for a
// resource read (G0 M15 D31).
func ReadParams(uri string) ([]byte, error) {
	b, err := json.Marshal(map[string]any{"uri": uri}, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	v := jsontext.Value(b)
	if err := v.Canonicalize(); err != nil {
		return nil, err
	}
	return v, nil
}

// ReadResource sends resources/read for uri, which the gateway built from
// a reviewed template (HR-419). The result is the ReadResourceResult as
// the server sent it, at most egress.MaxResponse bytes. An error wrapping
// ErrNotSent means the request never left the gateway.
func (c *Client) ReadResource(ctx context.Context, uri string, decorate Decorate) (Result, error) {
	ex, err := c.do(ctx, "resources/read", uri, map[string]any{"uri": uri}, nil, decorate)
	if err != nil {
		return Result{}, err
	}
	out := ex.result()
	if len(out.Result) > egress.MaxResponse {
		return Result{}, fmt.Errorf("%w: a resource larger than %d bytes", ErrProtocol, egress.MaxResponse)
	}
	if out.Error == nil && len(out.Result) > 0 {
		var r struct {
			Contents []jsontext.Value `json:"contents"`
		}
		if json.Unmarshal(out.Result, &r) != nil || r.Contents == nil {
			return Result{}, fmt.Errorf("%w: resources/read answered no contents", ErrProtocol)
		}
	}
	return out, nil
}
