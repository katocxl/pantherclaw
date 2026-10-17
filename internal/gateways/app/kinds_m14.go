// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/connections/ports"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// WithKindConfigs sets the stores the gateway configuration loads the M14
// kinds' configurations from (G0 M14 D64).
func (s *Service) WithKindConfigs(k *ports.KindConfigs) *Service {
	s.kinds = k
	return s
}

// kindConfigs loads each served connection's M14 configuration, by
// connection id. A kind without a registered store loads nothing: its
// connections reach the gateway without one and are refused there.
func (s *Service) kindConfigs(ctx context.Context, tx db.TenantTx, org ids.OrgID, conns []dbq.PcConnection) (map[ids.UUID]proto.Message, error) {
	out := map[ids.UUID]proto.Message{}
	for _, c := range conns {
		store, ok := s.kinds.Get(c.Kind)
		if !ok {
			continue
		}
		m, err := store.Load(ctx, tx, org, c.ID)
		if err != nil {
			return nil, err
		}
		out[c.ID] = m
	}
	return out, nil
}
