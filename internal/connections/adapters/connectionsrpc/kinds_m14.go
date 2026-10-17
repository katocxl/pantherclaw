// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectionsrpc

import (
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// postgresIn is a postgres configuration from the wire; nil when absent.
func postgresIn(p *pb.PostgresConfig) *capp.PostgresConfig {
	if p == nil {
		return nil
	}
	out := &capp.PostgresConfig{
		Host: p.GetHost(), Port: p.GetPort(), Database: p.GetDatabase(), User: p.GetUser(), SSLMode: p.GetSslmode(),
		CAPEM: p.GetCaPem(), Internal: p.GetInternal(), MaxRows: p.GetMaxRows(), StatementTimeoutMs: p.GetStatementTimeoutMs(),
		MaxResultBytes: p.GetMaxResultBytes(), MinGroupSize: p.GetMinGroupSize(),
	}
	for _, t := range p.GetTables() {
		tt := capp.PostgresTable{
			Schema: t.GetSchema(), Name: t.GetName(), ScopeKey: t.GetScopeKey(), ScopeColumn: t.GetScopeColumn(), MaxRows: t.GetMaxRows(),
		}
		for _, c := range t.GetColumns() {
			tt.Columns = append(tt.Columns, capp.PostgresColumn{Name: c.GetName(), Type: c.GetType(), Class: c.GetClass()})
		}
		out.Tables = append(out.Tables, tt)
	}
	return out
}

// a2aIn is an a2a configuration from the wire; nil when absent. The card
// digest is the server's to compute, never the caller's.
func a2aIn(a *pb.A2AConfig) (*capp.A2AConfig, error) {
	if a == nil {
		return nil, nil
	}
	out := &capp.A2AConfig{
		CardURL: a.GetCardUrl(), PinnedCard: a.GetPinnedCard(), CardKeys: a.GetCardKeys(), Skills: a.GetSkills(),
		Interface:      capp.A2AInterface{Protocol: a.GetInterface().GetProtocol(), URL: a.GetInterface().GetUrl()},
		MaxAnswerBytes: a.GetMaxAnswerBytes(), MaxStreamSeconds: a.GetMaxStreamSeconds(),
	}
	if p := a.GetPeerAgentId(); p != "" {
		id, err := ids.ParseUUID(p)
		if err != nil {
			return nil, capp.ErrA2AConfig
		}
		out.PeerAgent = &id
	}
	if s := a.GetPeerScope(); s != nil {
		out.PeerScope = &capp.A2APeerScope{Bounds: s.GetBounds(), Limits: s.GetLimits()}
	}
	return out, nil
}
