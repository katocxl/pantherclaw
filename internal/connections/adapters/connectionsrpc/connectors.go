// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectionsrpc

import (
	"encoding/json/v2"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// specIn is a connector spec as the use cases take it; nil when absent.
func specIn(s *pb.ConnectorSpec) (*capp.ConnectorSpec, error) {
	if s == nil {
		return nil, nil
	}
	out := &capp.ConnectorSpec{
		Image: s.GetImage(), Command: s.GetCommand(), Environment: s.GetEnvironment(), CredentialPlaceholders: s.GetCredentialPlaceholders(),
		MemoryMiB: s.GetLimits().GetMemoryMib(), MilliCPUs: s.GetLimits().GetMilliCpus(), PIDs: s.GetLimits().GetPids(),
	}
	if e := s.GetEgressConnectionId(); e != "" {
		id, err := ids.ParseUUID(e)
		if err != nil {
			return nil, capp.ErrConnector
		}
		out.EgressConnection = &id
	}
	return out, nil
}

// connectorOf is a stored connector spec on the wire; nil when absent.
func connectorOf(s *dbq.PcConnectorSpec) *pb.ConnectorSpec {
	if s == nil {
		return nil
	}
	out := &pb.ConnectorSpec{
		Image: s.Image, Command: s.Command, CredentialPlaceholders: s.CredentialPlaceholders, Revision: s.Revision,
		Limits: &pb.ConnectorLimits{MemoryMib: s.MemoryMib, MilliCpus: s.MilliCpus, Pids: s.Pids},
	}
	_ = json.Unmarshal(s.Environment, &out.Environment)
	if s.EgressConnectionID != nil {
		out.EgressConnectionId = s.EgressConnectionID.String()
	}
	return out
}
