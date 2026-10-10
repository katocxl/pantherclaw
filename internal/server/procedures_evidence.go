// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// evidenceProcedures are EvidenceService's procedures (G0 M7 track B). The
// use cases check scopes: a transaction bundle where each transaction's
// agent lives, a range bundle at org scope with audit.read.
var evidenceProcedures = map[string]td.Permission{
	pantherclawv1connect.EvidenceServiceListCheckpointsProcedure:     td.PermEvidenceRead,
	pantherclawv1connect.EvidenceServiceGetCheckpointProcedure:       td.PermEvidenceRead,
	pantherclawv1connect.EvidenceServiceGetInclusionProofProcedure:   td.PermEvidenceRead,
	pantherclawv1connect.EvidenceServiceGetConsistencyProofProcedure: td.PermEvidenceRead,
	pantherclawv1connect.EvidenceServiceExportBundleProcedure:        td.PermEvidenceRead,
}

func init() { maps.Copy(procedurePermissions, evidenceProcedures) }
