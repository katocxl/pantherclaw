// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// edgesProcedures are SIEMService's and SharedSignalsService's procedures
// (G0 M10 D4, D35, D37): changes need siem.manage or signals.manage (both
// human only, checked again by the use cases with the Business edition);
// reads need siem.read or signals.read.
var edgesProcedures = map[string]td.Permission{
	pantherclawv1connect.SIEMServiceCreateSIEMDestinationProcedure:       td.PermSIEMManage,
	pantherclawv1connect.SIEMServiceGetSIEMDestinationProcedure:          td.PermSIEMRead,
	pantherclawv1connect.SIEMServiceListSIEMDestinationsProcedure:        td.PermSIEMRead,
	pantherclawv1connect.SIEMServiceSetSIEMDestinationStateProcedure:     td.PermSIEMManage,
	pantherclawv1connect.SIEMServiceRotateSIEMDestinationSecretProcedure: td.PermSIEMManage,
	pantherclawv1connect.SIEMServiceRetrySIEMDestinationProcedure:        td.PermSIEMManage,
	pantherclawv1connect.SIEMServiceListSIEMBatchesProcedure:             td.PermSIEMRead,

	pantherclawv1connect.SharedSignalsServiceCreateSSFTransmitterProcedure:   td.PermSignalsManage,
	pantherclawv1connect.SharedSignalsServiceGetSSFTransmitterProcedure:      td.PermSignalsRead,
	pantherclawv1connect.SharedSignalsServiceListSSFTransmittersProcedure:    td.PermSignalsRead,
	pantherclawv1connect.SharedSignalsServiceSetSSFTransmitterStateProcedure: td.PermSignalsManage,
	pantherclawv1connect.SharedSignalsServiceListSSFEventsProcedure:          td.PermSignalsRead,
}

func init() { maps.Copy(procedurePermissions, edgesProcedures) }

// playbookProcedures are the identity playbook's procedures (D38): asking
// for or declining a change needs signals.manage (a person, checked by the
// use case); confirming happens only on the page.
var playbookProcedures = map[string]td.Permission{
	pantherclawv1connect.SharedSignalsServiceGetIdentityPlaybookProcedure:            td.PermSignalsRead,
	pantherclawv1connect.SharedSignalsServiceRequestIdentityPlaybookChangeProcedure:  td.PermSignalsManage,
	pantherclawv1connect.SharedSignalsServiceListIdentityPlaybookRequestsProcedure:   td.PermSignalsRead,
	pantherclawv1connect.SharedSignalsServiceDeclineIdentityPlaybookRequestProcedure: td.PermSignalsManage,
}

func init() { maps.Copy(procedurePermissions, playbookProcedures) }
