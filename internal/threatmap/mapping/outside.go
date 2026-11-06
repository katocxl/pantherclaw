// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import "slices"

// OutsideReason says why a technique is outside PantherClaw (G0 M28 D714).
type OutsideReason string

// Outside reasons (closed).
const (
	OutsideEndpoint            OutsideReason = "ENDPOINT"
	OutsideNetwork             OutsideReason = "NETWORK"
	OutsideEmail               OutsideReason = "EMAIL"
	OutsidePhysical            OutsideReason = "PHYSICAL"
	OutsideHuman               OutsideReason = "HUMAN"
	OutsidePreCompromise       OutsideReason = "PRE_COMPROMISE"
	OutsideCloudInfrastructure OutsideReason = "CLOUD_INFRASTRUCTURE"
	OutsideIdentityProvider    OutsideReason = "IDENTITY_PROVIDER"
	OutsideModelDevelopment    OutsideReason = "MODEL_DEVELOPMENT"
)

// OutsideReasons lists every OutsideReason.
func OutsideReasons() []OutsideReason {
	return []OutsideReason{
		OutsideEndpoint, OutsideNetwork, OutsideEmail, OutsidePhysical, OutsideHuman,
		OutsidePreCompromise, OutsideCloudInfrastructure, OutsideIdentityProvider, OutsideModelDevelopment,
	}
}

// Valid reports whether r is a listed OutsideReason.
func (r OutsideReason) Valid() bool { return slices.Contains(OutsideReasons(), r) }

// ToolKind is the kind of tool that covers a technique outside PantherClaw
// (D714), shown "Outside PantherClaw: covered by <tool kind>".
type ToolKind string

// Tool kinds (closed).
const (
	ToolEDR                ToolKind = "EDR"
	ToolNetworkSecurity    ToolKind = "NETWORK_SECURITY"
	ToolEmailSecurity      ToolKind = "EMAIL_SECURITY"
	ToolPhysicalSecurity   ToolKind = "PHYSICAL_SECURITY"
	ToolSecurityAwareness  ToolKind = "SECURITY_AWARENESS"
	ToolThreatIntelligence ToolKind = "THREAT_INTELLIGENCE"
	ToolCloudSecurity      ToolKind = "CLOUD_SECURITY"
	ToolIdentityProvider   ToolKind = "IDENTITY_PROVIDER"
	ToolModelSecurity      ToolKind = "MODEL_SECURITY"
)

// ToolKinds lists every ToolKind.
func ToolKinds() []ToolKind {
	return []ToolKind{
		ToolEDR, ToolNetworkSecurity, ToolEmailSecurity, ToolPhysicalSecurity, ToolSecurityAwareness,
		ToolThreatIntelligence, ToolCloudSecurity, ToolIdentityProvider, ToolModelSecurity,
	}
}

// Valid reports whether k is a listed ToolKind.
func (k ToolKind) Valid() bool { return slices.Contains(ToolKinds(), k) }

// OutsideEntry marks a technique outside PantherClaw. An entry on a
// technique covers its sub-techniques; one on a sub-technique covers only
// it (D712).
type OutsideEntry struct {
	ID        string        `json:"id"`
	Reason    OutsideReason `json:"reason"`
	CoveredBy ToolKind      `json:"covered_by"`
	// Note is an optional single line.
	Note string `json:"note,omitzero"`
}

// Outside is every technique outside PantherClaw (D714).
var Outside = []OutsideEntry{
	{ID: "AML.T0000", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0001", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0002", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0003", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0004", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0006", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0008", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0016", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0017", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0021", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0060", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0064", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0065", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0066", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0079", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0087", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0088", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0095", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0102", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0115", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0116", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0117", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0124", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0128", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0139", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0140", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0141", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "AML.T0111", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence, Note: "Inflated stars and downloads live on public registries; the MCP catalog approves by exact match, not by reputation."},
	{ID: "AML.T0005", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0007", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0013", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0014", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0015", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0018", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0020", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0031", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0035", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0040", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0042", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0043", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0044", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0046", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0047", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0059", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0062", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0063", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0076", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0135", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0137", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0144", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0145", Reason: OutsideModelDevelopment, CoveredBy: ToolModelSecurity},
	{ID: "AML.T0011", Reason: OutsideHuman, CoveredBy: ToolSecurityAwareness},
	{ID: "AML.T0012", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "AML.T0125", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "AML.T0041", Reason: OutsidePhysical, CoveredBy: ToolPhysicalSecurity},
	{ID: "AML.T0052", Reason: OutsideEmail, CoveredBy: ToolEmailSecurity},
	{ID: "AML.T0049", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "AML.T0122", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "AML.T0037", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0074", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0078", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0089", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0090", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0097", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0106", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0107", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0112", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0113", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0114", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0120", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0123", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0127", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0142", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "AML.T0132", Reason: OutsideCloudInfrastructure, CoveredBy: ToolCloudSecurity},
	{ID: "T1583", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1584", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1585", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1586", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1587", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1588", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1589", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1590", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1591", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1592", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1593", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1594", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1595", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1596", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1597", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1608", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1650", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1681", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1682", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1683", Reason: OutsidePreCompromise, CoveredBy: ToolThreatIntelligence},
	{ID: "T1114", Reason: OutsideEmail, CoveredBy: ToolEmailSecurity},
	{ID: "T1534", Reason: OutsideEmail, CoveredBy: ToolEmailSecurity},
	{ID: "T1566", Reason: OutsideEmail, CoveredBy: ToolEmailSecurity},
	{ID: "T1598", Reason: OutsideEmail, CoveredBy: ToolEmailSecurity},
	{ID: "T1667", Reason: OutsideEmail, CoveredBy: ToolEmailSecurity},
	{ID: "T1025", Reason: OutsidePhysical, CoveredBy: ToolPhysicalSecurity},
	{ID: "T1052", Reason: OutsidePhysical, CoveredBy: ToolPhysicalSecurity},
	{ID: "T1091", Reason: OutsidePhysical, CoveredBy: ToolPhysicalSecurity},
	{ID: "T1092", Reason: OutsidePhysical, CoveredBy: ToolPhysicalSecurity},
	{ID: "T1200", Reason: OutsidePhysical, CoveredBy: ToolPhysicalSecurity},
	{ID: "T1204", Reason: OutsideHuman, CoveredBy: ToolSecurityAwareness},
	{ID: "T1684", Reason: OutsideHuman, CoveredBy: ToolSecurityAwareness},
	{ID: "T1069", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1087", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1110", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1111", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1136", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1201", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1207", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1482", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1484", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1531", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1556", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1558", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1615", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1621", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1649", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1697", Reason: OutsideIdentityProvider, CoveredBy: ToolIdentityProvider},
	{ID: "T1525", Reason: OutsideCloudInfrastructure, CoveredBy: ToolCloudSecurity},
	{ID: "T1526", Reason: OutsideCloudInfrastructure, CoveredBy: ToolCloudSecurity},
	{ID: "T1535", Reason: OutsideCloudInfrastructure, CoveredBy: ToolCloudSecurity},
	{ID: "T1538", Reason: OutsideCloudInfrastructure, CoveredBy: ToolCloudSecurity},
	{ID: "T1578", Reason: OutsideCloudInfrastructure, CoveredBy: ToolCloudSecurity},
	{ID: "T1580", Reason: OutsideCloudInfrastructure, CoveredBy: ToolCloudSecurity},
	{ID: "T1619", Reason: OutsideCloudInfrastructure, CoveredBy: ToolCloudSecurity},
	{ID: "T1648", Reason: OutsideCloudInfrastructure, CoveredBy: ToolCloudSecurity},
	{ID: "T1666", Reason: OutsideCloudInfrastructure, CoveredBy: ToolCloudSecurity},
	{ID: "T1671", Reason: OutsideCloudInfrastructure, CoveredBy: ToolCloudSecurity},
	{ID: "T1673", Reason: OutsideCloudInfrastructure, CoveredBy: ToolCloudSecurity},
	{ID: "T1675", Reason: OutsideCloudInfrastructure, CoveredBy: ToolCloudSecurity},
	{ID: "T1001", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1008", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1011", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1016", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1018", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1029", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1030", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1040", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1046", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1049", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1102", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1104", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1132", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1133", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1135", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1187", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1190", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1205", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1210", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1498", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1557", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1568", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1571", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1573", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1599", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1600", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1601", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1602", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1659", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1665", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1669", Reason: OutsideNetwork, CoveredBy: ToolNetworkSecurity},
	{ID: "T1003", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1005", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1006", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1007", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1010", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1012", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1014", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1021", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1033", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1036", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1037", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1039", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1047", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1053", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1055", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1056", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1057", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1068", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1072", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1074", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1082", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1083", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1106", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1112", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1113", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1115", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1120", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1123", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1124", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1125", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1127", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1129", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1134", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1137", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1140", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1176", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1185", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1189", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1197", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1202", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1203", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1211", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1212", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1216", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1217", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1218", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1219", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1220", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1221", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1222", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1480", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1486", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1489", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1490", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1491", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1495", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1497", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1505", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1518", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1529", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1539", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1542", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1543", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1546", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1547", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1553", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1554", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1555", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1559", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1560", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1561", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1563", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1564", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1569", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1570", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1574", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1612", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1614", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1620", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1622", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1647", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1652", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1653", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1654", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1668", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1674", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1678", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1679", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1680", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1686", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1687", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1688", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1689", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
	{ID: "T1690", Reason: OutsideEndpoint, CoveredBy: ToolEDR},
}
