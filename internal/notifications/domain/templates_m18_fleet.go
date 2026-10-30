// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m18FleetTemplates are the gateway fleet notification types (G0 M18 D151,
// HR-470, HR-471). They render ids, times and parsed versions only, never
// the version text a gateway reported (HR-158): an unparseable one shows as
// "unknown".
var m18FleetTemplates = []Template{
	{
		Type: "gateway.silent", Severity: Critical, Params: []string{"gateway", "since", "threshold"},
		Title: "A gateway stopped reporting",
		Body: "Gateway {gateway} has sent no status report since {since}, longer than the fleet's silence threshold of " +
			"{threshold} seconds. Its connections may not be served. Check the gateway's host and its network path to PantherClaw.",
		Link: "/gateways",
	},
	{
		Type: "gateway.recovered", Severity: Info, Params: []string{"gateway", "since"},
		Title: "A silent gateway is reporting again",
		Body:  "Gateway {gateway}, silent since {since}, sent a status report again.",
		Link:  "/gateways",
	},
	{
		Type: "gateway.below_minimum", Severity: Warning, Params: []string{"gateway", "version", "minimum"},
		Title: "A gateway runs below the fleet's minimum version",
		Body: "Gateway {gateway} reports version {version}, below the fleet's minimum {minimum}. The minimum is advisory: " +
			"the gateway keeps serving. Upgrade it.",
		Link: "/gateways",
	},
}

func init() { templates = append(templates, m18FleetTemplates...) }
