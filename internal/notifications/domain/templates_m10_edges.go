// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m10EdgesTemplates are the SIEM export and Shared Signals notification
// types (G0 M10 D7, D36, D37, D38). They render ids, codes and counts,
// never a destination URL, an event's content or a person's name, which
// come from outside PantherClaw (HR-158).
var m10EdgesTemplates = []Template{
	{
		Type: "siem.delivery_failing", Severity: Critical, Params: []string{"destination", "code", "failures", "since", "seq"},
		Title: "SIEM export is failing",
		Body: "The export destination {destination} has failed {failures} times in a row since {since} (last answer: {code}). " +
			"Export is held at feed sequence {seq}: no event is skipped, and delivery resumes from there once the destination " +
			"answers. Check the receiver, then retry it.",
		Link: "/integrations/destinations/{destination}/confirm",
	},
	{
		Type: "signals.event_received", Severity: Warning, Params: []string{"transmitter", "event", "user", "basis", "case"},
		Title: "Your identity provider reported a security event",
		Body: "The Shared Signals transmitter {transmitter} sent a {event} event about person {user} (matched by {basis}). " +
			"Case {case} lists their grants and waiting approvals for review.",
		Link: "/integrations/transmitters/{transmitter}/confirm",
	},
	{
		Type: "signals.playbook_changed", Severity: Warning, Params: []string{"change", "request"},
		Title: "The identity playbook changed",
		Body: "The identity playbook change {request} ({change}) took effect after its confirmations.",
		Link: "/integrations/playbook/{request}/confirm",
	},
}

func init() { templates = append(templates, m10EdgesTemplates...) }
