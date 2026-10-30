// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// idpTemplates tell every org admin about a change to the organization's
// own identity providers (G0 M18 D155, D162; HR-481): when it is filed and
// when a second person applies it. Like every template they carry ids,
// codes and fixed text only (HR-158); the provider's name and issuer stay
// on the change's page. stranded lists the active admins who would lose
// their last sign-in provider, or "none".
var idpTemplates = []Template{
	{
		Type: "identity_provider.change_requested", Severity: Warning, Params: []string{"request", "change", "user", "stranded"},
		Title: "A change to your organization's identity providers waits for a second person",
		Body: "{user} asked to change how people sign in to your organization ({change}). It applies only after a " +
			"different org admin confirms it with a security key on its page. Admins who would lose their last " +
			"sign-in provider: {stranded}. If you did not expect this change, decline it.",
		Link: "/changes/{request}",
	},
	{
		Type: "identity_provider.change_applied", Severity: Warning, Params: []string{"change", "user", "publisher"},
		Title: "Your organization's identity providers changed",
		Body: "The change ({change}) asked by {user} was confirmed by {publisher} and now applies to sign-in. " +
			"Every change to identity providers is in the audit log.",
	},
}

func init() { templates = append(templates, idpTemplates...) }
