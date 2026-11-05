// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// bundleTemplates are the publisher bundle notification types (G0 M37
// D1083, FQ37-3; HR-799). They render only names, versions and fixed text.
var bundleTemplates = []Template{
	{
		Type: "bundle.revoked", Severity: Critical, Params: []string{"publisher", "bundle", "version", "source"},
		Title: "A publisher bundle was revoked",
		Body: "The bundle {bundle} {version} of the publisher {publisher} was revoked ({source}). Its package versions are " +
			"withdrawn, its detection rules disabled and its automations paused. Installing a later version that is not " +
			"revoked resumes it.",
		Link: "/integrations/bundles",
	},
}

func init() { templates = append(templates, bundleTemplates...) }
