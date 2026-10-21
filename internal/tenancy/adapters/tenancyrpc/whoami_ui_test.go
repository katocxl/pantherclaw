// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package tenancyrpc

import (
	"testing"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// TestHR346_WhoAmIReportsDeployment: WhoAmI reports every deployment, so a
// console can show development and staging.
func TestHR346_WhoAmIReportsDeployment(t *testing.T) {
	for in, want := range map[string]pantherclawv1.Deployment{
		"development": pantherclawv1.Deployment_DEPLOYMENT_DEVELOPMENT,
		"staging":     pantherclawv1.Deployment_DEPLOYMENT_STAGING,
		"production":  pantherclawv1.Deployment_DEPLOYMENT_PRODUCTION,
		"":            pantherclawv1.Deployment_DEPLOYMENT_UNSPECIFIED,
		"prod":        pantherclawv1.Deployment_DEPLOYMENT_UNSPECIFIED,
	} {
		if got := NewAccess(nil).WithDeployment(in).deployment; got != want {
			t.Errorf("WithDeployment(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSessionKindOf(t *testing.T) {
	for in, want := range map[app.Credential]pantherclawv1.CallerSessionKind{
		app.CredAccessToken:    pantherclawv1.CallerSessionKind_CALLER_SESSION_KIND_BEARER,
		app.CredAPIKey:         pantherclawv1.CallerSessionKind_CALLER_SESSION_KIND_BEARER,
		app.CredBrowserSession: pantherclawv1.CallerSessionKind_CALLER_SESSION_KIND_ORG_BROWSER,
		"":                     pantherclawv1.CallerSessionKind_CALLER_SESSION_KIND_UNSPECIFIED,
	} {
		if got := sessionKindOf(in); got != want {
			t.Errorf("sessionKindOf(%q) = %v, want %v", in, got, want)
		}
	}
}
