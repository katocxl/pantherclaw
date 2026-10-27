// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package tenancyrpc

import (
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// deploymentToProto maps config `deployment` to the WhoAmI field.
var deploymentToProto = map[string]pantherclawv1.Deployment{
	"development": pantherclawv1.Deployment_DEPLOYMENT_DEVELOPMENT,
	"staging":     pantherclawv1.Deployment_DEPLOYMENT_STAGING,
	"production":  pantherclawv1.Deployment_DEPLOYMENT_PRODUCTION,
}

// WithDeployment sets the deployment WhoAmI reports (development, staging
// or production; anything else reports UNSPECIFIED). It returns s.
func (s *Access) WithDeployment(d string) *Access {
	s.deployment = deploymentToProto[d]
	return s
}

// sessionKindOf is how the caller is signed in. Account browser sessions
// arrive with hosted accounts (G0 UI D8).
func sessionKindOf(c app.Credential) pantherclawv1.CallerSessionKind {
	switch c {
	case app.CredBrowserSession:
		return pantherclawv1.CallerSessionKind_CALLER_SESSION_KIND_ORG_BROWSER
	case app.CredSupportSession:
		// Display only: a support session is a browser organization session
		// (G0 M13 D38). Its read-only limits come from its support roles.
		return pantherclawv1.CallerSessionKind_CALLER_SESSION_KIND_ORG_BROWSER
	case app.CredAccessToken, app.CredAPIKey:
		return pantherclawv1.CallerSessionKind_CALLER_SESSION_KIND_BEARER
	}
	return pantherclawv1.CallerSessionKind_CALLER_SESSION_KIND_UNSPECIFIED
}
