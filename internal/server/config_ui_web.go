// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/extension"
)

// errDeploymentConfig prefixes every start-up refusal of the deployment
// settings (error code DEPLOYMENT_CONFIG, ADR-0031).
const errDeploymentConfig = "DEPLOYMENT_CONFIG: "

// deployment returns the configured deployment (validated by Validate); an
// unset one is development.
func (c *Config) deployment() extension.Deployment {
	if c.Deployment == "" {
		return extension.DeploymentDevelopment
	}
	return extension.Deployment(c.Deployment)
}

func (c *Config) validateDeployment() []error {
	if !c.deployment().Valid() {
		return []error{errors.New(errDeploymentConfig + "deployment must be development, staging or production")}
	}
	var errs []error
	if c.deployment() == extension.DeploymentProduction {
		// A development identity provider signs anyone in (HR-346).
		for i, p := range c.Auth.OIDCProviders {
			if p.Dev {
				errs = append(errs, fmt.Errorf("%sauth.oidc_providers[%d] (%q) is a development provider (dev: true), "+
					"which a production deployment refuses", errDeploymentConfig, i, p.Name))
			}
		}
	}
	return errs
}

// checkDeploymentFor refuses to serve a build with an extension unless
// `deployment` was set explicitly: a hosted production config that forgot
// it must not run as development (HR-346, D48).
func (c *Config) checkDeploymentFor(ext extension.Set) error {
	if ext.Present() && c.Deployment == "" {
		return errors.New(errDeploymentConfig + "a build with an extension needs an explicit deployment " +
			"(development, staging or production)")
	}
	return nil
}
