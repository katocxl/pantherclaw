// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"

	"github.com/katocxl/pantherclaw/internal/extension"
)

// errDeploymentConfig prefixes every start-up refusal of the deployment
// settings (error code DEPLOYMENT_CONFIG, ADR-0031).
const errDeploymentConfig = "DEPLOYMENT_CONFIG: "

// deployment returns the configured deployment (validated by Validate).
func (c *Config) deployment() extension.Deployment { return extension.Deployment(c.Deployment) }

func (c *Config) validateDeployment() []error {
	if !c.deployment().Valid() {
		return []error{errors.New(errDeploymentConfig + "deployment must be development, staging or production")}
	}
	return nil
}
