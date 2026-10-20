// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/extension"
)

func uiWebConfig() Config {
	c := DefaultConfig()
	c.DB.AppPasswordFile = "pw"
	c.KEKFiles = []string{"kek"}
	return c
}

// TestHR346_DeploymentConfig: an unset deployment is development and
// only development, staging or production are accepted; anything else
// stops start-up with DEPLOYMENT_CONFIG. A build with an extension needs
// it set explicitly.
func TestHR346_DeploymentConfig(t *testing.T) {
	c := uiWebConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("default configuration refused: %v", err)
	}
	if c.deployment() != extension.DeploymentDevelopment {
		t.Fatalf("default deployment = %q", c.deployment())
	}
	if err := c.checkDeploymentFor(extension.Set{}); err != nil {
		t.Fatalf("public build without deployment: %v", err)
	}
	present := extension.Set{Mount: func(extension.Deps) ([]extension.Route, error) { return nil, nil }}
	if err := c.checkDeploymentFor(present); err == nil || !strings.HasPrefix(err.Error(), "DEPLOYMENT_CONFIG: ") {
		t.Fatalf("extension build without deployment: err = %v", err)
	}
	for _, d := range []string{"development", "staging", "production"} {
		c := uiWebConfig()
		c.Deployment = d
		if err := c.Validate(); err != nil {
			t.Errorf("deployment %q refused: %v", d, err)
		}
		if err := c.checkDeploymentFor(present); err != nil {
			t.Errorf("extension build with deployment %q: %v", d, err)
		}
	}
	for _, d := range []string{"prod", "Production", "dev", "test", " production"} {
		c := uiWebConfig()
		c.Deployment = d
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "DEPLOYMENT_CONFIG") {
			t.Errorf("deployment %q: err = %v, want DEPLOYMENT_CONFIG", d, err)
		}
	}
}

// TestHR346_ExtensionValidateStopsStartup: an extension's Validate error
// is a DEPLOYMENT_CONFIG start-up error, and it sees the deployment.
func TestHR346_ExtensionValidateStopsStartup(t *testing.T) {
	c := uiWebConfig()
	c.Deployment = "production"
	d := extensionDeps(&c, nil)
	if d.Deployment != extension.DeploymentProduction || d.PublicURL != c.Auth.PublicURL || d.Clock == nil {
		t.Fatalf("deps = %+v", d)
	}
	if d.Plans != nil || d.Accounts != nil || d.BillingLinks != nil {
		t.Fatal("plans, accounts and billing links are not provided yet")
	}
	if err := validateExtension(extension.Set{}, d); err != nil {
		t.Fatal(err)
	}
	refuse := extension.Set{Validate: func(d extension.Deps) error {
		if d.Deployment == extension.DeploymentProduction {
			return errors.New("fake billing in production")
		}
		return nil
	}}
	err := validateExtension(refuse, d)
	if err == nil || !strings.HasPrefix(err.Error(), "DEPLOYMENT_CONFIG: ") {
		t.Fatalf("err = %v", err)
	}
}

// TestHR346_RunWith: RunWith validates the configuration first, then
// requires an explicit deployment, then runs the extension's Validate, all
// before it touches the database (the password file does not exist).
func TestHR346_RunWith(t *testing.T) {
	var calls []extension.Deployment
	ext := extension.Set{Validate: func(d extension.Deps) error {
		calls = append(calls, d.Deployment)
		if d.Deployment == extension.DeploymentProduction {
			return errors.New("fake billing in production")
		}
		return nil
	}}
	run := func(mutate func(*Config)) error {
		c := uiWebConfig()
		c.DB.AppPasswordFile = t.TempDir() + "/missing"
		mutate(&c)
		return RunWith(context.Background(), &c, ext)
	}
	// An invalid configuration stops before the extension is asked.
	if err := run(func(c *Config) { c.Deployment = "prod" }); err == nil || len(calls) != 0 {
		t.Fatalf("invalid config: err = %v, calls = %v", err, calls)
	}
	if err := run(func(c *Config) { c.Role = "nope" }); err == nil || len(calls) != 0 {
		t.Fatalf("invalid role: err = %v, calls = %v", err, calls)
	}
	// No explicit deployment: refused before the extension is asked.
	if err := run(func(*Config) {}); err == nil || !strings.Contains(err.Error(), "explicit deployment") || len(calls) != 0 {
		t.Fatalf("no deployment: err = %v, calls = %v", err, calls)
	}
	// The extension refuses production.
	err := run(func(c *Config) { c.Deployment = "production" })
	if err == nil || !strings.HasPrefix(err.Error(), "DEPLOYMENT_CONFIG: extension: ") || len(calls) != 1 {
		t.Fatalf("production: err = %v, calls = %v", err, calls)
	}
	// Accepted: start-up goes on and fails only at the database password.
	err = run(func(c *Config) { c.Deployment = "staging" })
	if err == nil || strings.Contains(err.Error(), "DEPLOYMENT_CONFIG") || len(calls) != 2 || calls[1] != extension.DeploymentStaging {
		t.Fatalf("staging: err = %v, calls = %v", err, calls)
	}
}
