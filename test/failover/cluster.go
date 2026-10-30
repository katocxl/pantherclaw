// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package failover drives the compose profile `failover` for the local
// failover tests (G0 M19 D202, D213; `task failover`): a primary on
// 127.0.0.1:5434, its synchronous standby on 5435, and a standby of the
// standby that becomes the new primary's synchronous standby once the
// standby is promoted. The tests kill the primary and promote the standby
// with the docker CLI, with fixed arguments.
package failover

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Ports of the primary and the standby on the loopback address.
const (
	PrimaryPort = 5434
	StandbyPort = 5435
)

// Project is the compose project the tests use, so they never touch the
// development stack's containers.
const Project = "pc-failover"

// Variant selects how the pair replicates.
type Variant int

// Variants.
const (
	// Sync: the primary waits for the standby (remote_apply), and the
	// standby, once promoted, waits for its own standby: verified at both
	// ends.
	Sync Variant = iota
	// Async: the primary waits for no standby.
	Async
	// SyncToUnverified: the primary waits for the standby, but the
	// standby, once promoted, waits for none.
	SyncToUnverified
)

// Cluster is the running failover profile.
type Cluster struct {
	root     string // the repository root
	password string
}

// FromEnv returns the cluster of the repository at root, with the
// superuser password the profile uses (PC_PG_TEST_PASSWORD).
func FromEnv(root string) (*Cluster, error) {
	pw := os.Getenv("PC_PG_TEST_PASSWORD")
	if pw == "" {
		return nil, fmt.Errorf("failover: PC_PG_TEST_PASSWORD is not set (task failover loads deploy/compose/.env)")
	}
	return &Cluster{root: root, password: pw}, nil
}

// AdminURL is the superuser URL of the server on port.
func (c *Cluster) AdminURL(port int) string {
	return fmt.Sprintf("postgres://postgres:%s@127.0.0.1:%d/postgres?sslmode=disable", c.password, port)
}

func (c *Cluster) run(ctx context.Context, env []string, args ...string) error {
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // G204: fixed arguments
	cmd.Dir = c.root
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker %v: %w\n%s", args, err, out.String())
	}
	return nil
}

func (c *Cluster) compose(ctx context.Context, env []string, args ...string) error {
	base := []string{"compose", "-f", filepath.Join("deploy", "compose", "compose.yaml"), "-p", Project, "--profile", "failover"}
	return c.run(ctx, env, append(base, args...)...)
}

// Start creates the three servers afresh for v and waits until each is
// healthy and the primary's standby streams.
func (c *Cluster) Start(ctx context.Context, v Variant) error {
	var env []string
	if v == SyncToUnverified {
		env = append(env, "PC_FAILOVER_STANDBY_SYNC=")
	}
	_ = c.compose(ctx, env, "down", "--timeout", "1")
	if err := c.compose(ctx, env, "up", "-d", "--wait", "--force-recreate"); err != nil {
		return err
	}
	if v == Async {
		return c.psql(ctx, "pg-primary", "ALTER SYSTEM SET synchronous_standby_names = ''", "SELECT pg_reload_conf()")
	}
	return nil
}

// Stop removes the servers.
func (c *Cluster) Stop(ctx context.Context) error {
	return c.compose(ctx, nil, "down", "--timeout", "1")
}

// KillPrimary kills the primary, as a crash would.
func (c *Cluster) KillPrimary(ctx context.Context) error {
	return c.run(ctx, nil, "kill", Project+"-pg-primary-1")
}

// Promote promotes the standby and waits until it is the primary.
func (c *Cluster) Promote(ctx context.Context) error {
	return c.psql(ctx, "pg-standby", "SELECT pg_promote(true, 30)")
}

func (c *Cluster) psql(ctx context.Context, service string, statements ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	args := []string{"exec", Project + "-" + service + "-1", "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q"}
	for _, s := range statements {
		args = append(args, "-c", s)
	}
	return c.run(ctx, nil, args...)
}
