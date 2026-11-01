// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

// Covers: F841

func hubKeyConfig(t *testing.T) Config {
	t.Helper()
	priv, kid, err := rootkey.Generate(rootkey.PurposeDevHub)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	b, err := json.Marshal(struct {
		Keys []jws.JWK `json:"keys"`
	}{Keys: []jws.JWK{jws.PublicJWK(pub, kid)}})
	if err != nil {
		t.Fatal(err)
	}
	c := devKeyConfig(t.TempDir())
	c.Dev.PackageKeyFile = ""
	c.Dev.HubKeyFile = filepath.Join(t.TempDir(), "hub-dev.pub.json")
	if err := os.WriteFile(c.Dev.HubKeyFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestHubDevKeyOnlyOnLoopback: the development Hub key is trusted by a server
// reachable only from this machine, and refused by every other one, by
// Validate and again where the roots are read (D101).
func TestHubDevKeyOnlyOnLoopback(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := hubKeyConfig(t)
	if err := c.Validate(); err != nil {
		t.Fatalf("development configuration refused: %v", err)
	}
	roots, err := hubRoots(context.Background(), &c, log)
	if err != nil || len(roots) != 1 {
		t.Fatalf("roots %v %v", roots, err)
	}
	for name, mutate := range map[string]func(*Config){
		"all interfaces": func(c *Config) { c.HTTP.Addr = "0.0.0.0:8080" },
		"behind a proxy": func(c *Config) { c.HTTP.PlaintextBehindProxy = true },
		"public url":     func(c *Config) { c.Auth.PublicURL = "https://pantherclaw.example.com" },
		"live keys":      func(c *Config) { c.Auth.APIKeyEnv = "live" },
	} {
		t.Run(name, func(t *testing.T) {
			c := hubKeyConfig(t)
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Error("Validate accepted it")
			}
			if _, err := hubRoots(context.Background(), &c, log); err == nil {
				t.Error("hubRoots trusted the key")
			}
		})
	}
	bad := hubKeyConfig(t)
	bad.Dev.HubKeyFile = "hub-dev.json"
	if err := bad.Validate(); err == nil {
		t.Error("a file that is not .pub.json was accepted")
	}
}
