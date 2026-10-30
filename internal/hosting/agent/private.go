// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package agent

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/katocxl/pantherclaw/internal/hosting/profile"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// ErrNotTmpfs: the private root is not on a memory file system, so a token
// written there could reach a disk (HR-502).
var ErrNotTmpfs = errors.New("hosting agent: the private root is not a tmpfs")

// Private is the host's private tmpfs root: one directory per hosted
// gateway, mounted read-only into that org's container only, holding its
// configuration and, until it enrolled, its enrollment token (HR-502).
type Private struct {
	// Root is an absolute path on a tmpfs, owned by the agent (0711).
	Root string
	// chown hands a file to the container's uid (Linux; a no-op in tests
	// and on other systems).
	chown func(path string, uid int) error
}

// NewPrivate checks that root is on a tmpfs and prepares it.
func NewPrivate(root string) (*Private, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("hosting agent: the private root must be an absolute clean path")
	}
	if err := os.MkdirAll(root, 0o711); err != nil {
		return nil, err
	}
	if err := checkTmpfs(root); err != nil {
		return nil, err
	}
	return &Private{Root: root, chown: chownTo}, nil
}

// Dir is the private directory of one hosted gateway.
func (p *Private) Dir(hosted ids.UUID) string {
	return filepath.Join(p.Root, profile.NamesOf(hosted).Container)
}

// GatewayConfig is the hosted gateway's configuration file: no secret.
type GatewayConfig struct {
	Listen  string `json:"listen"`
	Control struct {
		APIURL      string `json:"api_url"`
		CASHA256    string `json:"ca_sha256"`
		IdentityDir string `json:"identity_dir"`
	} `json:"control"`
}

// Prepare creates the hosted gateway's private directory (readable only by
// its container's uid) with its configuration.
func (p *Private) Prepare(hosted ids.UUID, apiURL, pin string) (string, error) {
	dir := p.Dir(hosted)
	if err := os.MkdirAll(dir, 0o500); err != nil {
		return "", err
	}
	uid := profile.UID(hosted)
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	var c GatewayConfig
	c.Listen = fmt.Sprintf("0.0.0.0:%d", profile.Port)
	c.Control.APIURL, c.Control.CASHA256, c.Control.IdentityDir = apiURL, pin, profile.StateDir
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	if err := writeAtomic(dir, filepath.Base(profile.ConfigFile), b, 0o400); err != nil {
		return "", err
	}
	if err := p.chown(filepath.Join(dir, filepath.Base(profile.ConfigFile)), uid); err != nil {
		return "", err
	}
	if err := p.chown(dir, uid); err != nil {
		return "", err
	}
	return dir, os.Chmod(dir, 0o500)
}

// WriteToken writes the single-use token to the hosted gateway's private
// directory, 0400 and owned by its container's uid: a file on the tmpfs,
// never a variable or a log line (HR-502).
func (p *Private) WriteToken(hosted ids.UUID, token pclog.Secret[string]) error {
	dir := p.Dir(hosted)
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	defer func() { _ = os.Chmod(dir, 0o500) }()
	name := filepath.Base(profile.TokenFile)
	if err := writeAtomic(dir, name, []byte(token.Reveal()), 0o400); err != nil {
		return err
	}
	return p.chown(filepath.Join(dir, name), profile.UID(hosted))
}

// RemoveToken deletes the token once the gateway enrolled.
func (p *Private) RemoveToken(hosted ids.UUID) error {
	dir := p.Dir(hosted)
	if err := os.Chmod(dir, 0o700); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	defer func() { _ = os.Chmod(dir, 0o500) }()
	err := os.Remove(filepath.Join(dir, filepath.Base(profile.TokenFile)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// HasToken reports whether a token waits in the directory.
func (p *Private) HasToken(hosted ids.UUID) bool {
	_, err := os.Lstat(filepath.Join(p.Dir(hosted), filepath.Base(profile.TokenFile)))
	return err == nil
}

// Remove deletes the hosted gateway's private directory.
func (p *Private) Remove(hosted ids.UUID) error {
	dir := p.Dir(hosted)
	_ = os.Chmod(dir, 0o700)
	return os.RemoveAll(dir)
}
