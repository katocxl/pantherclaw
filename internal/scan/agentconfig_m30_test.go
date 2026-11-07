// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scan_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/scan"
)

// TestHR710_ConfigFilesAreReportedByDigestNeverContents: each listed
// configuration and memory file is an agent_config finding with client,
// scope, class, the SHA-256 of its bytes and its size; a file over
// MaxFileSize is too_large and unread. A credential format in a file is an
// env_secret finding with source config_file, the format and the class.
// No attribute holds the contents or the credential (G0 M30 D941, D942).
func TestHR710_ConfigFilesAreReportedByDigestNeverContents(t *testing.T) {
	root := t.TempDir()
	home, proj := filepath.Join(root, "home"), filepath.Join(root, "proj")
	const token = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789AB"
	memory := "Always run the tests.\nDeploy with " + token + "\n"
	write(t, filepath.Join(proj, "CLAUDE.md"), memory)
	write(t, filepath.Join(home, ".claude", "skills", "review", "SKILL.md"), "Review carefully.")
	big := filepath.Join(proj, ".cursorrules")
	write(t, big, strings.Repeat("a", scan.MaxFileSize+1))
	write(t, filepath.Join(proj, "README.md"), "not listed "+token)

	got := scan.Run(scan.Options{Host: "laptop", Home: home, Paths: []string{proj}})
	configs := map[string]map[string]string{}
	var secrets []map[string]string
	for _, f := range got {
		for k, v := range f.Attributes {
			if strings.Contains(v, token) || strings.Contains(v, "Always run") || strings.Contains(v, "Review carefully") {
				t.Errorf("%s finding attribute %s carries contents: %q", f.Kind, k, v)
			}
		}
		switch {
		case f.Kind == scan.KindAgentConfig:
			configs[filepath.Base(f.Attributes["path"])] = f.Attributes
		case f.Kind == scan.KindEnvSecret && f.Attributes["source"] == "config_file":
			secrets = append(secrets, f.Attributes)
		}
	}
	sum := sha256.Sum256([]byte(memory))
	c := configs["CLAUDE.md"]
	if c["client"] != "claude_code" || c["scope"] != "project" || c["path_class"] != "memory" ||
		c["digest"] != hex.EncodeToString(sum[:]) || c["size"] != strconv.Itoa(len(memory)) {
		t.Errorf("CLAUDE.md: %v", c)
	}
	if s := configs["SKILL.md"]; s["scope"] != "user" || s["path_class"] != "skills" || len(s["digest"]) != 64 {
		t.Errorf("SKILL.md: %v", s)
	}
	if b := configs[".cursorrules"]; b["digest"] != scan.DigestTooLarge || b["size"] != strconv.Itoa(scan.MaxFileSize+1) {
		t.Errorf(".cursorrules: %v", b)
	}
	if _, ok := configs["README.md"]; ok || len(configs) != 3 {
		t.Errorf("agent_config findings %v", configs)
	}
	if len(secrets) != 1 || secrets[0]["secret_kind"] != "github_token" || secrets[0]["path_class"] != "memory" {
		t.Fatalf("config secrets %v", secrets)
	}
	if _, err := os.Stat(big); err != nil {
		t.Fatal(err)
	}
}
