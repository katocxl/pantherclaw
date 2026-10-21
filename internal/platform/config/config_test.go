// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type dbConfig struct {
	Host         string   `json:"host" env:"PC_TEST_DB_HOST"`
	Port         int      `json:"port" env:"PC_TEST_DB_PORT"`
	PasswordFile string   `json:"password_file" env:"PC_TEST_DB_PASSWORD_FILE"`
	Timeout      Duration `json:"timeout" env:"PC_TEST_DB_TIMEOUT"`
}

type testConfig struct {
	Role    string   `json:"role" env:"PC_TEST_ROLE"`
	Debug   bool     `json:"debug" env:"PC_TEST_DEBUG"`
	Ratio   float64  `json:"ratio" env:"PC_TEST_RATIO"`
	Origins []string `json:"origins" env:"PC_TEST_ORIGINS"`
	DB      dbConfig `json:"db"`
}

func (c *testConfig) Validate() error {
	if c.Role != "api" && c.Role != "worker" {
		return errors.New("role must be api or worker")
	}
	return nil
}

func defaults() testConfig {
	return testConfig{Role: "api", DB: dbConfig{Host: "127.0.0.1", Port: 5432, Timeout: Duration(5 * time.Second)}}
}

func envMap(m map[string]string) LookupEnv {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func writeFile(t *testing.T, name, content string, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPrecedenceDefaultsFileEnv(t *testing.T) {
	path := writeFile(t, "c.json", `{"role":"worker","db":{"host":"db.internal","timeout":"10s"}}`, 0o600)
	cfg := defaults()
	err := Load(&cfg, path, envMap(map[string]string{
		"PC_TEST_DB_PORT": "6543", "PC_TEST_DEBUG": "true", "PC_TEST_ORIGINS": "a, b,,c", "PC_TEST_RATIO": "0.25",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Ratio != 0.25 {
		t.Fatalf("ratio = %v", cfg.Ratio)
	}
	if cfg.Role != "worker" || cfg.DB.Host != "db.internal" || cfg.DB.Port != 6543 || !cfg.Debug {
		t.Fatalf("unexpected config %+v", cfg)
	}
	if cfg.DB.Timeout.D() != 10*time.Second {
		t.Fatalf("timeout = %v", cfg.DB.Timeout.D())
	}
	if strings.Join(cfg.Origins, "|") != "a|b|c" {
		t.Fatalf("origins = %q", cfg.Origins)
	}
}

func TestStrictFile(t *testing.T) {
	for name, content := range map[string]string{
		"unknown key":   `{"role":"api","rol":"worker"}`,
		"duplicate key": `{"role":"api","role":"worker"}`,
		"wrong type":    `{"db":{"port":"5432"}}`,
		"bad duration":  `{"db":{"timeout":5}}`,
		"trailing data": `{"role":"api"} {}`,
	} {
		cfg := defaults()
		err := Load(&cfg, writeFile(t, "c.json", content, 0o600), nil)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestEnvErrors(t *testing.T) {
	for k, v := range map[string]string{
		"PC_TEST_DB_PORT":    "54x",
		"PC_TEST_DEBUG":      "yes please",
		"PC_TEST_DB_TIMEOUT": "5",
		"PC_TEST_RATIO":      "a tenth",
	} {
		cfg := defaults()
		err := Load(&cfg, "", envMap(map[string]string{k: v}))
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), k) {
			t.Errorf("%s=%q: err = %v, want ErrInvalid naming the variable", k, v, err)
		}
		if strings.Contains(err.Error(), v) && len(v) > 3 {
			t.Errorf("%s: error echoes the raw value: %v", k, err)
		}
	}
}

func TestValidateRuns(t *testing.T) {
	cfg := defaults()
	err := Load(&cfg, "", envMap(map[string]string{"PC_TEST_ROLE": "admin"}))
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "role must be") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRejectsNonPointer(t *testing.T) {
	if err := Load(defaults(), "", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestOversizedFile(t *testing.T) {
	big := `{"role":"` + strings.Repeat("a", MaxFileBytes) + `"}`
	cfg := defaults()
	if err := Load(&cfg, writeFile(t, "c.json", big, 0o600), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestReadSecretFile(t *testing.T) {
	p := writeFile(t, "pw", "hunter2-not-real\r\n", 0o600)
	s, err := ReadSecretFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(s.Reveal()) != "hunter2-not-real" {
		t.Fatalf("Reveal = %q", s.Reveal())
	}
	if strings.Contains(s.String(), "hunter2") {
		t.Fatal("secret rendered in String()")
	}
}

func TestReadSecretFileErrorsNeverIncludeContents(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"missing": filepath.Join(dir, "nope"),
		"empty":   writeFile(t, "empty", "\n", 0o600),
		"dir":     dir,
		"huge":    writeFile(t, "huge", strings.Repeat("k", MaxSecretBytes+1), 0o600),
		"no path": "",
	}
	for name, p := range cases {
		_, err := ReadSecretFile(p)
		if !errors.Is(err, ErrSecretFile) {
			t.Errorf("%s: err = %v, want ErrSecretFile", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "kkkk") {
			t.Errorf("%s: error contains file contents", name)
		}
	}
}

func TestReadSecretFileRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS permissions are not checked (BUILD_GUIDE §4)")
	}
	p := writeFile(t, "pw", "x", 0o644)
	if _, err := ReadSecretFile(p); !errors.Is(err, ErrSecretFile) {
		t.Fatalf("0644 secret file accepted: %v", err)
	}
}
