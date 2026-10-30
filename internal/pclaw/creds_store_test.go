// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

// memKeychain is an in-memory keychain. Every test in this package uses
// one, so no test touches the machine's real keychain.
type memKeychain struct {
	mu      sync.Mutex
	items   map[string]string
	failing bool // no keychain (headless Linux, CI)
	limit   int  // Set refuses longer values (the Windows 2560-byte blob)
}

func (m *memKeychain) Get(service, user string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failing {
		return "", errors.New("no secret service")
	}
	v, ok := m.items[service+"|"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (m *memKeychain) Set(service, user, secret string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failing {
		return errors.New("no secret service")
	}
	if m.limit > 0 && len(secret) > m.limit {
		return keyring.ErrSetDataTooBig
	}
	m.items[service+"|"+user] = secret
	return nil
}

func (m *memKeychain) Delete(service, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failing {
		return errors.New("no secret service")
	}
	if _, ok := m.items[service+"|"+user]; !ok {
		return keyring.ErrNotFound
	}
	delete(m.items, service+"|"+user)
	return nil
}

func TestMain(m *testing.M) {
	systemKeychain = &memKeychain{items: map[string]string{}}
	os.Exit(m.Run())
}

// withKeychain installs k for one test.
func withKeychain(t *testing.T, k *memKeychain) *memKeychain {
	t.Helper()
	if k.items == nil {
		k.items = map[string]string{}
	}
	prev := systemKeychain
	systemKeychain = k
	t.Cleanup(func() { systemKeychain = prev })
	return k
}

var testSession = Credentials{
	Server: "https://pc.example.com", Org: "o", AccessToken: "at-secret-1", RefreshToken: "pcr_secret-1",
	DeviceKey: "device-seed-secret", AccessExpiry: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
}

func readCredsFile(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertNoSecrets(t *testing.T, file string) {
	t.Helper()
	for _, s := range []string{"at-secret-1", "pcr_secret-1", "device-seed-secret"} {
		if strings.Contains(file, s) {
			t.Fatalf("credentials file holds a secret %q: %s", s, file)
		}
	}
}

// Covers: HR-485, T-211
func TestHR485_SecretsGoToTheKeychain(t *testing.T) {
	k := withKeychain(t, &memKeychain{})
	dir := t.TempDir()
	env := envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": dir})
	var warn bytes.Buffer
	if err := saveCredsTo(env, testSession, &warn); err != nil {
		t.Fatal(err)
	}
	if warn.Len() != 0 {
		t.Fatalf("warning with a keychain: %s", warn.String())
	}
	file := readCredsFile(t, dir)
	assertNoSecrets(t, file)
	if !strings.Contains(file, `"secrets":"keychain"`) || !strings.Contains(file, "pc.example.com") {
		t.Fatalf("metadata missing from the file: %s", file)
	}
	got, err := loadCreds(env)
	if err != nil || got != testSession {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	// Logout removes the keychain entry as well as the file.
	if err := deleteCreds(env); err != nil {
		t.Fatal(err)
	}
	if len(k.items) != 0 {
		t.Fatalf("keychain entries left after logout: %d", len(k.items))
	}
	if _, err := loadCreds(env); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("after logout: %v", err)
	}
}

// Covers: HR-485, T-211
func TestHR485_FileFallbackIsWarned(t *testing.T) {
	withKeychain(t, &memKeychain{failing: true})
	dir := t.TempDir()
	env := envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": dir})
	var warn bytes.Buffer
	if err := saveCredsTo(env, testSession, &warn); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warn.String(), "warning: no OS keychain") || strings.Contains(warn.String(), "pcr_secret-1") {
		t.Fatalf("fallback warning = %q", warn.String())
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(dir, "credentials.json")); fi.Mode().Perm() != 0o600 {
			t.Fatalf("fallback file mode %v", fi.Mode().Perm())
		}
	}
	if got, err := loadCreds(env); err != nil || got != testSession {
		t.Fatalf("fallback round trip = %+v, %v", got, err)
	}
	// keychain mode refuses instead of falling back.
	kenv := envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": t.TempDir(), envCredentialStore: storeKeychain})
	if err := saveCredsTo(kenv, testSession, &warn); err == nil || !strings.Contains(err.Error(), "--credential-store=file") {
		t.Fatalf("keychain mode without a keychain: %v", err)
	}
	// file mode is the user's choice: no warning.
	warn.Reset()
	fenv := envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": t.TempDir(), envCredentialStore: storeFile})
	if err := saveCredsTo(fenv, testSession, &warn); err != nil || warn.Len() != 0 {
		t.Fatalf("file mode = %v, %q", err, warn.String())
	}
}

// Covers: HR-485, T-211
func TestHR485_PlainFileMovesToTheKeychainAndIsWiped(t *testing.T) {
	k := withKeychain(t, &memKeychain{})
	dir := t.TempDir()
	fileEnv := envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": dir, envCredentialStore: storeFile})
	if err := saveCreds(fileEnv, testSession); err != nil { // a file from before M18
		t.Fatal(err)
	}
	if !strings.Contains(readCredsFile(t, dir), "pcr_secret-1") {
		t.Fatal("file mode did not keep the secrets in the file")
	}
	env := envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": dir})
	c, err := loadCreds(env) // still readable
	if err != nil || c != testSession {
		t.Fatalf("legacy file = %+v, %v", c, err)
	}
	c.RefreshToken = "pcr_secret-2" // the next refresh
	if err := saveCredsTo(env, c, nil); err != nil {
		t.Fatal(err)
	}
	file := readCredsFile(t, dir)
	assertNoSecrets(t, file)
	if strings.Contains(file, "pcr_secret-2") || len(k.items) != 1 {
		t.Fatalf("after the move: file %s, %d keychain entries", file, len(k.items))
	}
	if got, err := loadCreds(env); err != nil || got.RefreshToken != "pcr_secret-2" {
		t.Fatalf("after the move = %+v, %v", got, err)
	}
	// A file pointing at a keychain entry that is gone asks for a login.
	k.items = map[string]string{}
	if _, err := loadCreds(env); !errors.Is(err, errKeychainEntry) {
		t.Fatalf("missing keychain entry: %v", err)
	}
}

func TestKeychainDropsAnAccessTokenThatDoesNotFit(t *testing.T) {
	withKeychain(t, &memKeychain{limit: 200})
	dir := t.TempDir()
	env := envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": dir})
	big := testSession
	big.AccessToken = strings.Repeat("a", 500)
	if err := saveCreds(env, big); err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, readCredsFile(t, dir))
	if strings.Contains(readCredsFile(t, dir), strings.Repeat("a", 50)) {
		t.Fatal("the access token was written to the file")
	}
	got, err := loadCreds(env)
	if err != nil || got.AccessToken != "" || !got.AccessExpiry.IsZero() || got.RefreshToken != big.RefreshToken {
		t.Fatalf("too big access token = %+v, %v; want it dropped and refreshed next time", got, err)
	}
}

func TestCredentialStoreFlag(t *testing.T) {
	base := envOf(map[string]string{"X": "y"})
	for _, args := range [][]string{{"--credential-store=file", "whoami"}, {"--credential-store", "file", "whoami"}} {
		rest, env, err := credentialStoreFlag(args, base)
		if err != nil || len(rest) != 1 || rest[0] != "whoami" {
			t.Fatalf("%v: %v %v", args, rest, err)
		}
		if mode, _ := credentialStore(env); mode != storeFile {
			t.Fatalf("%v: mode %q", args, mode)
		}
		if v, _ := env("X"); v != "y" {
			t.Fatal("other variables lost")
		}
	}
	for _, args := range [][]string{{"--credential-store=vault", "whoami"}, {"--credential-store"}} {
		if _, _, err := credentialStoreFlag(args, base); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
	if code, _, errs := run(t, base, "--credential-store=vault", "whoami"); code != 2 || !strings.Contains(errs, "auto, keychain or file") {
		t.Fatalf("bad flag = %d %q", code, errs)
	}
	if _, err := credentialStore(envOf(map[string]string{envCredentialStore: "nope"})); err == nil {
		t.Fatal("bad env accepted")
	}
}

// Covers: HR-485
// TestHR485_NoSecretOnACommandLine guards the pinned go-keyring: on macOS
// its Set must feed `security -i` through stdin and never pass the
// password (-w) as an argument of exec.Command.
func TestHR485_NoSecretOnACommandLine(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/zalando/go-keyring").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(out)), "keyring_darwin.go"))
	if err != nil {
		t.Skipf("module source not available: %v", err)
	}
	s := string(src)
	if !strings.Contains(s, `exec.Command(execPathKeychain, "-i")`) || !strings.Contains(s, "StdinPipe()") {
		t.Fatal("go-keyring's darwin Set no longer uses `security -i` through stdin; add the stdin adapter (D156)")
	}
	if regexp.MustCompile(`exec\.Command\([^)]*"-w"[^)]*password`).MatchString(s) {
		t.Fatal("go-keyring passes the password on a command line")
	}
}
