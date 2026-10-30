// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

// The OS keychain (G0 M18 S18e, D156, HR-485). The secrets of a session —
// the refresh token, the device key seed and, when it fits, the access
// token — go into the OS keychain (macOS Keychain, Windows Credential
// Manager, the Secret Service on Linux); credentials.json keeps only the
// metadata. go-keyring v0.2.8 feeds macOS `security -i` through stdin, so
// no secret is ever on a command line.
//
// --credential-store (env PANTHERCLAW_CREDENTIAL_STORE) is auto, keychain
// or file. auto falls back to the 0600 file, with a warning, where there is
// no keychain (headless Linux, CI). A file that still holds secrets moves
// to the keychain at the next login or refresh, and its secrets are wiped.

// Credential store modes.
const (
	storeAuto     = "auto"
	storeKeychain = "keychain"
	storeFile     = "file"
)

const (
	envCredentialStore = "PANTHERCLAW_CREDENTIAL_STORE"
	keychainService    = "pantherclaw"
	// secretsInKeychain marks a credentials file whose secrets are in the
	// keychain.
	secretsInKeychain = "keychain"
)

// secretStore is the OS keychain (go-keyring); tests replace it.
type secretStore interface {
	Get(service, user string) (string, error)
	Set(service, user, secret string) error
	Delete(service, user string) error
}

type osKeychain struct{}

func (osKeychain) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (osKeychain) Set(service, user, secret string) error   { return keyring.Set(service, user, secret) }
func (osKeychain) Delete(service, user string) error        { return keyring.Delete(service, user) }

// systemKeychain is the keychain pclaw uses.
var systemKeychain secretStore = osKeychain{}

// errKeychainEntry reports a credentials file that points at a keychain
// entry which is gone.
var errKeychainEntry = errors.New("pclaw: the keychain no longer holds this session; run pclaw login again")

// credentialStore returns the configured mode.
func credentialStore(env Env) (string, error) {
	v, _ := env(envCredentialStore)
	switch v {
	case "", storeAuto:
		return storeAuto, nil
	case storeKeychain, storeFile:
		return v, nil
	}
	return "", fmt.Errorf("%s must be auto, keychain or file", envCredentialStore)
}

// credentialStoreFlag takes a leading --credential-store=MODE (or
// --credential-store MODE) off args and passes it on as the environment
// variable, so every command reads the same setting.
func credentialStoreFlag(args []string, env Env) ([]string, Env, error) {
	if len(args) == 0 || !strings.HasPrefix(args[0], "--credential-store") {
		return args, env, nil
	}
	var v string
	switch {
	case strings.HasPrefix(args[0], "--credential-store="):
		v, args = strings.TrimPrefix(args[0], "--credential-store="), args[1:]
	case args[0] == "--credential-store" && len(args) > 1:
		v, args = args[1], args[2:]
	default:
		return nil, nil, errors.New("usage: pclaw --credential-store=auto|keychain|file COMMAND")
	}
	next := func(k string) (string, bool) {
		if k == envCredentialStore {
			return v, true
		}
		return env(k)
	}
	if _, err := credentialStore(next); err != nil {
		return nil, nil, err
	}
	return args, next, nil
}

// keychainSecrets are the values kept in the keychain.
type keychainSecrets struct {
	AccessToken  string `json:"access_token,omitzero"`
	RefreshToken string `json:"refresh_token"`
	DeviceKey    string `json:"device_key"`
}

// storedCreds is the credentials file: Credentials, plus where the secrets
// are.
type storedCreds struct {
	Credentials `json:",inline"`
	Secrets     string `json:"secrets,omitzero"`
}

// keychainUser names a profile's keychain entry: its credentials file.
func keychainUser(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// readSecrets fills c's secrets from the keychain.
func readSecrets(path string, c *Credentials) error {
	raw, err := systemKeychain.Get(keychainService, keychainUser(path))
	if errors.Is(err, keyring.ErrNotFound) {
		return errKeychainEntry
	} else if err != nil {
		return fmt.Errorf("pclaw: reading the keychain: %w", err)
	}
	var s keychainSecrets
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return errKeychainEntry
	}
	c.AccessToken, c.RefreshToken, c.DeviceKey = s.AccessToken, s.RefreshToken, s.DeviceKey
	if s.AccessToken == "" {
		c.AccessExpiry = time.Time{} // not kept: the next call refreshes
	}
	return nil
}

// writeSecrets puts c's secrets in the keychain and returns the file
// record without them. An access token too big for the keychain is not
// kept anywhere; the next call refreshes it.
func writeSecrets(path string, c Credentials) (storedCreds, error) {
	s := keychainSecrets{AccessToken: c.AccessToken, RefreshToken: c.RefreshToken, DeviceKey: c.DeviceKey}
	meta := storedCreds{Credentials: Credentials{Server: c.Server, Org: c.Org, AccessExpiry: c.AccessExpiry}, Secrets: secretsInKeychain}
	for {
		b, err := json.Marshal(s)
		if err != nil {
			return storedCreds{}, err
		}
		err = systemKeychain.Set(keychainService, keychainUser(path), string(b))
		if errors.Is(err, keyring.ErrSetDataTooBig) && s.AccessToken != "" {
			s.AccessToken, meta.AccessExpiry = "", time.Time{}
			continue
		}
		return meta, err
	}
}

// saveCredsTo stores c in the configured store, writing any fallback
// warning to warn (HR-485).
func saveCredsTo(env Env, c Credentials, warn io.Writer) error {
	mode, err := credentialStore(env)
	if err != nil {
		return err
	}
	p, err := credsPath(env)
	if err != nil {
		return err
	}
	if mode == storeFile {
		if err := writeCredsFile(p, storedCreds{Credentials: c}); err != nil {
			return err
		}
		_ = systemKeychain.Delete(keychainService, keychainUser(p))
		return nil
	}
	meta, kerr := writeSecrets(p, c)
	if kerr == nil {
		// Replacing the file wipes any secrets an older file held.
		return writeCredsFile(p, meta)
	}
	if mode == storeKeychain {
		return fmt.Errorf("pclaw: the OS keychain is not available (%w); use --credential-store=file to keep the session in a file", kerr)
	}
	if warn != nil {
		_, _ = fmt.Fprintf(warn, "warning: no OS keychain is available (%v); the session is kept in %s (mode 0600). "+
			"Use --credential-store=file to silence this warning.\n", kerr, p)
	}
	return writeCredsFile(p, storedCreds{Credentials: c})
}
