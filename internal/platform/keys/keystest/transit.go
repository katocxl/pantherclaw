// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package keystest is an httptest OpenBao Transit server for tests of the
// key service (G0 M18 S18e, D157). It is never built into a binary.
package keystest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Transit is an httptest OpenBao Transit server: one key with
// versions, encrypt/decrypt/rewrap, token and AppRole auth.
type Transit struct {
	t testing.TB
	// Srv serves the fake; Srv.URL is the OpenBao address.
	Srv *httptest.Server
	// Token is the accepted token; RoleID and SecretID the AppRole login.
	Token    string
	RoleID   string
	SecretID string

	mu       sync.Mutex
	versions [][]byte // AES-256 keys; index+1 is the version
	// Down makes every call fail with 503, like a sealed server.
	Down   atomic.Bool
	Calls  atomic.Int64
	Logins atomic.Int64
	// Delay is slept before each AppRole login.
	Delay time.Duration
	paths []string
}

// NewTransit starts a fake with one key version, closed at the end of t.
func NewTransit(t testing.TB) *Transit {
	t.Helper()
	f := &Transit{t: t, Token: "s.fake-token", RoleID: "role-1", SecretID: "secret-1"}
	f.Rotate()
	f.Srv = httptest.NewServer(f)
	t.Cleanup(f.Srv.Close)
	return f
}

// Rotate adds a key version; new ciphertexts use it.
func (f *Transit) Rotate() {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	f.mu.Lock()
	f.versions = append(f.versions, k)
	f.mu.Unlock()
}

// KeyName is the fake's one Transit key.
const KeyName = "pc-kek"

func (f *Transit) reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.MarshalWrite(w, v)
}

// ServeHTTP implements the Transit and AppRole endpoints of key KeyName.
func (f *Transit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.Calls.Add(1)
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	if f.Down.Load() {
		http.Error(w, `{"errors":["sealed"]}`, http.StatusServiceUnavailable)
		return
	}
	var in map[string]string
	if err := json.UnmarshalRead(r.Body, &in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if r.URL.Path == "/v1/auth/approle/login" {
		if in["role_id"] != f.RoleID || in["secret_id"] != f.SecretID {
			http.Error(w, "denied", http.StatusBadRequest)
			return
		}
		time.Sleep(f.Delay)
		f.Logins.Add(1)
		f.reply(w, map[string]any{"auth": map[string]any{"client_token": f.Token, "lease_duration": 3600}})
		return
	}
	if r.Header.Get("X-Vault-Token") != f.Token {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}
	op, ok := strings.CutPrefix(r.URL.Path, "/v1/transit/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch op {
	case "encrypt/pc-kek":
		pt, err := base64.StdEncoding.DecodeString(in["plaintext"])
		if err != nil {
			http.Error(w, "bad plaintext", http.StatusBadRequest)
			return
		}
		f.reply(w, map[string]any{"data": map[string]string{"ciphertext": f.seal(pt)}})
	case "decrypt/pc-kek":
		pt, ok := f.open(in["ciphertext"])
		if !ok {
			http.Error(w, "cipher: message authentication failed", http.StatusBadRequest)
			return
		}
		f.reply(w, map[string]any{"data": map[string]string{"plaintext": base64.StdEncoding.EncodeToString(pt)}})
	case "rewrap/pc-kek":
		pt, ok := f.open(in["ciphertext"])
		if !ok {
			http.Error(w, "bad ciphertext", http.StatusBadRequest)
			return
		}
		f.reply(w, map[string]any{"data": map[string]string{"ciphertext": f.seal(pt)}})
	default:
		http.NotFound(w, r)
	}
}

func (f *Transit) gcm(v int) cipher.AEAD {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v < 1 || v > len(f.versions) {
		return nil
	}
	b, err := aes.NewCipher(f.versions[v-1])
	if err != nil {
		f.t.Error(err)
		return nil
	}
	// The random-nonce GCM is the one FIPS 140-only mode allows.
	g, err := cipher.NewGCMWithRandomNonce(b)
	if err != nil {
		f.t.Error(err)
		return nil
	}
	return g
}

func (f *Transit) seal(pt []byte) string {
	f.mu.Lock()
	v := len(f.versions)
	f.mu.Unlock()
	g := f.gcm(v)
	if g == nil {
		return ""
	}
	return "vault:v" + strconv.Itoa(v) + ":" + base64.StdEncoding.EncodeToString(g.Seal(nil, nil, pt, nil)) //nolint:gosec // G407: random-nonce GCM requires a nil nonce
}

func (f *Transit) open(ct string) ([]byte, bool) {
	rest, ok := strings.CutPrefix(ct, "vault:v")
	if !ok {
		return nil, false
	}
	vs, b64, ok := strings.Cut(rest, ":")
	v, err := strconv.Atoi(vs)
	if !ok || err != nil {
		return nil, false
	}
	g := f.gcm(v)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if g == nil || err != nil {
		return nil, false
	}
	pt, err := g.Open(nil, nil, raw, nil)
	return pt, err == nil
}
