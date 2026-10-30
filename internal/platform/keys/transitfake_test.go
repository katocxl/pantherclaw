// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// transitFake is an httptest OpenBao Transit server: one key with
// versions, encrypt/decrypt/rewrap, token and AppRole auth.
type transitFake struct {
	t        *testing.T
	srv      *httptest.Server
	token    string
	roleID   string
	secretID string

	mu       sync.Mutex
	versions [][]byte // AES-256 keys; index+1 is the version
	down     atomic.Bool
	calls    atomic.Int64
	logins   atomic.Int64
	paths    []string
}

func newTransitFake(t *testing.T) *transitFake {
	t.Helper()
	f := &transitFake{t: t, token: "s.fake-token", roleID: "role-1", secretID: "secret-1"}
	f.rotate()
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *transitFake) rotate() {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	f.mu.Lock()
	f.versions = append(f.versions, k)
	f.mu.Unlock()
}

func (f *transitFake) reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.MarshalWrite(w, v)
}

func (f *transitFake) serve(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	if f.down.Load() {
		http.Error(w, `{"errors":["sealed"]}`, http.StatusServiceUnavailable)
		return
	}
	var in map[string]string
	if err := json.UnmarshalRead(r.Body, &in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if r.URL.Path == "/v1/auth/approle/login" {
		if in["role_id"] != f.roleID || in["secret_id"] != f.secretID {
			http.Error(w, "denied", http.StatusBadRequest)
			return
		}
		f.logins.Add(1)
		f.reply(w, map[string]any{"auth": map[string]any{"client_token": f.token, "lease_duration": 3600}})
		return
	}
	if r.Header.Get("X-Vault-Token") != f.token {
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

func (f *transitFake) gcm(v int) cipher.AEAD {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v < 1 || v > len(f.versions) {
		return nil
	}
	b, err := aes.NewCipher(f.versions[v-1])
	if err != nil {
		f.t.Fatal(err)
	}
	// The random-nonce GCM is the one FIPS 140-only mode allows.
	g, err := cipher.NewGCMWithRandomNonce(b)
	if err != nil {
		f.t.Fatal(err)
	}
	return g
}

func (f *transitFake) seal(pt []byte) string {
	f.mu.Lock()
	v := len(f.versions)
	f.mu.Unlock()
	return "vault:v" + strconv.Itoa(v) + ":" + base64.StdEncoding.EncodeToString(f.gcm(v).Seal(nil, nil, pt, nil))
}

func (f *transitFake) open(ct string) ([]byte, bool) {
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

func writeSecret(t *testing.T, name, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// tokenConfig is a Transit config for the fake with token-file auth.
func (f *transitFake) tokenConfig(t *testing.T) OpenBaoConfig {
	return OpenBaoConfig{
		Address: f.srv.URL, KeyName: "pc-kek",
		Auth: OpenBaoAuth{Kind: AuthToken, TokenFile: writeSecret(t, "token", f.token)},
	}
}

func (f *transitFake) provider(t *testing.T) *OpenBaoProvider {
	t.Helper()
	c, err := NewTransitClient(f.tokenConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	return NewOpenBaoProvider(c)
}
