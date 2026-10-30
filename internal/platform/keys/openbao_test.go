// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keys

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOpenBaoProviderWrapUnwrap(t *testing.T) {
	ctx := context.Background()
	f := newTransitFake(t)
	p := baoProvider(t, f)
	if p.CurrentKEK() != "bao:pc-kek" {
		t.Fatalf("CurrentKEK = %q", p.CurrentKEK())
	}
	w, err := p.Wrap(ctx, []byte("dek-bytes"), []byte("dek|org|purpose|1"))
	if err != nil {
		t.Fatal(err)
	}
	if kek, err := KEKOf(w); err != nil || kek != "bao:pc-kek" {
		t.Fatalf("KEKOf = %q, %v", kek, err)
	}
	pt, err := p.Unwrap(ctx, w, []byte("dek|org|purpose|1"))
	if err != nil || string(pt) != "dek-bytes" {
		t.Fatalf("Unwrap = %q, %v", pt, err)
	}
	// The associated data is bound: the same value under another row's AAD
	// does not unwrap.
	if _, err := p.Unwrap(ctx, w, []byte("dek|org|purpose|2")); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("unwrap with other AAD: %v", err)
	}
	if _, err := p.Wrap(ctx, []byte("x"), nil); err == nil {
		t.Fatal("wrap without AAD accepted")
	}
	if len(w) > 1024 {
		t.Fatalf("wrapped DEK is %d bytes, over the column limit", len(w))
	}
}

func TestTransitClientAppRoleAndRelogin(t *testing.T) {
	ctx := context.Background()
	f := newTransitFake(t)
	c, err := NewTransitClient(OpenBaoConfig{
		Address: f.Srv.URL, KeyName: "pc-kek",
		Auth: OpenBaoAuth{Kind: AuthAppRole, RoleID: f.RoleID, SecretIDFile: writeSecret(t, "sid", f.SecretID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := c.Encrypt(ctx, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if f.Logins.Load() != 1 {
		t.Fatalf("logins = %d", f.Logins.Load())
	}
	// A refused token logs in once more.
	f.Token = "s.rotated"
	pt, err := c.Decrypt(ctx, ct)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("Decrypt = %q, %v", pt, err)
	}
	if f.Logins.Load() != 2 {
		t.Fatalf("logins after a refused token = %d", f.Logins.Load())
	}
	// Rewrap moves a ciphertext to the newest key version.
	f.Rotate()
	re, err := c.Rewrap(ctx, ct)
	if err != nil || !strings.HasPrefix(re, "vault:v2:") {
		t.Fatalf("Rewrap = %q, %v", re, err)
	}
	if pt, err := c.Decrypt(ctx, re); err != nil || string(pt) != "hello" {
		t.Fatalf("Decrypt(rewrapped) = %q, %v", pt, err)
	}
}

// Covers: HR-486, T-210
func TestHR486_OpenBaoOutageFailsClosed(t *testing.T) {
	ctx := context.Background()
	f := newTransitFake(t)
	bao := baoProvider(t, f)
	fp, err := NewFileProvider([]string{kekFile(t, t.TempDir(), "kek")})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRouter(PrefixOpenBao, fp, bao)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("dek|org|p|1")
	w, err := r.Wrap(ctx, []byte("dek"), aad)
	if err != nil {
		t.Fatal(err)
	}
	f.Down.Store(true)
	if _, err := r.Wrap(ctx, []byte("dek"), aad); !errors.Is(err, ErrKeyServiceUnavailable) {
		t.Fatalf("wrap during an outage: %v", err)
	}
	pt, err := r.Unwrap(ctx, w, aad)
	if !errors.Is(err, ErrUnwrap) || pt != nil {
		t.Fatalf("unwrap during an outage = %q, %v; want ErrUnwrap and no plaintext", pt, err)
	}
	// No fallback: the file provider never sees an OpenBao value.
	if _, err := fp.Unwrap(ctx, w, aad); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("file provider unwrapped an OpenBao value: %v", err)
	}
	f.Down.Store(false)
	if pt, err := r.Unwrap(ctx, w, aad); err != nil || string(pt) != "dek" {
		t.Fatalf("unwrap after recovery = %q, %v", pt, err)
	}
	// A provider that is not configured fails closed too.
	fileOnly, _ := NewRouter(PrefixFile, fp, nil)
	if _, err := fileOnly.Unwrap(ctx, w, aad); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("unwrap without an OpenBao provider: %v", err)
	}
}

// Covers: HR-488
func TestHR488_OpenBaoAddressAndTLS(t *testing.T) {
	ok := []string{"https://bao.example:8200", "https://bao.example", "http://127.0.0.1:8200", "http://127.8.9.10:8200", "http://[::1]:8200"}
	for _, a := range ok {
		if _, err := baoBaseURL(a); err != nil {
			t.Errorf("%s refused: %v", a, err)
		}
	}
	bad := []string{
		"http://bao.example:8200", "http://10.0.0.5:8200", "ftp://bao.example", "https://u:p@bao.example",
		"https://bao.example/v1/transit", "https://bao.example?x=1", "bao.example:8200", "",
		// A name is resolved, so even localhost needs TLS (D165).
		"http://localhost:8200", "http://LOCALHOST:8200", "http://127.0.0.1.nip.io:8200", "http://[::ffff:10.0.0.1]:8200",
	}
	for _, a := range bad {
		if _, err := baoBaseURL(a); err == nil {
			t.Errorf("%s accepted", a)
		}
	}

	// Redirects and proxies are never followed: only the configured
	// address is reached.
	var elsewhere int
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere++ }))
	t.Cleanup(other.Close)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirect.Close)
	t.Setenv("HTTP_PROXY", other.URL)
	t.Setenv("HTTPS_PROXY", other.URL)
	t.Setenv("NO_PROXY", "")
	c, err := NewTransitClient(OpenBaoConfig{
		Address: redirect.URL, KeyName: "pc-kek",
		Auth: OpenBaoAuth{Kind: AuthToken, TokenFile: writeSecret(t, "token", "s.x")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Encrypt(context.Background(), []byte("x")); !errors.Is(err, ErrKeyServiceUnavailable) {
		t.Fatalf("redirected call: %v", err)
	}
	if elsewhere != 0 {
		t.Fatalf("the client reached another address %d times", elsewhere)
	}

	// TLS: an https address with an untrusted certificate is refused; the
	// configured CA bundle makes it work.
	f := newTransitFake(t)
	tlsSrv := httptest.NewTLSServer(f)
	t.Cleanup(tlsSrv.Close)
	cfg := tokenConfig(t, f)
	cfg.Address = strings.Replace(tlsSrv.URL, "127.0.0.1", "localhost", 1)
	untrusted, err := NewTransitClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrusted.Encrypt(context.Background(), []byte("x")); !errors.Is(err, ErrKeyServiceUnavailable) {
		t.Fatalf("untrusted certificate: %v", err)
	}
	cfg.Address = tlsSrv.URL
	cfg.CAFile = writeCA(t, tlsSrv)
	trusted, err := NewTransitClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trusted.Encrypt(context.Background(), []byte("x")); err != nil {
		t.Fatalf("trusted certificate: %v", err)
	}
}

func writeCA(t *testing.T, s *httptest.Server) string {
	t.Helper()
	return writeSecret(t, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})))
}

func TestRouterRoutesByKEKPrefix(t *testing.T) {
	ctx := context.Background()
	f := newTransitFake(t)
	fp, err := NewFileProvider([]string{kekFile(t, t.TempDir(), "kek")})
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("signing|org|receipts|kid")
	legacy, err := fp.Wrap(ctx, []byte("seed"), aad) // written before M18
	if err != nil {
		t.Fatal(err)
	}
	if kek, _ := KEKOf(legacy); kek != PrefixFile+fp.CurrentKEK() {
		t.Fatalf("KEKOf(file value) = %q", kek)
	}
	fileRouter, _ := NewRouter(PrefixFile, fp, nil)
	if fileRouter.CurrentKEK() != PrefixFile+fp.CurrentKEK() {
		t.Fatalf("file router CurrentKEK = %q", fileRouter.CurrentKEK())
	}
	r, err := NewRouter(PrefixOpenBao, fp, baoProvider(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := r.Unwrap(ctx, legacy, aad); err != nil || string(pt) != "seed" {
		t.Fatalf("legacy file value through the router = %q, %v", pt, err)
	}
	if !SameKEK(fp.CurrentKEK(), PrefixFile+fp.CurrentKEK()) || SameKEK("bao:pc-kek", "file:pc-kek") {
		t.Fatal("SameKEK")
	}
	for _, bad := range [][]byte{nil, {wrapV1}, {0x02, 1, 'x'}, {wrapV1, 0}, {wrapV1, 9, 'x'}} {
		if _, err := r.Unwrap(ctx, bad, aad); !errors.Is(err, ErrUnwrap) {
			t.Errorf("Unwrap(%x) = %v", bad, err)
		}
	}
	if _, err := NewRouter(PrefixOpenBao, fp, nil); err == nil {
		t.Fatal("router without its current provider accepted")
	}
	if _, err := NewRouter("kms:", fp, nil); err == nil {
		t.Fatal("unknown provider accepted")
	}
}

// tamperProvider wraps with an inner provider but corrupts the output.
type tamperProvider struct {
	KeyProvider
	mode string
}

func (p tamperProvider) Wrap(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	switch p.mode {
	case "other-key":
		return p.KeyProvider.Wrap(ctx, []byte("not the original key"), aad)
	case "flip":
		w, err := p.KeyProvider.Wrap(ctx, plaintext, aad)
		if err == nil {
			w[len(w)-3] ^= 0x01
		}
		return w, err
	}
	return p.KeyProvider.Wrap(ctx, plaintext, aad)
}

// Covers: HR-487, T-210
func TestHR487_RewrapVerifiesBeforeReturning(t *testing.T) {
	ctx := context.Background()
	f := newTransitFake(t)
	fp, err := NewFileProvider([]string{kekFile(t, t.TempDir(), "kek")})
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("dek|org|p|1")
	old, err := fp.Wrap(ctx, []byte("0123456789abcdef0123456789abcdef"), aad)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := NewRouter(PrefixOpenBao, fp, baoProvider(t, f))
	nw, kek, err := Rewrap(ctx, r, old, aad)
	if err != nil {
		t.Fatal(err)
	}
	if kek != "bao:pc-kek" {
		t.Fatalf("kek = %q", kek)
	}
	if pt, err := r.Unwrap(ctx, nw, aad); err != nil || string(pt) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("re-wrapped value = %q, %v", pt, err)
	}
	for _, mode := range []string{"other-key", "flip"} {
		got, kek, err := Rewrap(ctx, tamperProvider{r, mode}, old, aad)
		if !errors.Is(err, ErrRewrapVerify) || got != nil || kek != "" {
			t.Errorf("%s: Rewrap = %d bytes, %q, %v; want ErrRewrapVerify and nothing", mode, len(got), kek, err)
		}
	}
	// An outage mid-way returns nothing to write.
	f.Down.Store(true)
	if got, _, err := Rewrap(ctx, r, old, aad); err == nil || got != nil {
		t.Fatalf("Rewrap during an outage = %d bytes, %v", len(got), err)
	}
}

func TestServiceConfigFromConfig(t *testing.T) {
	f := newTransitFake(t)
	kek := kekFile(t, t.TempDir(), "kek")
	r, err := FromConfig(ServiceConfig{}, []string{kek})
	if err != nil || !strings.HasPrefix(r.CurrentKEK(), PrefixFile) {
		t.Fatalf("file: %v, %v", r, err)
	}
	r, err = FromConfig(ServiceConfig{Kind: ServiceOpenBao, OpenBao: tokenConfig(t, f)}, nil)
	if err != nil || r.CurrentKEK() != "bao:pc-kek" {
		t.Fatalf("openbao: %v, %v", r, err)
	}
	for name, c := range map[string]ServiceConfig{
		"no kek files": {},
		"bad kind":     {Kind: "kms"},
		"no address":   {Kind: ServiceOpenBao, OpenBao: OpenBaoConfig{KeyName: "k", Auth: OpenBaoAuth{Kind: AuthToken, TokenFile: "t"}}},
		"no key":       {Kind: ServiceOpenBao, OpenBao: OpenBaoConfig{Address: "https://b", Auth: OpenBaoAuth{Kind: AuthToken, TokenFile: "t"}}},
		"no auth":      {Kind: ServiceOpenBao, OpenBao: OpenBaoConfig{Address: "https://b", KeyName: "k"}},
		"approle":      {Kind: ServiceOpenBao, OpenBao: OpenBaoConfig{Address: "https://b", KeyName: "k", Auth: OpenBaoAuth{Kind: AuthAppRole}}},
		"plain http":   {Kind: ServiceOpenBao, OpenBao: OpenBaoConfig{Address: "http://b", KeyName: "k", Auth: OpenBaoAuth{Kind: AuthToken, TokenFile: "t"}}},
	} {
		if _, err := FromConfig(c, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestOpenBaoReal runs against a real OpenBao when PC_TEST_OPENBAO_ADDR is
// set (with PC_TEST_OPENBAO_TOKEN, and a Transit key "pc-test" on mount
// "transit"; `bao server -dev` and `bao secrets enable transit`).
func TestOpenBaoReal(t *testing.T) {
	addr := os.Getenv("PC_TEST_OPENBAO_ADDR")
	if addr == "" {
		t.Skip("PC_TEST_OPENBAO_ADDR is not set")
	}
	key := os.Getenv("PC_TEST_OPENBAO_KEY")
	if key == "" {
		key = "pc-test"
	}
	c, err := NewTransitClient(OpenBaoConfig{
		Address: addr, KeyName: key,
		Auth: OpenBaoAuth{Kind: AuthToken, TokenFile: writeSecret(t, "token", os.Getenv("PC_TEST_OPENBAO_TOKEN"))},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p := NewOpenBaoProvider(c)
	aad := []byte("dek|org|p|1")
	w, err := p.Wrap(ctx, []byte("0123456789abcdef0123456789abcdef"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := p.Unwrap(ctx, w, aad); err != nil || len(pt) != 32 {
		t.Fatalf("Unwrap = %d bytes, %v", len(pt), err)
	}
	if _, err := p.Unwrap(ctx, w, []byte("other")); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("unwrap with other AAD: %v", err)
	}
	if _, err := c.Rewrap(ctx, string(w[2+len(p.kid):])); err != nil {
		t.Fatal(err)
	}
}

// Covers: HR-486
func TestTransitClientConcurrentCallersShareOneLogin(t *testing.T) {
	f := newTransitFake(t)
	f.Delay = 200 * time.Millisecond
	c, err := NewTransitClient(OpenBaoConfig{
		Address: f.Srv.URL, KeyName: "pc-kek",
		Auth: OpenBaoAuth{Kind: AuthAppRole, RoleID: f.RoleID, SecretIDFile: writeSecret(t, "sid", f.SecretID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			_, err := c.Encrypt(context.Background(), []byte("x"))
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := f.Logins.Load(); n != 1 {
		t.Fatalf("20 concurrent callers logged in %d times; want 1", n)
	}
	// A cancelled first caller does not fail the others' shared login.
	f.Token = "s.rotated"
	c.dropToken()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.currentToken(ctx); err != nil {
		t.Fatalf("login with a cancelled caller context: %v", err)
	}
}

func TestRouterRoutesStoredKEKIDs(t *testing.T) {
	f := newTransitFake(t)
	fp, err := NewFileProvider([]string{kekFile(t, t.TempDir(), "kek")})
	if err != nil {
		t.Fatal(err)
	}
	both, _ := NewRouter(PrefixOpenBao, fp, baoProvider(t, f))
	baoOnly, _ := NewRouter(PrefixOpenBao, nil, baoProvider(t, f))
	for id, want := range map[string][2]bool{
		fp.CurrentKEK():              {true, false}, // pre-M18, unprefixed
		PrefixFile + fp.CurrentKEK(): {true, false},
		"file:kek-0000000000000000":  {false, false},
		"bao:pc-kek":                 {true, true},
		"bao:other-key":              {false, false},
	} {
		if got := [2]bool{both.Routes(id), baoOnly.Routes(id)}; got != want {
			t.Errorf("Routes(%q) = %v, want %v", id, got, want)
		}
	}
}
