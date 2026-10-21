// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writePair writes a self-signed certificate for cn, valid from nb to na,
// and its key, and moves both files' modification time to mod.
func writePair(t *testing.T, dir, cn string, nb, na, mod time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	writeAt(t, filepath.Join(dir, "cert.pem"), certPEM, mod)
	writeAt(t, filepath.Join(dir, "key.pem"), keyPEM, mod)
	return certPEM, keyPEM
}

func writeAt(t *testing.T, path string, b []byte, mod time.Time) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

func servedCN(r *CertReloader) string {
	c := r.Certificate()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return "unparsable"
	}
	return leaf.Subject.CommonName
}

// TestHR371_CertificateReloadsAndKeepsLastGood: a renewed pair is served
// without a restart; a broken, mismatched, expired or missing pair keeps
// the last good one, logs tls.reload_failed without key material, and a
// certificate is always served.
func TestHR371_CertificateReloadsAndKeepsLastGood(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	base := now.Add(-time.Hour)
	_, keyA := writePair(t, dir, "first", now.Add(-time.Hour), now.Add(time.Hour), base)
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	r, err := NewCertReloader(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), log)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if servedCN(r) != "first" {
		t.Fatalf("served %q, want first", servedCN(r))
	}
	if r.Reload(ctx) {
		t.Fatal("reloaded unchanged files")
	}

	// A renewal is picked up.
	certB, keyB := writePair(t, dir, "second", now.Add(-time.Minute), now.Add(90*24*time.Hour), base.Add(time.Minute))
	if !r.Reload(ctx) || servedCN(r) != "second" {
		t.Fatalf("after renewal served %q, want second", servedCN(r))
	}

	bad := map[string]func(mod time.Time){
		"garbage cert": func(mod time.Time) {
			writeAt(t, filepath.Join(dir, "cert.pem"), []byte("not a certificate"), mod)
		},
		"mismatched key": func(mod time.Time) {
			writeAt(t, filepath.Join(dir, "cert.pem"), certB, mod)
			writeAt(t, filepath.Join(dir, "key.pem"), keyA, mod)
		},
		"expired": func(mod time.Time) {
			writePair(t, dir, "expired", now.Add(-48*time.Hour), now.Add(-24*time.Hour), mod)
		},
		"not yet valid": func(mod time.Time) {
			writePair(t, dir, "future", now.Add(24*time.Hour), now.Add(48*time.Hour), mod)
		},
		"missing key": func(time.Time) {
			if err := os.Remove(filepath.Join(dir, "key.pem")); err != nil {
				t.Fatal(err)
			}
		},
	}
	step := 2
	for name, write := range bad {
		logs.Reset()
		write(base.Add(time.Duration(step) * time.Minute))
		step++
		if r.Reload(ctx) {
			t.Errorf("%s: swapped to a bad pair", name)
		}
		if servedCN(r) != "second" {
			t.Errorf("%s: served %q, want the last good pair", name, servedCN(r))
		}
		if c, err := r.GetCertificate(nil); err != nil || c == nil {
			t.Errorf("%s: no certificate served (%v)", name, err)
		}
		if !strings.Contains(logs.String(), `"msg":"tls.reload_failed"`) {
			t.Errorf("%s: no tls.reload_failed log: %s", name, logs.String())
		}
		for _, secret := range [][]byte{keyA, keyB} {
			body := strings.TrimSpace(strings.Split(string(secret), "\n")[1])
			if strings.Contains(logs.String(), body) || strings.Contains(logs.String(), "PRIVATE KEY") {
				t.Errorf("%s: key material in the log", name)
			}
		}
		// Restore the good pair for the next case (a new modification time).
		writeAt(t, filepath.Join(dir, "cert.pem"), certB, base.Add(time.Duration(step)*time.Minute))
		writeAt(t, filepath.Join(dir, "key.pem"), keyB, base.Add(time.Duration(step)*time.Minute))
		step++
		r.Reload(ctx)
	}

	// A failed pair is not read again until a file changes.
	logs.Reset()
	writeAt(t, filepath.Join(dir, "cert.pem"), []byte("broken"), base.Add(time.Hour))
	r.Reload(ctx)
	logs.Reset()
	r.Reload(ctx)
	if logs.Len() != 0 {
		t.Errorf("unchanged bad files were read again: %s", logs.String())
	}
}

// TestHR371_ListenerServesRenewedCertificate: a TLS 1.3 listener with the
// reloading profile presents the renewed certificate to new connections.
func TestHR371_ListenerServesRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writePair(t, dir, "first", now.Add(-time.Hour), now.Add(time.Hour), now.Add(-time.Hour))
	r, err := NewCertReloader(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), nil)
	if err != nil {
		t.Fatal(err)
	}
	conf := ReloadingServerTLSConfig(r)
	if conf.MinVersion != tls.VersionTLS13 || conf.CurvePreferences[0] != tls.X25519MLKEM768 || len(conf.Certificates) != 0 {
		t.Fatalf("profile changed: %+v", conf)
	}
	srv, err := NewServer(ServerConfig{
		Addr: "127.0.0.1:0", TLS: conf,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }),
	})
	if err != nil {
		t.Fatal(err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	peer := func() string {
		d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}} //nolint:gosec // the test reads the presented certificate
		c, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		return c.(*tls.Conn).ConnectionState().PeerCertificates[0].Subject.CommonName
	}
	if got := peer(); got != "first" {
		t.Fatalf("presented %q, want first", got)
	}
	writePair(t, dir, "second", now.Add(-time.Minute), now.Add(time.Hour), now)
	r.Reload(context.Background())
	if got := peer(); got != "second" {
		t.Fatalf("presented %q after renewal, want second", got)
	}
}
