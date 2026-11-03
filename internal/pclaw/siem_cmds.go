// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/katocxl/pantherclaw/internal/pclaw/siemforward"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// `pclaw siem forward` (founder decision FD8, D660; F950, HR-662) receives
// the SIEM export, verifies each batch and writes its OCSF events as NDJSON
// to a file or stdout, for a SIEM agent that reads files (Sentinel's Azure
// Monitor Agent, Wazuh). It needs no PantherClaw login: the JWKS is public
// and the secrets come from files or the environment, never an argument.
// Diagnostics go to stderr, so `--out -` leaves stdout to the events.

// envSIEMSecret holds one HMAC signing secret, as an alternative to
// --secret-file.
const envSIEMSecret = "PCLAW_SIEM_SECRET" //nolint:gosec // G101: an environment variable's name, not a credential

// maxSecretFile bounds a secret file.
const maxSecretFile = 4 << 10

func init() {
	commands["siem forward"] = command{
		usage: "siem forward --out PATH|- [--listen ADDR] [--secret-file PATH]... [--jwks-url URL | --jwks-file PATH] [--window DURATION] " +
			"[--tls-cert PATH --tls-key PATH]",
		run: siemForward,
	}
}

func siemForward(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("siem forward", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	listen := fs.String("listen", siemforward.DefaultListen, "address to listen on; a non-loopback one needs --tls-cert and --tls-key")
	out := fs.String("out", "", "file the events are appended to (created 0600), or - for stdout (required)")
	var secretFiles list
	fs.Var(&secretFiles, "secret-file", "file holding the destination's signing secret (whsec_…); give it twice during a rotation (at most 2). "+
		"Or set "+envSIEMSecret)
	jwksURL := fs.String("jwks-url", "", "https URL of the org's webhook JWKS, to verify Ed25519 (v1a) signatures")
	jwksFile := fs.String("jwks-file", "", "a saved copy of the org's webhook JWKS, instead of --jwks-url")
	window := fs.Duration("window", siemforward.DefaultWindow, "how far a batch's timestamp may be from this host's clock (at most 15m)")
	certFile := fs.String("tls-cert", "", "TLS certificate (PEM) to serve HTTPS")
	keyFile := fs.String("tls-key", "", "TLS private key (PEM) to serve HTTPS")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *out == "" {
		return errUsage
	}
	switch {
	case *window <= 0 || *window > siemforward.MaxWindow:
		return fmt.Errorf("--window is more than 0 and at most %s", siemforward.MaxWindow)
	case (*certFile == "") != (*keyFile == ""):
		return errors.New("--tls-cert and --tls-key go together")
	case *certFile == "" && !siemforward.Loopback(*listen):
		return fmt.Errorf("--listen %s: %w", *listen, siemforward.ErrNeedsTLS)
	case *jwksURL != "" && *jwksFile != "":
		return errors.New("give --jwks-url or --jwks-file, not both")
	}
	var tlsConf *tls.Config
	if *certFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return fmt.Errorf("--tls-cert/--tls-key: %w", err)
		}
		tlsConf = httpx.ServerTLSConfig(cert)
	}
	secrets, err := a.siemSecrets(secretFiles)
	if err != nil {
		return err
	}
	log := pclog.New(a.stderr, pclog.Options{Service: "pclaw-siem-forward"})
	var keys siemforward.Keys
	switch {
	case *jwksFile != "":
		doc, err := readBounded(*jwksFile, 64<<10)
		if err != nil {
			return fmt.Errorf("--jwks-file: %w", err)
		}
		ks, err := siemforward.ParseJWKS(doc)
		if err != nil {
			return fmt.Errorf("--jwks-file: %w", err)
		}
		if len(ks) == 0 {
			return errors.New("--jwks-file holds no webhooks Ed25519 key")
		}
		keys = siemforward.StaticKeys(ks)
	case *jwksURL != "":
		j, err := siemforward.NewJWKSURL(ctx, *jwksURL, a.http, nil, log)
		if err != nil {
			return err
		}
		keys = j
	}
	if len(secrets) == 0 && keys == nil {
		return siemforward.ErrNoScheme
	}
	var sink siemforward.Sink
	if *out == "-" {
		sink = siemforward.NewWriterSink(a.stdout)
	} else {
		fsink, err := siemforward.OpenFile(*out)
		if err != nil {
			return fmt.Errorf("--out: %w", err)
		}
		sink = fsink
	}
	defer func() { _ = sink.Close() }()
	fwd, err := siemforward.New(siemforward.Config{Secrets: secrets, Keys: keys, Window: *window, Sink: sink, Log: log})
	if err != nil {
		return err
	}
	jwks := "none"
	switch {
	case *jwksFile != "":
		jwks = "file"
	case *jwksURL != "":
		jwks = "url"
	}
	log.InfoContext(ctx, "siem.forward.start", slog.Int("hmac_count", len(secrets)), slog.String("jwks", jwks),
		slog.String("window", window.String()), slog.Bool("stdout", *out == "-"))
	return siemforward.Serve(ctx, fwd, siemforward.ServeConfig{Listen: *listen, TLS: tlsConf, Log: log})
}

// siemSecrets reads the HMAC secrets from --secret-file (at most two) or
// from PCLAW_SIEM_SECRET, never both. No error names a secret's value.
func (a *app) siemSecrets(files []string) ([][]byte, error) {
	env, envSet := a.env(envSIEMSecret)
	envSet = envSet && env != ""
	switch {
	case len(files) > siemforward.MaxSecrets:
		return nil, fmt.Errorf("--secret-file: at most %d (the current secret and the previous one during a rotation)", siemforward.MaxSecrets)
	case len(files) > 0 && envSet:
		return nil, fmt.Errorf("give --secret-file or set %s, not both", envSIEMSecret)
	case envSet:
		s, err := siemforward.ParseSecret(env)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envSIEMSecret, err)
		}
		return [][]byte{s}, nil
	}
	out := make([][]byte, 0, len(files))
	for _, p := range files {
		raw, err := readBounded(p, maxSecretFile)
		if err != nil {
			return nil, fmt.Errorf("--secret-file %s: %w", p, err)
		}
		s, err := siemforward.ParseSecret(string(raw))
		if err != nil {
			return nil, fmt.Errorf("--secret-file %s: %w", p, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// readBounded reads a file the operator names, refusing one over limit
// bytes.
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a file the operator names
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return b, nil
}
