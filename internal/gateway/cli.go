// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
)

// EnrollFile is what `pantherclaw-server dev seed --gateway-out` writes and
// `serve --enroll-file` reads: where to enroll, the single-use token and
// the CA pin.
type EnrollFile struct {
	APIURL   string `json:"api_url"`
	Token    string `json:"token"`
	CASHA256 string `json:"ca_sha256"`
}

// ReadEnrollFile reads an enrollment file.
func ReadEnrollFile(path string) (EnrollFile, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: operator-chosen enrollment file
	if err != nil {
		return EnrollFile{}, err
	}
	var f EnrollFile
	if err := json.Unmarshal(b, &f, json.RejectUnknownMembers(true)); err != nil || f.Token == "" || f.APIURL == "" ||
		!pinPattern.MatchString(f.CASHA256) {
		return EnrollFile{}, errors.New("gateway: malformed enrollment file")
	}
	return f, nil
}

// enroll enrolls the gateway and saves its identity.
func enroll(ctx context.Context, cfg *Config, apiURL, pin string, token pclog.Secret[string]) (*control.Identity, error) {
	hc := httpx.NewControlClient(httpx.ControlConfig{Timeout: cfg.Control.Timeout.D()})
	id, err := control.Enroll(ctx, hc, apiURL, token, pin)
	if err != nil {
		return nil, err
	}
	if err := id.Save(cfg.Control.IdentityDir); err != nil {
		return nil, err
	}
	return id, nil
}

// LoadOrEnroll loads the saved identity, enrolling from an enrollment file
// when there is none or it has expired.
func LoadOrEnroll(ctx context.Context, cfg *Config, enrollFile string, log *slog.Logger) (*control.Identity, error) {
	id, err := control.Load(cfg.Control.IdentityDir, cfg.Control.CASHA256)
	if err == nil && !id.Expired(time.Now()) {
		return id, nil
	}
	if enrollFile == "" {
		if err == nil {
			return nil, errors.New("gateway: the gateway certificate expired; enroll again with a new token")
		}
		return nil, err
	}
	f, ferr := ReadEnrollFile(enrollFile)
	if ferr != nil {
		return nil, ferr
	}
	if cfg.Control.CASHA256 != "" && f.CASHA256 != cfg.Control.CASHA256 {
		return nil, control.ErrPin
	}
	log.InfoContext(ctx, "gateway.enrolling", slog.String("api_url", f.APIURL))
	return enroll(ctx, cfg, f.APIURL, f.CASHA256, pclog.NewSecret(f.Token))
}

const usage = `pantherclaw-gateway — PantherClaw gateway

Usage:
  pantherclaw-gateway enroll --config FILE --token-file FILE
  pantherclaw-gateway broker-key generate --out FILE --kek-file FILE
  pantherclaw-gateway serve [--config FILE] [--enroll-file FILE]
  pantherclaw-gateway version

Configuration: JSON file plus PC_GW_* environment variables; secrets only as file paths.
`

// Run executes pantherclaw-gateway.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, env config.LookupEnv) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "version", "--version":
		_, _ = fmt.Fprintln(stdout, version.Get().String("pantherclaw-gateway"))
		return 0
	case "serve":
		err = serve(ctx, args[1:], stderr, env, nil)
	case "broker-key":
		err = cmdBrokerKey(ctx, args[1:], stdout, stderr)
	case "enroll":
		err = cmdEnroll(ctx, args[1:], stdout, stderr, env)
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pantherclaw-gateway: %v\n", err)
		return 1
	}
	return 0
}

func loadConfig(args []string, stderr io.Writer, env config.LookupEnv, name string, extra func(*flag.FlagSet)) (Config, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "JSON configuration file")
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	cfg := DefaultConfig()
	if err := config.Load(&cfg, *path, env); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func cmdEnroll(ctx context.Context, args []string, stdout, stderr io.Writer, env config.LookupEnv) error {
	var tokenFile string
	cfg, err := loadConfig(args, stderr, env, "enroll", func(fs *flag.FlagSet) {
		fs.StringVar(&tokenFile, "token-file", "", "file holding the single-use pcg_ enrollment token")
	})
	if err != nil {
		return err
	}
	if tokenFile == "" || cfg.Control.APIURL == "" || cfg.Control.CASHA256 == "" {
		return errors.New("enroll needs --token-file, control.api_url and control.ca_sha256")
	}
	tok, err := config.ReadSecretFile(tokenFile)
	if err != nil {
		return err
	}
	id, err := enroll(ctx, &cfg, cfg.Control.APIURL, cfg.Control.CASHA256, pclog.NewSecret(strings.TrimSpace(string(tok.Reveal()))))
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "enrolled gateway %s of org %s; certificate valid until %s; identity in %s\n",
		id.Gateway, id.Org, id.NotAfter().Format(time.RFC3339), cfg.Control.IdentityDir)
	return nil
}

func serve(ctx context.Context, args []string, stderr io.Writer, env config.LookupEnv, onStart func(addr string)) error {
	var enrollFile string
	cfg, err := loadConfig(args, stderr, env, "serve", func(fs *flag.FlagSet) {
		fs.StringVar(&enrollFile, "enroll-file", "", "enroll from this file when no identity is saved (development)")
	})
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	level, _ := pclog.ParseLevel(cfg.Log.Level)
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-gateway", Version: version.Get().Version, Level: level})
	id, err := LoadOrEnroll(ctx, &cfg, enrollFile, log)
	if err != nil {
		return err
	}
	g, err := New(ctx, &cfg, id, log)
	if err != nil {
		return err
	}
	var tlsConf *tls.Config
	if cfg.TLS.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("gateway: TLS key pair: %w", err)
		}
		tlsConf = httpx.ServerTLSConfig(cert)
	}
	srv, err := httpx.NewServer(httpx.ServerConfig{Addr: cfg.Listen, Handler: g.Handler(), TLS: tlsConf, Logger: log})
	if err != nil {
		return err
	}
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return g.Run(ctx) })
	// Serve nothing until the first containment snapshot arrived (HR-010).
	if err := g.WaitReady(ctx, 30*time.Second); err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.InfoContext(ctx, "gateway.listening", slog.String("addr", ln.Addr().String()), slog.String("gateway_id", id.Gateway.String()),
		slog.String("org_id", id.Org.String()))
	warnApproverKeys(ctx, &cfg, id.Org.String(), log)
	if onStart != nil {
		onStart(ln.Addr().String())
	}
	eg.Go(func() error {
		var err error
		if tlsConf != nil {
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})
	eg.Go(func() error {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	})
	return eg.Wait()
}
