// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/hosting/sni"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
)

// Config is the host agent's configuration: a JSON file plus PC_HOST_*
// variables, no secret (its key is a file in IdentityDir).
type Config struct {
	// APIURL is the server's gateway listener.
	APIURL string `json:"api_url" env:"PC_HOST_API_URL"`
	// CASHA256 pins the internal CA.
	CASHA256 string `json:"ca_sha256" env:"PC_HOST_CA_SHA256"`
	// IdentityDir keeps the host's key and certificate (0700).
	IdentityDir string `json:"identity_dir" env:"PC_HOST_IDENTITY_DIR"`
	// PrivateRoot is the tmpfs holding each org's private directory.
	PrivateRoot string `json:"private_root" env:"PC_HOST_PRIVATE_ROOT"`
	// Domain is the hosting domain: agents use <slug>.gw.<domain>.
	Domain string `json:"domain" env:"PC_HOST_DOMAIN"`
	// Listen is the SNI router's address (default :443).
	Listen string `json:"listen" env:"PC_HOST_LISTEN"`
	// Runtime is runc or runsc.
	Runtime string `json:"runtime" env:"PC_HOST_RUNTIME"`
	// Images maps gateway versions to images pinned by digest.
	Images map[string]string `json:"images"`
	// DefaultVersion names the image of a gateway without a target.
	DefaultVersion string `json:"default_version" env:"PC_HOST_DEFAULT_VERSION"`
	// PerOrgConnections caps an org's concurrent agent connections.
	PerOrgConnections int             `json:"per_org_connections" env:"PC_HOST_PER_ORG_CONNECTIONS"`
	Timeout           config.Duration `json:"timeout" env:"PC_HOST_TIMEOUT"`
}

var (
	pinRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	imageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)
)

// Validate checks the configuration.
func (c *Config) Validate() error {
	var errs []error
	if !strings.HasPrefix(c.APIURL, "https://") {
		errs = append(errs, errors.New("api_url must be https"))
	}
	if !pinRE.MatchString(c.CASHA256) {
		errs = append(errs, errors.New("ca_sha256 must be sha256:<64 hex>"))
	}
	if c.IdentityDir == "" || c.PrivateRoot == "" || c.Domain == "" {
		errs = append(errs, errors.New("identity_dir, private_root and domain are required"))
	}
	if c.Runtime != docker.RuntimeRunc && c.Runtime != docker.RuntimeRunsc {
		errs = append(errs, errors.New("runtime must be runc or runsc"))
	}
	if _, ok := c.Images[c.DefaultVersion]; !ok {
		errs = append(errs, errors.New("default_version must name one of images"))
	}
	for v, img := range c.Images {
		if !imageRE.MatchString(img) || len(v) > 64 {
			errs = append(errs, fmt.Errorf("images[%q] is not pinned by digest", v))
		}
	}
	return errors.Join(errs...)
}

const usage = `pantherclaw-host — the host agent of a PantherClaw hosting host

Usage:
  pantherclaw-host keygen --identity-dir DIR --csr-out FILE
  pantherclaw-host install --identity-dir DIR --cert FILE --ca-sha256 PIN
  pantherclaw-host serve --config FILE
  pantherclaw-host version

keygen makes the host's key and a certificate request; the operator issues
the host certificate from it, and install saves it. Configuration: JSON file
plus PC_HOST_* environment variables.
`

// Run executes pantherclaw-host.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, env config.LookupEnv) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "version", "--version":
		_, _ = fmt.Fprintln(stdout, version.Get().String("pantherclaw-host"))
		return 0
	case "keygen":
		err = cmdKeygen(args[1:], stdout, stderr)
	case "install":
		err = cmdInstall(args[1:], stdout, stderr)
	case "serve":
		err = serve(ctx, args[1:], stderr, env)
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pantherclaw-host: %v\n", err)
		return 1
	}
	return 0
}

// pendingKey is the key keygen made, waiting for its certificate.
const pendingKey = "host-key.pending"

func cmdKeygen(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("identity-dir", "", "the host's identity directory")
	out := fs.String("csr-out", "", "where to write the DER certificate request")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *out == "" {
		return errors.New("keygen needs --identity-dir and --csr-out")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(*dir, pendingKey, []byte(base64.RawURLEncoding.EncodeToString(priv.Seed())), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(*out, der, 0o644); err != nil { //nolint:gosec // G306: a certificate request is public
		return err
	}
	_, _ = fmt.Fprintf(stdout, "key in %s; certificate request in %s\n", filepath.Join(*dir, pendingKey), *out)
	return nil
}

// Bundle is what the operator's host issuance writes: the host certificate
// and the CA certificate, DER, base64.
type Bundle struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
}

func cmdInstall(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("identity-dir", "", "the host's identity directory")
	certFile := fs.String("cert", "", "the certificate bundle the operator issued")
	pin := fs.String("ca-sha256", "", "the CA pin, sha256:<hex>")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *certFile == "" || !pinRE.MatchString(*pin) {
		return errors.New("install needs --identity-dir, --cert and --ca-sha256")
	}
	seedB64, err := os.ReadFile(filepath.Join(*dir, pendingKey))
	if err != nil {
		return err
	}
	seed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(seedB64)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return ErrIdentity
	}
	b, err := os.ReadFile(*certFile)
	if err != nil {
		return err
	}
	var bundle Bundle
	if err := json.Unmarshal(b, &bundle, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("%w: bundle", ErrIdentity)
	}
	cert, err1 := base64.StdEncoding.DecodeString(bundle.Certificate)
	caDER, err2 := base64.StdEncoding.DecodeString(bundle.CA)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("%w: bundle", ErrIdentity)
	}
	id, err := NewIdentity(ed25519.NewKeyFromSeed(seed), cert, caDER, *pin)
	if err != nil {
		return err
	}
	if err := id.Save(*dir); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(*dir, pendingKey))
	_, _ = fmt.Fprintf(stdout, "installed host %s; certificate valid until %s\n", id.Host.Host, id.NotAfter().Format(time.RFC3339))
	return nil
}

func serve(ctx context.Context, args []string, stderr io.Writer, env config.LookupEnv) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "JSON configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := Config{Listen: ":443", Runtime: docker.RuntimeRunc}
	if err := config.Load(&cfg, *path, env); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-host", Version: version.Get().Version})
	id, err := Load(cfg.IdentityDir, cfg.CASHA256)
	if err != nil {
		return err
	}
	if !time.Now().Before(id.NotAfter()) {
		return errors.New("hosting agent: the host certificate expired; issue a new one")
	}
	private, err := NewPrivate(cfg.PrivateRoot)
	if err != nil {
		return err
	}
	hc := httpx.NewControlClient(httpx.ControlConfig{
		Timeout: cfg.Timeout.D(), RootCAs: id.Roots(), Link: "hosting-control", Log: log,
		ClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c := id.TLSCertificate()
			return &c, nil
		},
	})
	base := strings.TrimSuffix(cfg.APIURL, "/")
	cli := docker.CLI{}
	router := &sni.Router{Domain: cfg.Domain, PerOrg: cfg.PerOrgConnections, Log: log}
	a := &Agent{
		Control: pantherclawv1connect.NewHostingAgentServiceClient(connect.NewClient(connecthttp.NewTransport(hc, base))),
		Engine:  docker.New(cli),
		Volumes: func(ctx context.Context, name string) error {
			if !strings.HasPrefix(name, "pc-hgv-") {
				return docker.ErrInvalid
			}
			_, err := cli.Run(ctx, "volume", "rm", name)
			return err
		},
		Private: private, Router: router, Images: cfg.Images, Default: cfg.DefaultVersion, Runtime: cfg.Runtime,
		Version: version.Get().Version, Log: log,
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	versions := make([]string, 0, len(cfg.Images))
	for v := range cfg.Images {
		versions = append(versions, v)
	}
	slices.Sort(versions)
	log.InfoContext(ctx, "hosting.agent_started", "host_id", id.Host.Host.String(), "listen", ln.Addr().String(), "versions", versions)
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return router.Serve(ctx, ln) })
	eg.Go(func() error { return a.Run(ctx) })
	return eg.Wait()
}
