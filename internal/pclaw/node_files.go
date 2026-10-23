// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// The files of a local node (`pclaw up`, G0 M13 D36, D39). Everything lives
// in one directory, ~/.pantherclaw/node by default:
//
//	compose.yaml          generated on every run (do not edit)
//	server.json           the server's configuration, generated on every run
//	gateway.json          the gateway's configuration, generated on every run
//	state.json            what pclaw up chose and did (sign-in, ports, org)
//	secrets/              0700: database passwords, the owner's URL, KEKs,
//	                      the identity provider's client secret
//	tls/                  the node's own CA and PostgreSQL's certificate
//	secrets/gateway-enroll.json
//	                      0600: the gateway's single-use enrollment
//
// Inside the containers the configurations are mounted under /node, and
// each service's secrets come from its own volume at /node/secrets
// (secrets-init in compose.yaml). The gateway's identity and broker key
// stay in the gatewaydata volume.

// nodeState is state.json.
type nodeState struct {
	// Deployment is production, or development with --dev.
	Deployment  string      `json:"deployment"`
	APIPort     int         `json:"api_port"`
	GatewayPort int         `json:"gateway_port"`
	OIDC        *nodeOIDC   `json:"oidc,omitempty"`
	GitHub      *nodeGitHub `json:"github,omitempty"`
	// Bootstrapped: `db bootstrap` succeeded once.
	Bootstrapped bool `json:"bootstrapped"`
	// Org is the organization `org create` made, OrgName its name.
	Org     string `json:"org,omitempty"`
	OrgName string `json:"org_name,omitempty"`
	// BrokerKey: the gateway's broker key was generated.
	BrokerKey bool `json:"broker_key"`
	// GatewayID is gateway "local", once created.
	GatewayID string `json:"gateway_id,omitempty"`
}

// nodeOIDC is the operator's own identity provider; its client secret is
// copied to secrets/oidc-client.secret.
type nodeOIDC struct {
	Name     string `json:"name"`
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
}

// nodeGitHub is the GitHub sign-in App people link their GitHub account
// with; its client secret is copied to secrets/github-client.secret.
type nodeGitHub struct {
	ClientID string `json:"client_id"`
}

const (
	nodeStateFile      = "state.json"
	nodeComposeFile    = "compose.yaml"
	nodeServerConfig   = "server.json"
	nodeGatewayConfig  = "gateway.json"
	nodeEnrollFile     = "gateway-enroll.json"
	nodeSecretsDir     = "secrets"
	nodeTLSDir         = "tls"
	nodeGatewayDir     = "gateway"
	nodeOIDCSecret     = "oidc-client.secret"
	nodeGitHubSecret   = "github-client.secret"
	nodeDeploymentProd = "production"
	nodeDeploymentDev  = "development"
	// nodePostgresImage is the PostgreSQL 17 image deploy/compose pins.
	nodePostgresImage = "postgres:17-bookworm@sha256:3645570cccdfa447589da9f57dd740faa29b30938e861289a5574b6ca6b03826"
	// nodeServerHost is the server's name on the node's network: the
	// gateway enrolls at http://server:8080 and connects to its mTLS
	// listener at https://server:8443.
	nodeServerHost = "server"
	// nodePostgresHost is PostgreSQL's name on the node's network, in its
	// certificate.
	nodePostgresHost = "postgres"
)

// nodePasswordFiles are the generated database passwords.
var nodePasswordFiles = []string{"pg_owner.pw", "pc_app.pw", "pc_migrator.pw", "pc_audit_ro.pw", "pc_retention.pw"}

func loadNodeState(dir string) (nodeState, bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, nodeStateFile)) //nolint:gosec // G304: the node directory pclaw manages
	if errors.Is(err, fs.ErrNotExist) {
		return nodeState{}, false, nil
	}
	if err != nil {
		return nodeState{}, false, err
	}
	var st nodeState
	if err := json.Unmarshal(b, &st); err != nil {
		return nodeState{}, false, fmt.Errorf("pclaw: %s: %w", filepath.Join(dir, nodeStateFile), err)
	}
	return st, true, nil
}

func saveNodeState(dir string, st nodeState) error {
	b, err := json.Marshal(st, json.Deterministic(true))
	if err != nil {
		return err
	}
	return writeNodeFile(filepath.Join(dir, nodeStateFile), append(indentJSON(b), '\n'), 0o600)
}

// writeNodeFile replaces path with b (written beside it, then renamed).
func writeNodeFile(path string, b []byte, perm os.FileMode) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, perm); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// writeNodeSecrets creates what is missing: the database passwords, the
// owner's connection URL, the server's and the gateway's KEKs. Existing
// files are never replaced.
func writeNodeSecrets(dir string) error {
	sec := filepath.Join(dir, nodeSecretsDir)
	if err := os.MkdirAll(sec, 0o700); err != nil {
		return err
	}
	for _, name := range nodePasswordFiles {
		p := filepath.Join(sec, name)
		if _, err := os.Stat(p); err == nil {
			continue
		}
		pw := make([]byte, 24)
		if _, err := rand.Read(pw); err != nil {
			return err
		}
		if err := writeNodeFile(p, []byte(hex.EncodeToString(pw)), 0o600); err != nil {
			return err
		}
	}
	owner, err := os.ReadFile(filepath.Join(sec, "pg_owner.pw")) //nolint:gosec // G304: the node directory pclaw manages
	if err != nil {
		return err
	}
	u := url.URL{
		Scheme: "postgres", User: url.UserPassword("pc_owner", strings.TrimSpace(string(owner))),
		Host: nodePostgresHost + ":5432", Path: "/pantherclaw",
		RawQuery: "sslmode=verify-full&sslrootcert=/node/secrets/ca.crt",
	}
	if err := writeNodeFile(filepath.Join(sec, "admin.url"), []byte(u.String()), 0o600); err != nil {
		return err
	}
	for _, name := range []string{"kek", "gateway-kek"} {
		p := filepath.Join(sec, name)
		if _, err := os.Stat(p); err == nil {
			continue
		}
		if err := keys.GenerateKEKFile(p); err != nil {
			return err
		}
	}
	return nil
}

// copyNodeSecret copies an operator's secret file into secrets/name.
func copyNodeSecret(dir, from, name string) error {
	b, err := os.ReadFile(from) //nolint:gosec // G304: operator-chosen secret file
	if err != nil {
		return fmt.Errorf("pclaw: read %s: %w", from, err)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return fmt.Errorf("pclaw: %s is empty", from)
	}
	return writeNodeFile(filepath.Join(dir, nodeSecretsDir, name), b, 0o600)
}

// nodeCertRenewBefore: PostgreSQL's certificate is replaced when it
// expires within this.
const nodeCertRenewBefore = 30 * 24 * time.Hour

// writeNodeTLS creates the node's CA once (10 years) and PostgreSQL's
// certificate for the name "postgres" (2 years), renewed when it expires
// within 30 days. The server connects with sslmode=verify-full.
func writeNodeTLS(dir string, now time.Time) error {
	d := filepath.Join(dir, nodeTLSDir)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	caCertPath, caKeyPath := filepath.Join(d, "ca.crt"), filepath.Join(d, "ca.key")
	caCert, caKey, err := readNodeCA(caCertPath, caKeyPath)
	if err != nil {
		caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial(), Subject: pkix.Name{CommonName: "PantherClaw local node CA"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0),
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
		if err != nil {
			return err
		}
		if caCert, err = x509.ParseCertificate(der); err != nil {
			return err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
		if err != nil {
			return err
		}
		if err := writeNodeFile(caKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
			return err
		}
		if err := writeNodeFile(caCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			return err
		}
		// A new CA invalidates the old leaf.
		_ = os.Remove(filepath.Join(d, "postgres.crt"))
	}
	leafPath := filepath.Join(d, "postgres.crt")
	if b, err := os.ReadFile(leafPath); err == nil { //nolint:gosec // G304: the node directory pclaw manages
		if blk, _ := pem.Decode(b); blk != nil {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil && c.CheckSignatureFrom(caCert) == nil &&
				c.NotAfter.Sub(now) > nodeCertRenewBefore {
				return nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: nodePostgresHost},
		DNSNames: []string{nodePostgresHost}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeNodeFile(filepath.Join(d, "postgres.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return writeNodeFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func readNodeCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, err := os.ReadFile(certPath) //nolint:gosec // G304: the node directory pclaw manages
	if err != nil {
		return nil, nil, err
	}
	kb, err := os.ReadFile(keyPath) //nolint:gosec // G304: the node directory pclaw manages
	if err != nil {
		return nil, nil, err
	}
	cblk, _ := pem.Decode(cb)
	kblk, _ := pem.Decode(kb)
	if cblk == nil || kblk == nil {
		return nil, nil, errors.New("pclaw: malformed node CA")
	}
	c, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || !c.IsCA {
		return nil, nil, errors.New("pclaw: malformed node CA")
	}
	return c, ek, nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err) // crypto/rand never fails
	}
	return n
}

// nodePublicURL is the server's URL on this machine.
func nodePublicURL(st nodeState) string {
	return "http://localhost:" + strconv.Itoa(st.APIPort)
}

// nodeServerConfigJSON is server.json. The server binds every address in
// its container with plaintext_behind_proxy; compose publishes the port on
// the host's loopback only (D39). The gateway listener stays mTLS with the
// internal CA, reachable only on the node's network.
func nodeServerConfigJSON(st nodeState) ([]byte, error) {
	apiKeyEnv := "live"
	if st.Deployment == nodeDeploymentDev {
		apiKeyEnv = "dev"
	}
	providers := []any{}
	if st.OIDC != nil {
		providers = append(providers, map[string]any{
			"name": st.OIDC.Name, "issuer": st.OIDC.Issuer, "client_id": st.OIDC.ClientID,
			"client_secret_file": "/node/secrets/" + nodeOIDCSecret,
		})
	}
	cfg := map[string]any{
		"role":       "all",
		"deployment": st.Deployment,
		"log":        map[string]any{"level": "info"},
		"http":       map[string]any{"addr": "0.0.0.0:8080", "plaintext_behind_proxy": true},
		"database": map[string]any{
			"host": nodePostgresHost, "port": 5432, "name": "pantherclaw",
			"sslmode": "verify-full", "sslrootcert": "/node/secrets/ca.crt",
			"app_user": "pc_app", "app_password_file": "/node/secrets/pc_app.pw",
			"migrator_user": "pc_migrator", "migrator_password_file": "/node/secrets/pc_migrator.pw",
			"retention_user": "pc_retention", "retention_password_file": "/node/secrets/pc_retention.pw",
		},
		"kek_files": []string{"/node/secrets/kek"},
		"gateway_api": map[string]any{
			"addr": "0.0.0.0:8443", "hostnames": []string{nodeServerHost}, "url": "https://" + nodeServerHost + ":8443",
		},
		"auth": map[string]any{"public_url": nodePublicURL(st), "api_key_env": apiKeyEnv, "oidc_providers": providers},
	}
	if st.GitHub != nil {
		cfg["github"] = map[string]any{"client_id": st.GitHub.ClientID, "client_secret_file": "/node/secrets/" + nodeGitHubSecret}
	}
	b, err := json.Marshal(cfg, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	return append(indentJSON(b), '\n'), nil
}

// nodeGatewayConfigJSON is gateway.json: the agent-facing listener in
// plain HTTP inside the container, published on the host's loopback only
// (plaintext_published_loopback, D39).
func nodeGatewayConfigJSON(st nodeState) ([]byte, error) {
	cfg := map[string]any{
		"log":                          map[string]any{"level": "info"},
		"listen":                       "0.0.0.0:8090",
		"plaintext_published_loopback": true,
		"public_url":                   "http://localhost:" + strconv.Itoa(st.GatewayPort),
		// The gateway enrolls from gateway-enroll.json; no default API URL.
		"control": map[string]any{"api_url": "", "identity_dir": "/node/gateway/identity", "timeout": "5s"},
		"broker":  map[string]any{"key_file": "/node/gateway/broker.json", "kek_files": []string{"/node/secrets/gateway-kek"}},
	}
	b, err := json.Marshal(cfg, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	return append(indentJSON(b), '\n'), nil
}

// nodeEnrollJSON is gateway-enroll.json (gateway.EnrollFile).
func nodeEnrollJSON(token, caSHA256 string) ([]byte, error) {
	b, err := json.Marshal(map[string]string{
		"api_url": "http://" + nodeServerHost + ":8080", "token": token, "ca_sha256": caSHA256,
	}, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func indentJSON(b []byte) []byte {
	v := jsontext.Value(bytes.Clone(b))
	if v.Indent(jsontext.WithIndent("  ")) != nil {
		return b
	}
	return v
}

// nodeComposeData fills compose.yaml.
type nodeComposeData struct {
	Project, ServerImage, GatewayImage, PostgresImage string
	APIPort, GatewayPort                              int
}

// The distroless images run as nonroot (65532). Secrets reach them through
// one named volume per service, which secrets-init fills from the node
// directory with owner 65532 and mode 0400 on every pclaw up: bind-mounted
// files keep the host's modes, which Docker Desktop shows as 0777 and the
// server refuses for secrets. Each volume holds only what its service needs.
var nodeComposeTemplate = template.Must(template.New("compose").Parse(`# Generated by pclaw up (G0 M13 D36, D39) on every run: do not edit.
# Ports are published on 127.0.0.1 only. Data stays in the volumes
# {{.Project}}_pgdata and {{.Project}}_gatewaydata after pclaw down.
name: {{.Project}}

x-hardening: &hardening
  read_only: true
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
  tmpfs: ["/tmp"]

services:
  postgres:
    image: {{.PostgresImage}}
    environment:
      POSTGRES_DB: pantherclaw
      POSTGRES_USER: pc_owner
      POSTGRES_PASSWORD_FILE: /run/pantherclaw/pg_owner.pw
      POSTGRES_INITDB_ARGS: "--auth-host=scram-sha-256 --data-checksums"
    # PostgreSQL wants its key owned by its own user: copy the mounted pair
    # into place before the image's entrypoint.
    entrypoint:
      - /bin/sh
      - -c
      - >-
        install -o postgres -g postgres -m 0600 /run/pantherclaw/postgres.key /var/lib/postgresql/server.key &&
        install -o postgres -g postgres -m 0644 /run/pantherclaw/postgres.crt /var/lib/postgresql/server.crt &&
        exec docker-entrypoint.sh "$$@"
      - --
    command:
      - postgres
      - -c
      - ssl=on
      - -c
      - ssl_cert_file=/var/lib/postgresql/server.crt
      - -c
      - ssl_key_file=/var/lib/postgresql/server.key
      - -c
      - ssl_min_protocol_version=TLSv1.3
      - -c
      - password_encryption=scram-sha-256
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./secrets/pg_owner.pw:/run/pantherclaw/pg_owner.pw:ro
      - ./tls/postgres.crt:/run/pantherclaw/postgres.crt:ro
      - ./tls/postgres.key:/run/pantherclaw/postgres.key:ro
    security_opt: ["no-new-privileges:true"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U pc_owner -d pantherclaw"]
      interval: 2s
      timeout: 3s
      retries: 30
    restart: unless-stopped

  # Copies each service's secrets into its own volume (owner 65532, 0400)
  # and prepares the gateway's data volume. Runs on every pclaw up.
  secrets-init:
    image: {{.PostgresImage}}
    profiles: ["tools"]
    network_mode: none
    cap_drop: [ALL]
    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER]
    security_opt: ["no-new-privileges:true"]
    entrypoint:
      - /bin/sh
      - -c
      - |
        set -eu
        put() {
          vol=$$1; shift
          install -d -m 0500 -o 65532 -g 65532 "/v/$$vol"
          rm -f "/v/$$vol"/*
          for f in "$$@"; do
            if [ -f "/src/$$f" ]; then install -m 0400 -o 65532 -g 65532 "/src/$$f" "/v/$$vol/$$f"; fi
          done
        }
        put bootstrap admin.url pc_app.pw pc_migrator.pw pc_audit_ro.pw pc_retention.pw
        put migrate pc_migrator.pw
        put server pc_app.pw pc_retention.pw kek oidc-client.secret github-client.secret
        put gateway gateway-kek gateway-enroll.json
        for vol in bootstrap migrate server; do
          install -m 0444 -o 65532 -g 65532 /tls/ca.crt "/v/$$vol/ca.crt"
        done
        chown 65532:65532 /gw && chmod 0700 /gw
    volumes:
      - ./secrets:/src:ro
      - ./tls/ca.crt:/tls/ca.crt:ro
      - sec-bootstrap:/v/bootstrap
      - sec-migrate:/v/migrate
      - sec-server:/v/server
      - sec-gateway:/v/gateway
      - gatewaydata:/gw

  # db bootstrap, once, as the database owner.
  bootstrap:
    <<: *hardening
    image: {{.ServerImage}}
    profiles: ["tools"]
    volumes:
      - sec-bootstrap:/node/secrets:ro
    depends_on:
      postgres: {condition: service_healthy}

  # migrate up: the only service with the migrator's password (besides
  # bootstrap, which sets it).
  migrate:
    <<: *hardening
    image: {{.ServerImage}}
    profiles: ["tools"]
    volumes:
      - ./server.json:/node/server.json:ro
      - sec-migrate:/node/secrets:ro
    depends_on:
      postgres: {condition: service_healthy}

  server:
    <<: *hardening
    image: {{.ServerImage}}
    command: ["serve", "--config", "/node/server.json"]
    ports:
      - "127.0.0.1:{{.APIPort}}:8080"
    volumes:
      - ./server.json:/node/server.json:ro
      - sec-server:/node/secrets:ro
    depends_on:
      postgres: {condition: service_healthy}
    restart: unless-stopped

  # broker-key generate, once.
  gateway-tools:
    <<: *hardening
    image: {{.GatewayImage}}
    profiles: ["tools"]
    network_mode: none
    volumes:
      - gatewaydata:/node/gateway
      - sec-gateway:/node/secrets:ro

  # Started once gateway "local" exists (pclaw up after pclaw login).
  gateway:
    <<: *hardening
    image: {{.GatewayImage}}
    profiles: ["gateway"]
    command: ["serve", "--config", "/node/gateway.json", "--enroll-file", "/node/secrets/gateway-enroll.json"]
    ports:
      - "127.0.0.1:{{.GatewayPort}}:8090"
    volumes:
      - ./gateway.json:/node/gateway.json:ro
      - gatewaydata:/node/gateway
      - sec-gateway:/node/secrets:ro
    depends_on:
      server: {condition: service_started}
    restart: unless-stopped

volumes:
  pgdata:
  gatewaydata:
  sec-bootstrap:
  sec-migrate:
  sec-server:
  sec-gateway:
`))

func nodeComposeYAML(d nodeComposeData) ([]byte, error) {
	var b bytes.Buffer
	if err := nodeComposeTemplate.Execute(&b, d); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// nodeProject is the compose project name: pantherclaw-node for the
// default directory, with a suffix from the directory otherwise, so two
// nodes never share containers or volumes.
func nodeProject(dir, defaultDir string) string {
	if filepath.Clean(dir) == filepath.Clean(defaultDir) {
		return "pantherclaw-node"
	}
	sum := sha256.Sum256([]byte(filepath.Clean(dir)))
	return "pantherclaw-node-" + hex.EncodeToString(sum[:4])
}
