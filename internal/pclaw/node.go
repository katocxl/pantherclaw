// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect/v2"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// `pclaw up`, `pclaw down` and `pclaw status`: a local single-node install
// through Docker Compose (G0 M13 D36, D39; PN-010.1). The compose file,
// the configurations and the secrets are generated into the node directory
// (node_files.go); the server and gateway images are the ones this pclaw
// release names by digest.

func init() {
	commands["up"] = command{
		usage: "up [--dev] [--oidc-issuer URL --oidc-client-id ID --oidc-client-secret-file F [--oidc-name N]] " +
			"[--github-client-id ID --github-client-secret-file F] [--org-name N] [--port P] [--gateway-port P] [--dir D]",
		run: nodeUp,
	}
	commands["down"] = command{usage: "down [--dir D]", run: nodeDown}
	commands["status"] = command{usage: "status [--dir D]", run: nodeStatus}
}

// Set at release build time (-ldflags -X, .goreleaser.yaml) to the images
// the release published, by digest; empty in a development build, which
// uses images built locally from this checkout (task images).
var (
	nodeServerImage  string
	nodeGatewayImage string
)

// Development fallbacks: `task images` builds them.
const (
	nodeDevServerImage  = "pantherclaw-server:dev"
	nodeDevGatewayImage = "pantherclaw-gateway:dev"
)

// nodeImages returns the server and gateway images, and whether they are
// the development fallbacks.
func nodeImages() (server, gateway string, dev bool) {
	if nodeServerImage != "" && nodeGatewayImage != "" {
		return nodeServerImage, nodeGatewayImage, false
	}
	return nodeDevServerImage, nodeDevGatewayImage, true
}

// nodeDocker runs docker; tests replace it.
type nodeDocker func(ctx context.Context, dir string, stdout, stderr io.Writer, args ...string) error

func execDocker(ctx context.Context, dir string, stdout, stderr io.Writer, args ...string) error {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return errNoDocker
	}
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: docker with arguments pclaw builds
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, stdout, stderr
	return cmd.Run()
}

var errNoDocker = errors.New("pclaw up needs Docker with Compose v2: install Docker (28 or later) and start it")

// node is one command's view of the node directory.
type node struct {
	a       *app
	dir     string
	project string
	docker  nodeDocker
	// readyTimeout bounds the wait for the server's /readyz.
	readyTimeout time.Duration
}

// defaultNodeDir is ~/.pantherclaw/node.
func defaultNodeDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("pclaw: no home directory: %w", err)
	}
	return filepath.Join(home, ".pantherclaw", "node"), nil
}

// newNode resolves the directory: --dir, then PANTHERCLAW_NODE_DIR, then
// ~/.pantherclaw/node.
func newNode(a *app, dirFlag string) (*node, error) {
	def, err := defaultNodeDir()
	if err != nil {
		return nil, err
	}
	dir := dirFlag
	if dir == "" {
		if v, ok := a.env("PANTHERCLAW_NODE_DIR"); ok && v != "" {
			dir = v
		} else {
			dir = def
		}
	}
	if dir, err = filepath.Abs(dir); err != nil {
		return nil, err
	}
	d := nodeDockerHook
	if d == nil {
		d = execDocker
	}
	return &node{a: a, dir: dir, project: nodeProject(dir, def), docker: d, readyTimeout: 3 * time.Minute}, nil
}

// nodeDockerHook replaces docker in tests (nil: the docker binary).
var nodeDockerHook nodeDocker

// compose runs docker compose on the node's file, with every profile so
// that down and ps see all services.
func (n *node) compose(ctx context.Context, stdout io.Writer, args ...string) error {
	full := append([]string{"compose", "--file", filepath.Join(n.dir, nodeComposeFile), "--project-directory", n.dir}, args...)
	var errb bytes.Buffer
	if err := n.docker(ctx, n.dir, stdout, io.MultiWriter(&errb, n.a.stderr), full...); err != nil {
		if errors.Is(err, errNoDocker) {
			return err
		}
		return fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// checkDocker refuses without a running Docker engine and Compose v2.
func (n *node) checkDocker(ctx context.Context) error {
	var out bytes.Buffer
	if err := n.docker(ctx, "", &out, io.Discard, "version", "--format", "{{.Server.Version}}"); err != nil || strings.TrimSpace(out.String()) == "" {
		return errNoDocker
	}
	out.Reset()
	if err := n.docker(ctx, "", &out, io.Discard, "compose", "version", "--short"); err != nil || strings.TrimSpace(out.String()) == "" {
		return errNoDocker
	}
	return nil
}

type upFlags struct {
	dev                                          bool
	oidcIssuer, oidcClientID, oidcSecret, oidcNm string
	ghClientID, ghSecret                         string
	orgName, dir                                 string
	port, gatewayPort                            int
}

func nodeUp(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var f upFlags
	fs.BoolVar(&f.dev, "dev", false, "deployment=development, for a quick try-out (never production); sign in with go run ./test/devoidc and a host-run server (BUILD_GUIDE §4) or your own provider")
	fs.StringVar(&f.oidcIssuer, "oidc-issuer", "", "your OpenID provider's issuer URL, which people sign in with")
	fs.StringVar(&f.oidcClientID, "oidc-client-id", "", "the client id registered at the provider")
	fs.StringVar(&f.oidcSecret, "oidc-client-secret-file", "", "file holding the client secret (copied into the node directory)")
	fs.StringVar(&f.oidcNm, "oidc-name", "sso", "name of the provider (its redirect URI is <url>/oauth2/callback/<name>)")
	fs.StringVar(&f.ghClientID, "github-client-id", "", "a GitHub sign-in App's client id, for people to link their GitHub accounts")
	fs.StringVar(&f.ghSecret, "github-client-secret-file", "", "file holding that App's client secret (copied into the node directory)")
	fs.StringVar(&f.orgName, "org-name", "local", "name of the organization the first run creates")
	fs.IntVar(&f.port, "port", 0, "API port on 127.0.0.1 (default 8080, then what the first run chose)")
	fs.IntVar(&f.gatewayPort, "gateway-port", 0, "gateway port on 127.0.0.1 (default 8090, then what the first run chose)")
	fs.StringVar(&f.dir, "dir", "", "node directory (default $PANTHERCLAW_NODE_DIR or ~/.pantherclaw/node)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	n, err := newNode(a, f.dir)
	if err != nil {
		return err
	}
	return n.up(ctx, f)
}

func nodeDown(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	dir := fs.String("dir", "", "node directory (default $PANTHERCLAW_NODE_DIR or ~/.pantherclaw/node)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	n, err := newNode(a, *dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(n.dir, nodeComposeFile)); err != nil {
		return fmt.Errorf("pclaw: no node in %s (run pclaw up first)", n.dir)
	}
	if err := n.checkDocker(ctx); err != nil {
		return err
	}
	if err := n.compose(ctx, a.stderr, "--profile", "gateway", "--profile", "tools", "down", "--remove-orphans"); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(a.stdout, "The node is stopped. Its data stays in the Docker volumes %s_pgdata and %s_gatewaydata and in %s; pclaw up starts it again.\n",
		n.project, n.project, n.dir)
	return nil
}

func nodeStatus(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	dir := fs.String("dir", "", "node directory (default $PANTHERCLAW_NODE_DIR or ~/.pantherclaw/node)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	n, err := newNode(a, *dir)
	if err != nil {
		return err
	}
	st, ok, err := loadNodeState(n.dir)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("pclaw: no node in %s (run pclaw up first)", n.dir)
	}
	if err := n.checkDocker(ctx); err != nil {
		return err
	}
	if err := n.compose(ctx, a.stdout, "--profile", "gateway", "ps", "--all"); err != nil {
		return err
	}
	code, body := n.readyz(ctx, st)
	ready := "not ready"
	if code == http.StatusOK {
		ready = "ready"
	}
	_, _ = fmt.Fprintf(a.stdout, "\nserver: %s, %s (/readyz %s)\n", nodePublicURL(st), ready, body)
	_, _ = fmt.Fprintf(a.stdout, "deployment: %s\n", st.Deployment)
	if st.Org != "" {
		_, _ = fmt.Fprintf(a.stdout, "organization: %s (%s)\n", st.Org, st.OrgName)
	}
	switch {
	case st.GatewayID != "":
		_, _ = fmt.Fprintf(a.stdout, "gateway: local (%s) on http://localhost:%d\n", st.GatewayID, st.GatewayPort)
	default:
		_, _ = fmt.Fprintln(a.stdout, "gateway: not enrolled yet (pclaw login, then pclaw up)")
	}
	if code != http.StatusOK {
		return &exitError{code: 1, msg: "pclaw: the server is not ready"}
	}
	return nil
}

// readyz asks the server's /readyz once.
func (n *node) readyz(ctx context.Context, st nodeState) (int, string) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(st.APIPort)+"/readyz", nil)
	if err != nil {
		return 0, "unreachable"
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return 0, "unreachable"
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, strings.TrimSpace(string(b))
}

// mergeUpFlags applies this run's flags to the saved state: sign-in and
// ports given now replace the saved ones; the deployment is fixed by the
// first run.
func mergeUpFlags(st nodeState, existed bool, f upFlags) (nodeState, error) {
	want := nodeDeploymentProd
	if f.dev {
		want = nodeDeploymentDev
	}
	if existed && st.Deployment != want {
		return st, fmt.Errorf("pclaw: this node is a %s deployment; a node does not change deployment (pclaw down, then use another --dir)", st.Deployment)
	}
	st.Deployment = want
	if f.port != 0 {
		st.APIPort = f.port
	}
	if f.gatewayPort != 0 {
		st.GatewayPort = f.gatewayPort
	}
	if st.APIPort == 0 {
		st.APIPort = 8080
	}
	if st.GatewayPort == 0 {
		st.GatewayPort = 8090
	}
	for _, p := range []int{st.APIPort, st.GatewayPort} {
		if p < 1 || p > 65535 {
			return st, errors.New("pclaw: --port and --gateway-port must be 1..65535")
		}
	}
	if st.APIPort == st.GatewayPort {
		return st, errors.New("pclaw: --port and --gateway-port must differ")
	}
	oidcAny := f.oidcIssuer != "" || f.oidcClientID != "" || f.oidcSecret != ""
	if oidcAny {
		if f.oidcIssuer == "" || f.oidcClientID == "" || f.oidcSecret == "" {
			return st, errors.New("pclaw: --oidc-issuer, --oidc-client-id and --oidc-client-secret-file go together")
		}
		u, err := url.Parse(f.oidcIssuer)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return st, errors.New("pclaw: --oidc-issuer must be the provider's issuer URL")
		}
		if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`).MatchString(f.oidcNm) {
			return st, errors.New("pclaw: --oidc-name must be lower-case letters, digits and dashes")
		}
		st.OIDC = &nodeOIDC{Name: f.oidcNm, Issuer: f.oidcIssuer, ClientID: f.oidcClientID}
	}
	if (f.ghClientID == "") != (f.ghSecret == "") {
		return st, errors.New("pclaw: --github-client-id and --github-client-secret-file go together")
	}
	if f.ghClientID != "" {
		st.GitHub = &nodeGitHub{ClientID: f.ghClientID}
	}
	if st.OrgName == "" {
		st.OrgName = f.orgName
	}
	return st, nil
}

// prepare writes every generated file of the node directory.
func (n *node) prepare(st nodeState, f upFlags, now time.Time) error {
	if err := os.MkdirAll(n.dir, 0o700); err != nil {
		return err
	}
	if err := writeNodeSecrets(n.dir); err != nil {
		return err
	}
	if f.oidcSecret != "" {
		if err := copyNodeSecret(n.dir, f.oidcSecret, nodeOIDCSecret); err != nil {
			return err
		}
	}
	if f.ghSecret != "" {
		if err := copyNodeSecret(n.dir, f.ghSecret, nodeGitHubSecret); err != nil {
			return err
		}
	}
	if err := writeNodeTLS(n.dir, now); err != nil {
		return err
	}
	srv, err := nodeServerConfigJSON(st)
	if err != nil {
		return err
	}
	// The configurations hold file paths only, no secrets: readable by the
	// containers' nonroot user.
	if err := writeNodeFile(filepath.Join(n.dir, nodeServerConfig), srv, 0o644); err != nil {
		return err
	}
	gw, err := nodeGatewayConfigJSON(st)
	if err != nil {
		return err
	}
	if err := writeNodeFile(filepath.Join(n.dir, nodeGatewayConfig), gw, 0o644); err != nil {
		return err
	}
	server, gateway, _ := nodeImages()
	compose, err := nodeComposeYAML(nodeComposeData{
		Project: n.project, ServerImage: server, GatewayImage: gateway, PostgresImage: nodePostgresImage,
		APIPort: st.APIPort, GatewayPort: st.GatewayPort,
	})
	if err != nil {
		return err
	}
	return writeNodeFile(filepath.Join(n.dir, nodeComposeFile), compose, 0o600)
}

var orgCreatedRe = regexp.MustCompile(`created organization ([0-9a-f-]{36})`)

func (n *node) up(ctx context.Context, f upFlags) error {
	a := n.a
	if err := n.checkDocker(ctx); err != nil {
		return err
	}
	st, existed, err := loadNodeState(n.dir)
	if err != nil {
		return err
	}
	if st, err = mergeUpFlags(st, existed, f); err != nil {
		return err
	}
	if err := n.prepare(st, f, time.Now()); err != nil {
		return err
	}
	if err := saveNodeState(n.dir, st); err != nil {
		return err
	}
	server, _, dev := nodeImages()
	if dev {
		_, _ = fmt.Fprintf(a.stderr, "pclaw: this development build uses the local images %s and %s (build them with: task images)\n",
			nodeDevServerImage, nodeDevGatewayImage)
	}
	say := func(s string) { _, _ = fmt.Fprintln(a.stderr, s) }

	say("1/5 PostgreSQL")
	if err := n.compose(ctx, a.stderr, "up", "--detach", "--wait", "postgres"); err != nil {
		return err
	}
	if err := n.initSecrets(ctx); err != nil {
		return err
	}
	if !st.Bootstrapped {
		say("2/5 database roles and schema (db bootstrap)")
		if err := n.compose(ctx, a.stderr, "--profile", "tools", "run", "--rm", "bootstrap", "db", "bootstrap",
			"--admin-url-file", "/node/secrets/admin.url",
			"--app-password-file", "/node/secrets/pc_app.pw", "--migrator-password-file", "/node/secrets/pc_migrator.pw",
			"--audit-password-file", "/node/secrets/pc_audit_ro.pw", "--retention-password-file", "/node/secrets/pc_retention.pw"); err != nil {
			return err
		}
		st.Bootstrapped = true
		if err := saveNodeState(n.dir, st); err != nil {
			return err
		}
	} else {
		say("2/5 database roles and schema: done before")
	}
	say("3/5 migrations (migrate up)")
	if err := n.compose(ctx, a.stderr, "--profile", "tools", "run", "--rm", "migrate", "migrate", "up", "--config", "/node/server.json"); err != nil {
		return err
	}
	if !st.BrokerKey {
		if err := n.compose(ctx, a.stderr, "--profile", "tools", "run", "--rm", "gateway-tools", "broker-key", "generate",
			"--out", "/node/gateway/broker.json", "--kek-file", "/node/secrets/gateway-kek"); err != nil {
			return err
		}
		st.BrokerKey = true
		if err := saveNodeState(n.dir, st); err != nil {
			return err
		}
	}
	var token string
	if st.Org == "" {
		say("4/5 the organization (org create)")
		var out bytes.Buffer
		if err := n.compose(ctx, &out, "run", "--rm", "--no-deps", "-T", "server", "org", "create", "--name", st.OrgName, "--config", "/node/server.json"); err != nil {
			return err
		}
		m := orgCreatedRe.FindStringSubmatch(out.String())
		tok := regexp.MustCompile(`\bpci_[A-Za-z0-9_-]+`).FindString(out.String())
		if m == nil || tok == "" {
			return errors.New("pclaw: org create printed no organization and token")
		}
		st.Org, token = m[1], tok
		if err := saveNodeState(n.dir, st); err != nil {
			return err
		}
	} else {
		say("4/5 the organization: " + st.Org)
	}
	say("5/5 the server (" + server + ")")
	if err := n.compose(ctx, a.stderr, "up", "--detach", "server"); err != nil {
		return err
	}
	if err := n.waitReady(ctx, st); err != nil {
		return err
	}
	gatewayLine, err := n.gateway(ctx, &st)
	if err != nil {
		return err
	}
	n.printUp(st, token, gatewayLine)
	return nil
}

// initSecrets copies each service's secrets into its own volume (owner
// 65532, mode 0400) and prepares the gateway's data volume.
func (n *node) initSecrets(ctx context.Context) error {
	return n.compose(ctx, n.a.stderr, "--profile", "tools", "run", "--rm", "secrets-init")
}

// waitReady polls /readyz until it answers 200.
func (n *node) waitReady(ctx context.Context, st nodeState) error {
	deadline := time.Now().Add(n.readyTimeout)
	for {
		code, body := n.readyz(ctx, st)
		if code == http.StatusOK {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pclaw: the server was not ready within %s (/readyz: %s); see docker compose --file %s logs server",
				n.readyTimeout, body, filepath.Join(n.dir, nodeComposeFile))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// nodeGatewayName is the gateway pclaw up creates.
const nodeGatewayName = "local"

// gatewayAdmin is what enrolling the gateway needs.
type gatewayAdmin interface {
	CreateGateway(context.Context, *pantherclawv1.CreateGatewayRequest) (*pantherclawv1.CreateGatewayResponse, error)
	ListGateways(context.Context, *pantherclawv1.ListGatewaysRequest) (*pantherclawv1.ListGatewaysResponse, error)
	CreateGatewayEnrollmentToken(context.Context, *pantherclawv1.CreateGatewayEnrollmentTokenRequest) (*pantherclawv1.CreateGatewayEnrollmentTokenResponse, error)
}

// gateway starts gateway "local" once it exists; otherwise, with a pclaw
// session on this node's server and org, creates it, writes its enrollment
// and starts it (D39). The gateway enrolls with that single-use token the
// first time and keeps its identity in the gatewaydata volume; delete
// secrets/gateway-enroll.json to enroll it again. It returns the line to
// print.
func (n *node) gateway(ctx context.Context, st *nodeState) (string, error) {
	_, enrollErr := os.Stat(filepath.Join(n.dir, nodeSecretsDir, nodeEnrollFile))
	if st.GatewayID == "" || enrollErr != nil {
		admin, why := n.gatewayAdmin(*st)
		if admin == nil {
			return why, nil
		}
		if err := n.enrollGateway(ctx, admin, st); err != nil {
			if connect.CodeOf(err) == connect.CodePermissionDenied {
				return "gateway: not enrolled: creating it needs the gateway_admin role " +
					"(pclaw role bind --role gateway_admin --user <your user id>), then run pclaw up again", nil
			}
			return "", err
		}
		if err := n.initSecrets(ctx); err != nil {
			return "", err
		}
	}
	if err := n.compose(ctx, n.a.stderr, "--profile", "gateway", "up", "--detach", "gateway"); err != nil {
		return "", err
	}
	return fmt.Sprintf("gateway: http://localhost:%d (gateway %q)", st.GatewayPort, nodeGatewayName), nil
}

// gatewayAdmin returns a client signed in to this node's server and org,
// or nil and what to do.
func (n *node) gatewayAdmin(st nodeState) (gatewayAdmin, string) {
	later := "gateway: not enrolled yet: sign in (pclaw login, above), then run pclaw up again to enroll the gateway"
	if nodeGatewayAdminHook != nil {
		return nodeGatewayAdminHook, ""
	}
	s, err := n.a.session()
	if err != nil {
		return nil, later
	}
	if s.apiKey == "" && (s.creds.Org != st.Org || !sameServer(s.server, nodePublicURL(st))) {
		return nil, later
	}
	if s.apiKey != "" && !sameServer(s.server, nodePublicURL(st)) {
		return nil, later
	}
	return pantherclawv1connect.NewGatewayAdminServiceClient(s.connect()), ""
}

// nodeGatewayAdminHook replaces the session's client in tests.
var nodeGatewayAdminHook gatewayAdmin

// sameServer compares base URLs, treating localhost and 127.0.0.1 alike.
func sameServer(a, b string) bool {
	norm := func(s string) string {
		return strings.Replace(strings.TrimRight(s, "/"), "://127.0.0.1:", "://localhost:", 1)
	}
	return norm(a) == norm(b)
}

// enrollGateway finds or creates gateway "local" and writes a fresh
// enrollment (a single-use token valid 15 minutes).
func (n *node) enrollGateway(ctx context.Context, admin gatewayAdmin, st *nodeState) error {
	id := ""
	tok := ""
	for {
		res, err := admin.ListGateways(ctx, &pantherclawv1.ListGatewaysRequest{PageSize: 200, PageToken: tok})
		if err != nil {
			return fmt.Errorf("pclaw: list gateways: %w", err)
		}
		for _, g := range res.GetGateways() {
			if g.GetName() == nodeGatewayName {
				id = g.GetId()
			}
		}
		if tok = res.GetNextPageToken(); tok == "" || id != "" {
			break
		}
	}
	if id == "" {
		res, err := admin.CreateGateway(ctx, &pantherclawv1.CreateGatewayRequest{Name: nodeGatewayName})
		if err != nil {
			return fmt.Errorf("pclaw: create gateway %q: %w", nodeGatewayName, err)
		}
		id = res.GetGateway().GetId()
	}
	res, err := admin.CreateGatewayEnrollmentToken(ctx, &pantherclawv1.CreateGatewayEnrollmentTokenRequest{GatewayId: id})
	if err != nil {
		return fmt.Errorf("pclaw: gateway enrollment token: %w", err)
	}
	b, err := nodeEnrollJSON(res.GetToken(), res.GetCaSha256())
	if err != nil {
		return err
	}
	if err := writeNodeFile(filepath.Join(n.dir, nodeSecretsDir, nodeEnrollFile), b, 0o600); err != nil {
		return err
	}
	st.GatewayID = id
	return saveNodeState(n.dir, *st)
}

func (n *node) printUp(st nodeState, token, gatewayLine string) {
	w := n.a.stdout
	url := nodePublicURL(st)
	_, _ = fmt.Fprintf(w, "\nPantherClaw is up: %s (deployment %s, organization %s)\n", url, st.Deployment, st.Org)
	if token != "" {
		_, _ = fmt.Fprintf(w, "\nThe first administrator signs in with this one-time token (shown only now; valid 24 hours):\n"+
			"  pclaw login --server %s --org %s --invitation %s\n", url, st.Org, token)
	}
	if st.OIDC == nil {
		_, _ = fmt.Fprintf(w, "\nNobody can sign in yet: add your OpenID provider and run pclaw up again:\n"+
			"  pclaw up --oidc-issuer https://idp.example.com --oidc-client-id ID --oidc-client-secret-file FILE [--oidc-name sso]\n"+
			"Register %s/oauth2/callback/<name> at the provider as the redirect URI.", url)
		if st.Deployment == nodeDeploymentDev {
			_, _ = fmt.Fprint(w, " For a try-out without one, run the server from a checkout with go run ./test/devoidc (docs/BUILD_GUIDE.md §4).")
		}
		_, _ = fmt.Fprintln(w)
		if token != "" {
			_, _ = fmt.Fprintf(w, "Lost the token? docker compose --file %s run --rm --no-deps server org admin-invite --org %s --config /node/server.json\n",
				filepath.Join(n.dir, nodeComposeFile), st.Org)
		}
	} else {
		_, _ = fmt.Fprintf(w, "Sign-in: %s (redirect URI %s/oauth2/callback/%s)\n", st.OIDC.Issuer, url, st.OIDC.Name)
	}
	_, _ = fmt.Fprintln(w, gatewayLine)
	_, _ = fmt.Fprintf(w, "Files: %s · pclaw status · pclaw down\n", n.dir)
}
