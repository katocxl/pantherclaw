// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package server wires pantherclaw-server: the control plane (API role),
// background workers (worker role), migrations and database bootstrap.
// cmd/pantherclaw-server only calls Run.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/agents/adapters/agentsrpc"
	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/accountrpc"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/devicehttp"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/oauthhttp"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/billing/licence"
	"github.com/katocxl/pantherclaw/internal/definitions/adapters/packagesrpc"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/evidence/chainer"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/facts/adapters/factsrpc"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	factsapp "github.com/katocxl/pantherclaw/internal/facts/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/grants/adapters/grantsrpc"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/identityrpc"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/issuerkeys"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/notifications/adapters/notificationsrpc"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/policy/adapters/policiesrpc"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/runs/adapters/runsrpc"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	"github.com/katocxl/pantherclaw/internal/tenancy/adapters/tenancyrpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

const usage = `pantherclaw-server — PantherClaw control plane

Usage:
  pantherclaw-server serve [--config FILE]            run the API and/or workers (role from config)
  pantherclaw-server migrate up|status [--config FILE] apply or show schema migrations (as pc_migrator)
  pantherclaw-server db bootstrap --admin-url-file F --app-password-file F --migrator-password-file F --audit-password-file F
                                 --retention-password-file F
                                                     create roles and schema once, as the database owner
  pantherclaw-server keys gen-kek --out FILE          write a new key-encryption key (0600)
  pantherclaw-server keys rotate-gateway-ca --confirm [--config FILE]
                                                     replace the internal gateway CA key; every gateway enrolls again
  pantherclaw-server org create --name N [--admin-email E] [--config FILE]
                                                     create an organization and print its one-time admin token
  pantherclaw-server org admin-invite --org ID [--admin-email E] [--config FILE]
                                                     issue a new one-time admin token (recovery)
  pantherclaw-server evidence integrity reset --org ID --reason TEXT --confirm [--config FILE]
                                                     resume checkpointing of an org whose evidence integrity FAILED,
                                                     after investigating; its ledger is checked again
  pantherclaw-server dev seed [--config FILE] [--org-name N] [--budget-limit X] [--max-count N] [--gateway-out FILE
                             [--target-url URL [--access-mode M]] [--shell]] [--workload-out FILE [--facts-key-out FILE]]
                             [--hold-over AMOUNT]
                                                     DEVELOPMENT ONLY: demo org with the reference package; a gateway
                                                     enrollment file and a payments connection; a workload with a grant,
                                                     a run and a fact provider; a policy holding refunds over
                                                     --hold-over (default 50.00, empty for none) for an approver
  pantherclaw-server dev gateway --org ID --out FILE [--config FILE] [--name NAME]
                                                     DEVELOPMENT ONLY: a gateway enrollment file for an existing org
  pantherclaw-server dev connection --org ID --target-url URL [--config FILE] [--gateway NAME] [--name N] [--mode M]
                             [--access-mode M]
                                                     DEVELOPMENT ONLY: a payments connection for an existing gateway
  pantherclaw-server version

Configuration: JSON file plus PC_* environment variables; secrets only as file paths.
`

// Env reads environment variables (os.LookupEnv in production).
type Env = config.LookupEnv

// Run executes pantherclaw-server; ctx is canceled on SIGINT/SIGTERM.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "version", "--version":
		_, _ = fmt.Fprintln(stdout, version.Get().String("pantherclaw-server"))
		return 0
	case "serve":
		err = cmdServe(ctx, args[1:], stderr, env, nil)
	case "migrate":
		err = cmdMigrate(ctx, args[1:], stdout, stderr, env)
	case "db":
		err = cmdDB(ctx, args[1:], stdout, stderr)
	case "keys":
		err = cmdKeys(ctx, args[1:], stdout, stderr, env)
	case "org":
		err = cmdOrg(ctx, args[1:], stdout, stderr, env)
	case "evidence":
		err = cmdEvidence(ctx, args[1:], stdout, stderr, env)
	case "dev":
		err = cmdDev(ctx, args[1:], stdout, stderr, env)
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp), errors.Is(err, errUsage):
		return 2
	default:
		_, _ = fmt.Fprintf(stderr, "pantherclaw-server: %v\n", err)
		return 1
	}
}

var errUsage = errors.New("usage")

func loadConfig(args []string, stderr io.Writer, env Env, name string) (*Config, []string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "JSON configuration file")
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	cfg := DefaultConfig()
	if err := config.Load(&cfg, *path, env); err != nil {
		return nil, nil, err
	}
	return &cfg, fs.Args(), nil
}

func newLogger(cfg *Config, w io.Writer) *slog.Logger {
	level, _ := pclog.ParseLevel(cfg.Log.Level)
	return pclog.New(w, pclog.Options{Service: "pantherclaw-server", Version: version.Get().Version, Level: level})
}

// started reports the bound API address to tests (nil in production).
type started func(apiAddr string)

func cmdServe(ctx context.Context, args []string, stderr io.Writer, env Env, onStart started) error {
	cfg, rest, err := loadConfig(args, stderr, env, "serve")
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errUsage
	}
	log := newLogger(cfg, stderr)
	appCfg, err := cfg.dbConfig(cfg.DB.AppUser, cfg.DB.AppPasswordFile, cfg.DB.MaxConns)
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, appCfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	kp, err := keys.NewFileProvider(cfg.KEKFiles)
	if err != nil {
		return err
	}
	bill, err := applyLicence(ctx, cfg, pool, log)
	if err != nil {
		return err
	}
	ents, err := bill.Current(ctx)
	if err != nil {
		return err
	}
	if err := cfg.checkEvidenceEdition(ents); err != nil {
		return err
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, pool, kp, reg, cfg.evidenceKeyPurposes()...); err != nil {
		return err
	}

	svc, err := newAuthority(cfg, pool, reg, kp, log)
	if err != nil {
		return err
	}
	m5, err := newM5(ctx, cfg, pool, kp, bill, log)
	if err != nil {
		return err
	}
	m6, err := newM6(cfg, pool, reg, m5.notifications, log)
	if err != nil {
		return err
	}
	m5p2, err := newM5p2(cfg, pool, bill, m5.notifications, log)
	if err != nil {
		return err
	}
	verification, err := newVerification(pool, reg, m5.notifications)
	if err != nil {
		return err
	}
	m6.verifications = verification

	g, ctx := errgroup.WithContext(ctx)
	if cfg.Role == RoleAPI || cfg.Role == RoleAll {
		tokens, err := token.New(reg, cfg.Auth.PublicURL, token.Audience)
		if err != nil {
			return err
		}
		authn, err := authnapp.NewAuthenticator(pool, tokens, credential.Env(cfg.Auth.APIKeyEnv), clock.System{}, log)
		if err != nil {
			return err
		}
		clusters, err := kube.NewDirectory(cfg.Identity.KubernetesClusters)
		if err != nil {
			return err
		}
		provs, err := cfg.oidcProviders()
		if err != nil {
			return err
		}
		idps := make([]authnapp.IdP, 0, len(provs))
		var subjects oidcrp.Subjects
		for i, p := range provs {
			idps = append(idps, p)
			if cfg.Auth.OIDCProviders[i].SubjectTokenAudience != "" {
				subjects = append(subjects, p)
			}
		}
		limiter := httpx.NewLimiter(oauthRateLimit, time.Minute, nil)
		proxies, err := cfg.trustedProxies()
		if err != nil {
			return err
		}
		if len(proxies) > 0 {
			limiter.WithClientIP(httpx.TrustedProxyClientIP(proxies))
		} else if cfg.HTTP.PlaintextBehindProxy {
			log.WarnContext(ctx, "server.no_trusted_proxies", slog.String("note",
				"behind a proxy without http.trusted_proxies: sign-in rate limits are shared by all clients of the proxy"))
		}
		device, err := devicehttp.New(authnapp.NewDevice(pool, tokens, cfg.Auth.PublicURL, idps, clock.System{}, log),
			cfg.Auth.PublicURL, limiter, log)
		if err != nil {
			return err
		}
		web, err := m5.web(cfg, pool, idps, limiter, log)
		if err != nil {
			return err
		}
		m6.mountPages(web)
		m5p2.mountPages(web, m5)
		mountM7Pages(web, pool, verification, m5)
		device.WithBrowserCallback(web.Callback)
		roots, err := packageRoots(ctx, cfg, log)
		if err != nil {
			return err
		}
		handler, err := apiHandler(apiDeps{
			pool: pool, reg: reg, log: log, authority: svc, billing: bill,
			auth:      rpcauth.New(authn, procedurePermissions, nil),
			apiKeyEnv: credential.Env(cfg.Auth.APIKeyEnv),
			oauth: oauthhttp.New(authnapp.NewOAuth(pool, tokens, cfg.Auth.PublicURL, clock.System{}, log),
				cfg.Auth.PublicURL, limiter),
			device:    device,
			publicURL: cfg.Auth.PublicURL, clientIP: limiter.ClientIP, clusters: clusters, subjects: subjects,
			logOrigin:    cfg.logOrigin(),
			packageRoots: roots,
			web:          web,
			m5:           m5,
			m6:           m6,
			m5p2:         m5p2,
			verification: verification,
			kp:           kp,
		})
		if err != nil {
			return err
		}
		if err := m6.serveGateways(ctx, g, cfg, svc, log, nil); err != nil {
			return err
		}
		srv, ln, err := listen(ctx, cfg, handler, log)
		if err != nil {
			return err
		}
		if onStart != nil {
			onStart(ln.Addr().String())
		}
		log.InfoContext(ctx, "server.listening", slog.String("addr", ln.Addr().String()), slog.String("role", cfg.Role))
		m5p2.serveWaits(ctx, g)
		g.Go(func() error {
			var err error
			if srv.TLSConfig != nil {
				err = srv.ServeTLS(ln, "", "")
			} else {
				err = srv.Serve(ln)
			}
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		})
		g.Go(func() error {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
			defer cancel()
			return srv.Shutdown(sctx)
		})
	}
	if cfg.Role == RoleWorker || cfg.Role == RoleAll {
		jreg := jobs.NewRegistry()
		if err := chainer.Register(jreg, pool); err != nil {
			return err
		}
		if err := authority.RegisterSweeper(jreg, pool, svc, cfg.Authority.StaleDispatch.D()); err != nil {
			return err
		}
		evidenceJobs, err := registerEvidenceWorkers(jreg, cfg, pool, reg, m5.notifications, log)
		if err != nil {
			return err
		}
		retentionJobs, closeRetention, err := registerRetention(ctx, jreg, cfg, pool, log)
		if err != nil {
			return err
		}
		defer closeRetention()
		evidenceJobs = append(evidenceJobs, retentionJobs...)
		if err := authnapp.RegisterJanitor(jreg, pool, log); err != nil {
			return err
		}
		if err := iapp.RegisterJanitor(jreg, pool, log); err != nil {
			return err
		}
		if err := m5.registerWorkers(jreg); err != nil {
			return err
		}
		if err := m5p2.registerWorkers(jreg, log); err != nil {
			return err
		}
		if err := txapp.Register(jreg, pool, verification); err != nil {
			return err
		}
		client, err := jobs.NewClient(pool, jreg, jobs.Config{
			Queues: map[string]int{river.QueueDefault: cfg.WorkerConcurrency, napp.Queue: cfg.Notifications.Concurrency},
			PeriodicJobs: slices.Concat(chainer.PeriodicJobs(), authority.SweeperPeriodicJobs(), authnapp.JanitorPeriodicJobs(),
				iapp.JanitorPeriodicJobs(), napp.PeriodicJobs(), m5p2.periodicJobs(), txapp.PeriodicJobs()),
			Logger: log,
		})
		if err != nil {
			return err
		}
		client.PeriodicJobs().AddMany(evidenceJobs)
		if err := client.Start(ctx); err != nil {
			return fmt.Errorf("server: start workers: %w", err)
		}
		log.InfoContext(ctx, "server.workers_started", slog.Int("concurrency", cfg.WorkerConcurrency))
		g.Go(func() error {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
			defer cancel()
			return client.Stop(sctx)
		})
	}
	err = g.Wait()
	log.InfoContext(context.WithoutCancel(ctx), "server.stopped")
	return err
}

func listen(ctx context.Context, cfg *Config, handler http.Handler, log *slog.Logger) (*http.Server, net.Listener, error) {
	var tlsConf *tls.Config
	if cfg.HTTP.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.HTTP.TLSCertFile, cfg.HTTP.TLSKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("server: TLS key pair: %w", err)
		}
		tlsConf = httpx.ServerTLSConfig(cert)
	}
	srv, err := httpx.NewServer(httpx.ServerConfig{
		Addr: cfg.HTTP.Addr, Handler: handler, TLS: tlsConf,
		PlaintextBehindProxy: cfg.HTTP.PlaintextBehindProxy, Logger: log,
	})
	if err != nil {
		return nil, nil, err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.HTTP.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("server: listen: %w", err)
	}
	return srv, ln, nil
}

// publicProcedures run without authentication; each is declared
// "permission: public" in its proto (tested).
func publicProcedures() []string {
	return []string{pantherclawv1connect.SystemServiceGetBuildInfoProcedure}
}

// apiDeps are the API role's dependencies. auth authenticates users,
// service accounts and API keys. Gateway procedures are refused here: gateways
// call the Authority only on the mTLS gateway listener (HR-181).
type apiDeps struct {
	pool      *db.Pool
	reg       *keys.Registry
	log       *slog.Logger
	authority *authority.Service
	billing   *billing.Service
	auth      rpc.Authenticator
	apiKeyEnv credential.Env
	oauth     *oauthhttp.Handler
	device    *devicehttp.Handler
	// publicURL is the server's external base URL (PAP/1 htu and token iss).
	publicURL string
	// logOrigin names the evidence log (evidence.log_origin).
	logOrigin string
	// clientIP resolves client addresses behind trusted proxies.
	clientIP httpx.ClientIPFunc
	// clusters are the configured Kubernetes clusters (identity.kubernetes_clusters).
	clusters *kube.Directory
	// subjects are the providers configured for subject tokens (HR-145).
	subjects oidcrp.Subjects
	// packageRoots are the trusted package roots (nil: the embedded ones).
	packageRoots trust.Roots
	// M5 part 1: browser pages, accounts, notifications.
	web *webhttp.Handler
	m5  *m5Services
	// M6: gateway identity.
	m6 *m6Services
	// M5 part 2: approvals, the waitlist and wait handles.
	m5p2 *m5p2Services
	// M7: verification signs the effect receipts people's actions append.
	verification *txapp.Service
	// kp opens sealed evaluation inputs for decision replay (M7 track B).
	kp keys.KeyProvider
}

// apiHandler mounts the RPC services, health endpoints and the JWKS.
func apiHandler(d apiDeps) (http.Handler, error) {
	pool, reg, log := d.pool, d.reg, d.log
	rs, err := rpc.NewServer(rpc.Options{
		Logger:       log,
		Public:       publicProcedures(),
		Authenticate: d.auth,
	})
	if err != nil {
		return nil, err
	}
	pantherclawv1connect.RegisterSystemServiceHandler(rs, systemService{})
	pantherclawv1connect.RegisterAuthorityServiceHandler(rs, authority.NewHandler(d.authority))
	pantherclawv1connect.RegisterTenancyServiceHandler(rs, tenancyrpc.NewTenancy(tapp.NewHierarchy(pool, d.billing)))
	pantherclawv1connect.RegisterAccessServiceHandler(rs, tenancyrpc.NewAccess(tapp.NewAccess(pool, log)))
	pantherclawv1connect.RegisterServiceAccountServiceHandler(rs, tenancyrpc.NewServiceAccounts(tapp.NewServiceAccounts(pool, d.apiKeyEnv)))
	pantherclawv1connect.RegisterAgentServiceHandler(rs, d.m5p2.agents(agentsrpc.NewAgents(aapp.NewInventory(pool, d.billing))))
	pantherclawv1connect.RegisterWaitlistServiceHandler(rs, d.m5p2.waitlist())
	attestors, err := newAttestors(d.clusters)
	if err != nil {
		return nil, err
	}
	identity := iapp.New(pool, reg, d.publicURL, clock.System{}).WithAttestors(attestors)
	pantherclawv1connect.RegisterIdentityServiceHandler(rs, identityrpc.NewIdentity(identity, d.clusters))
	gstore := &grantspg.Store{Pool: pool}
	grants := &grantsapp.Service{
		Repo: gstore, Subjects: gstore, Defs: &defspg.Store{Pool: pool}, Authz: grantsapp.SubjectAuthorizer{},
		Clock: clock.System{}, Listing: gstore,
	}
	runs := runsapp.New(pool).WithGrants(gstore)
	if len(d.subjects) > 0 {
		runs.WithSubjects(d.subjects)
	}
	pantherclawv1connect.RegisterRunServiceHandler(rs, runsrpc.NewRuns(runs))
	d.authority.WithWorkloads(identity, runs)
	workload := d.m5p2.workload(workloadrpc.NewWorkload(identity, runs, d.publicURL, clock.System{}).WithGrants(grants))
	pantherclawv1connect.RegisterWorkloadServiceHandler(rs, workload)
	if err := registerAuthorityAdmin(rs, d, grants); err != nil {
		return nil, err
	}
	if d.m5 != nil {
		pantherclawv1connect.RegisterAccountServiceHandler(rs, accountrpc.New(authnapp.NewAccount(pool, d.m5.webauthn, d.m5.notifications)))
		pantherclawv1connect.RegisterNotificationServiceHandler(rs, notificationsrpc.New(d.m5.notifications))
	}
	d.m6.registerPublic(rs)
	d.m5p2.registerPublic(rs)
	registerM7(rs, pool, d.verification)
	registerEvidence(rs, d)
	registerEvidenceAdmin(rs, d)
	mux := http.NewServeMux()
	rpc.Mount(mux, rs)
	d.m5p2.mount(mux, workload)
	d.oauth.Mount(mux)
	d.device.Mount(mux, d.oauth)
	if d.web != nil {
		d.web.Mount(mux)
	}
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		err := pool.InGlobalTx(ctx, db.GlobalHealth, func(ctx context.Context, tx db.GlobalTx) error {
			var one int
			return tx.QueryRow(ctx, "SELECT 1").Scan(&one)
		}, db.ReadOnly())
		if err != nil {
			log.WarnContext(ctx, "server.not_ready", pclog.Err(err))
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("GET /.well-known/pantherclaw/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		b, err := reg.JWKS()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(b)
	})
	mountEvidenceKeys(mux, d)
	return workloadrpc.RawBody(mux, d.clientIP), nil
}

// attestTimeout bounds one call to an issuer or a cluster API server.
const attestTimeout = 10 * time.Second

// newAttestors returns the L2 verifiers: GitHub keys through the egress
// client (public addresses only) and the configured clusters (HR-142).
func newAttestors(clusters *kube.Directory) (iapp.Attestors, error) {
	gh, err := issuerkeys.New(httpx.NewEgressClient(httpx.EgressConfig{Timeout: attestTimeout}), issuers.GitHubIssuer, nil)
	if err != nil {
		return iapp.Attestors{}, err
	}
	kc, err := kube.NewClient(clusters, attestTimeout)
	if err != nil {
		return iapp.Attestors{}, err
	}
	return iapp.Attestors{GitHub: gh, Kube: kc, Clusters: clusters}, nil
}

// startupActor records start-up actions in the audit log.
var startupActor = evdomain.Actor{Type: "system", ID: "server-startup"}

func applyLicence(ctx context.Context, cfg *Config, pool *db.Pool, log *slog.Logger) (*billing.Service, error) {
	roots, err := licence.EmbeddedRoots()
	if err != nil {
		return nil, err
	}
	svc := billing.New(pool, roots, clock.System{}, log)
	if cfg.LicenceFile != "" {
		doc, err := os.ReadFile(cfg.LicenceFile)
		if err != nil {
			return nil, fmt.Errorf("server: licence file: %w", err)
		}
		// An invalid licence is recorded and audited, and the server keeps
		// running with Community limits (founder decision 2026-10-08).
		if _, err := svc.Install(ctx, doc, startupActor); err != nil && !errors.Is(err, licence.ErrInvalid) {
			return nil, err
		}
	}
	e, err := svc.Current(ctx)
	if err != nil {
		return nil, err
	}
	log.InfoContext(ctx, "licence.status", slog.String("edition", string(e.Edition)), slog.String("status", string(e.Status)),
		slog.Int("max_agents", e.Limits.MaxAgents), slog.Int("max_orgs", e.Limits.MaxOrgs))
	return svc, nil
}

func cmdMigrate(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return errUsage
	}
	sub := args[0]
	cfg, rest, err := loadConfig(args[1:], stderr, env, "migrate "+sub)
	if err != nil {
		return err
	}
	if len(rest) != 0 || cfg.DB.MigratorPasswordFile == "" {
		_, _ = fmt.Fprintln(stderr, "migrate needs database.migrator_password_file")
		return errUsage
	}
	mc, err := cfg.dbConfig(cfg.DB.MigratorUser, cfg.DB.MigratorPasswordFile, 2)
	if err != nil {
		return err
	}
	switch sub {
	case "up":
		res, err := db.Migrate(ctx, mc)
		if err != nil {
			return err
		}
		for _, r := range res {
			_, _ = fmt.Fprintf(stdout, "applied %d %s\n", r.Version, r.Source)
		}
		v, err := db.MigrationVersion(ctx, mc)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "schema version %d\n", v)
		return nil
	case "status":
		v, err := db.MigrationVersion(ctx, mc)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "schema version %d\n", v)
		return nil
	default:
		return errUsage
	}
}

func cmdDB(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "bootstrap" {
		_, _ = fmt.Fprint(stderr, usage)
		return errUsage
	}
	fs := flag.NewFlagSet("db bootstrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	adminURL := fs.String("admin-url-file", "", "file holding the owner/superuser connection URL for the target database")
	appPW := fs.String("app-password-file", "", "password file for pc_app")
	migPW := fs.String("migrator-password-file", "", "password file for pc_migrator")
	auditPW := fs.String("audit-password-file", "", "password file for pc_audit_ro")
	retentionPW := fs.String("retention-password-file", "", "password file for pc_retention (the retention job's role)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *adminURL == "" || *appPW == "" || *migPW == "" || *auditPW == "" || *retentionPW == "" || fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	url, err := config.ReadSecretFile(*adminURL)
	if err != nil {
		return err
	}
	var pw db.RolePasswords
	for dst, path := range map[*pclog.Secret[[]byte]]string{
		&pw.App: *appPW, &pw.Migrator: *migPW, &pw.AuditRO: *auditPW, &pw.Retention: *retentionPW,
	} {
		s, err := config.ReadSecretFile(path)
		if err != nil {
			return err
		}
		*dst = s
	}
	cc, err := pgx.ParseConfig(string(url.Reveal()))
	if err != nil {
		return errors.New("db bootstrap: admin URL does not parse")
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return fmt.Errorf("db bootstrap: connect: %w", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if err := db.BootstrapRoles(ctx, conn, pw); err != nil {
		return err
	}
	if err := db.BootstrapDatabase(ctx, conn); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "bootstrapped roles %s, %s, %s, %s, %s and schema %s in database %s\n",
		db.RoleMigrator, db.RoleApp, db.RoleAuditRO, db.RoleRetention, db.RoleLister, db.Schema, cc.Database)
	return nil
}

func cmdKeys(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) > 0 && args[0] == "rotate-gateway-ca" {
		return cmdRotateGatewayCA(ctx, args[1:], stdout, stderr, env)
	}
	if len(args) == 0 || args[0] != "gen-kek" {
		_, _ = fmt.Fprint(stderr, usage)
		return errUsage
	}
	fs := flag.NewFlagSet("keys gen-kek", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "output file (created with mode 0600, never overwritten)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	if err := keys.GenerateKEKFile(*out); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "wrote key-encryption key to %s; keep it outside the repository and back it up securely\n", *out)
	return nil
}

// registerAuthorityAdmin mounts the M4 administration services: grants,
// guardrails, facts, packages and policies. Every one checks its caller's
// permissions in its use cases; human-only steps refuse service accounts
// and API keys (HR-161).
func registerAuthorityAdmin(rs *connect.Server, d apiDeps, grants *grantsapp.Service) error {
	authz := grantsapp.SubjectAuthorizer{}
	defs := &defspg.Store{Pool: d.pool}
	facts := &factspg.Store{Pool: d.pool}
	pantherclawv1connect.RegisterGrantServiceHandler(rs, grantsrpc.NewGrants(grants))
	pantherclawv1connect.RegisterGuardrailServiceHandler(rs, grantsrpc.NewGuardrails(grants))
	pantherclawv1connect.RegisterFactServiceHandler(rs, factsrpc.New(&factsapp.Service{Store: facts, Authz: authz, Reads: facts}))
	roots := d.packageRoots
	if roots == nil {
		var err error
		if roots, err = trust.EmbeddedRoots(); err != nil {
			return err
		}
	}
	pantherclawv1connect.RegisterPackageServiceHandler(rs, packagesrpc.New(&defsapp.Admin{
		Importer: &defsapp.Importer{Roots: roots, Repo: defs, Keys: defs, Clock: clock.System{}}, Reads: defs, Authz: authz,
		Ents: d.billing,
	}))
	pantherclawv1connect.RegisterPolicyServiceHandler(rs, policiesrpc.New(&policyapp.Versions{
		Store: &polpg.Store{Pool: d.pool}, Facts: facts, Definitions: defs, Authz: authz, Limits: celenv.DefaultLimits,
	}))
	return nil
}
