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
	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/billing/licence"
	coverage "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/datarequests"
	"github.com/katocxl/pantherclaw/internal/definitions/adapters/packagesrpc"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/evidence/chainer"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/extension"
	"github.com/katocxl/pantherclaw/internal/externalchecks"
	"github.com/katocxl/pantherclaw/internal/facts/adapters/factsrpc"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	factsapp "github.com/katocxl/pantherclaw/internal/facts/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	githubapp "github.com/katocxl/pantherclaw/internal/github/app"
	"github.com/katocxl/pantherclaw/internal/grants/adapters/grantsrpc"
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
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/runs/adapters/runsrpc"
	"github.com/katocxl/pantherclaw/internal/tenancy/adapters/tenancyrpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tsapp "github.com/katocxl/pantherclaw/internal/ticketsync/app"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

const usage = `pantherclaw-server — PantherClaw control plane

Usage:
  pantherclaw-server serve [--config FILE]            run the API and/or workers (role from config)
  pantherclaw-server migrate up|status [--config FILE] apply or show schema migrations (as pc_migrator)
  pantherclaw-server db bootstrap --admin-url-file F --app-password-file F --migrator-password-file F --audit-password-file F
                                 --retention-password-file F [--backup-password-file F] [--deleter-password-file F] [--keystore-password-file F]
                                                     create roles and schema once, as the database owner; with
                                                     --backup-password-file also the read-only backup role pc_backup;
                                                     --deleter-password-file also the org deletion role pc_deleter;
                                                     --keystore-password-file also the key re-wrap role pc_keystore
  pantherclaw-server keys gen-kek --out FILE          write a new key-encryption key (0600)
  pantherclaw-server keys rotate-gateway-ca --confirm [--config FILE]
                                                     replace the internal gateway CA key; every gateway enrolls again
  pantherclaw-server keys rotate-receipts --confirm [--config FILE]
  pantherclaw-server keys rotate-evidence --confirm [--config FILE]
                                                     new receipts / evidence signing keys; earlier keys stay
                                                     published and verifying; restart every server instance after
  pantherclaw-server keys bump-epochs --all --confirm [--config FILE]
                                                     after restore: raise every non-DELETED org's containment epoch
  pantherclaw-server security-log export --org ID --out FILE [--after SEQ] [--limit 1..500] [--config FILE]
  pantherclaw-server security-log ack --org ID --through SEQ --confirm [--config FILE]
                                                     ACK only after verifying the prefix has a durable external copy
  pantherclaw-server restore reapply --from FILE [--since RFC3339] --confirm [--config FILE]
                                                     re-apply shipped tightening events while maintenance hold is on
  pantherclaw-server org create --name N [--admin-email E] [--config FILE]
                                                     create an organization and print its one-time admin token
  pantherclaw-server org admin-invite --org ID [--admin-email E] [--config FILE]
                                                     issue a new one-time admin token (recovery)
  pantherclaw-server org plan grant --org ID --plan P --until RFC3339 --reason TEXT [--edition E] [--config FILE]
                                                     give an org a complimentary plan (at most a year; audited)
  pantherclaw-server org plan revoke --org ID --reason TEXT [--config FILE]
                                                     end an org's complimentary plan now
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
  pantherclaw-server hosting add-host --name N --domain D --capacity N --milli-cpus N --memory-mib N
                             --csr FILE --bundle-out FILE [--config FILE]
                                                     record a shared hosting host and issue its agent certificate
  pantherclaw-server secrets stage --from DIR --to DIR
                                                     copy each regular file of DIR as a 0400 secret file
                                                     (Kubernetes init container; symlinks and others refused)
  pantherclaw-server version

Configuration: JSON file plus PC_* environment variables; secrets only as file paths.
`

// Env reads environment variables (os.LookupEnv in production).
type Env = config.LookupEnv

// Run executes pantherclaw-server without extensions; ctx is canceled on
// SIGINT/SIGTERM.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) int {
	return RunCommand(ctx, args, stdout, stderr, env, extension.Set{})
}

// RunCommand executes pantherclaw-server with ext added to `serve`
// (internal/extension); every other subcommand ignores it.
func RunCommand(ctx context.Context, args []string, stdout, stderr io.Writer, env Env, ext extension.Set) int {
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
		err = cmdServeWith(ctx, args[1:], stderr, env, nil, ext)
	case "migrate":
		err = cmdMigrate(ctx, args[1:], stdout, stderr, env)
	case "db":
		err = cmdDB(ctx, args[1:], stdout, stderr)
	case "keys":
		err = cmdKeys(ctx, args[1:], stdout, stderr, env)
	case "security-log":
		err = cmdSecurityLog(ctx, args[1:], stdout, stderr, env)
	case "restore":
		err = cmdRestore(ctx, args[1:], stdout, stderr, env)
	case "org":
		err = cmdOrg(ctx, args[1:], stdout, stderr, env)
	case "evidence":
		err = cmdEvidence(ctx, args[1:], stdout, stderr, env)
	case "hosting":
		err = cmdHosting(ctx, args[1:], stdout, stderr, env)
	case "dev":
		err = cmdDev(ctx, args[1:], stdout, stderr, env)
	case "secrets":
		// The Helm chart's init container (G0 M13 D42).
		err = config.StageSecretsCommand("pantherclaw-server", args[1:], stdout, stderr)
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
	return pclog.New(w, pclog.Options{
		Service: "pantherclaw-server", Version: version.Get().Version, Level: level,
		// Records written inside a traced request carry its trace and span
		// ids (G0 M13 D30).
		ContextAttrs: []func(context.Context) []slog.Attr{telemetry.LogAttrs},
	})
}

// started reports the bound API address to tests (nil in production).
type started func(apiAddr string)

func cmdServeWith(ctx context.Context, args []string, stderr io.Writer, env Env, onStart started, ext extension.Set) error {
	cfg, rest, err := loadConfig(args, stderr, env, "serve")
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errUsage
	}
	return runServe(ctx, cfg, stderr, onStart, ext)
}

// RunWith serves cfg with ext added (internal/extension), logging to
// stderr, until ctx is canceled. cfg is validated first.
func RunWith(ctx context.Context, cfg *Config, ext extension.Set) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	return runServe(ctx, cfg, os.Stderr, nil, ext)
}

func runServe(ctx context.Context, cfg *Config, stderr io.Writer, onStart started, ext extension.Set) error {
	log := newLogger(cfg, stderr)
	if err := cfg.checkDeploymentFor(ext); err != nil {
		return err
	}
	xdeps := extensionDeps(cfg, log)
	if err := validateExtension(ext, xdeps); err != nil {
		return err
	}
	tel, err := startTelemetry(cfg, log) //nolint:contextcheck // the span exporter goroutine outlives this call by design; Shutdown bounds it
	if err != nil {
		return err
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		_ = tel.Shutdown(sctx)
	}()
	appCfg, err := cfg.dbConfig(cfg.DB.AppUser, cfg.DB.AppPasswordFile, cfg.DB.MaxConns)
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, withQueryTracer(appCfg, tel))
	if err != nil {
		return err
	}
	defer pool.Close()
	observePool(pool)
	if err := checkSchemaAtStart(ctx, cfg, pool, log); err != nil {
		return err
	}
	if err := holdAfterPromotion(ctx, cfg, pool, log); err != nil {
		return err
	}
	workers := newWorkerHeartbeat(cfg.Role)

	kp, err := newCheckedKeyProvider(ctx, cfg, pool)
	if err != nil {
		return err
	}
	bill, err := applyLicence(ctx, cfg, pool, log)
	if err != nil {
		return err
	}
	entsSvc, err := newEntitlements(cfg, pool, bill, log)
	if err != nil {
		return err
	}
	ui := newUITenancy(cfg, pool, entsSvc)
	ents, err := bill.Current(ctx)
	if err != nil {
		return err
	}
	applyFIPSMode(ctx, cfg, log)
	if err := cfg.checkEvidenceEdition(ents); err != nil {
		return err
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, pool, kp, reg, cfg.evidenceKeyPurposes()...); err != nil {
		return err
	}

	authorityStore := &pgauthority.Store{Pool: pool, LockTimeout: cfg.Authority.BudgetLockTimeout.D()}
	svc, err := newAuthority(cfg, pool, reg, kp, authorityStore, consoleBaseURL(cfg.Auth.PublicURL, ext), log)
	if err != nil {
		return err
	}
	// The operator's maintenance hold: no decision from any path (HR-379).
	svc.WithMaintenanceHold(cfg.Maintenance.Hold)
	if err := auditMaintenanceHold(ctx, pool, cfg.Maintenance.Hold, log); err != nil {
		return err
	}
	captures := newCaptures(pool, kp, log)
	svc.WithCaptures(captures.recorder)
	m5, err := newM5(ctx, cfg, pool, kp, bill, log)
	if err != nil {
		return err
	}
	dataRequests, err := newDataRequests(cfg, pool, reg, m5, log)
	if err != nil {
		return err
	}
	exportDeps := exportsDeps{pool: pool, kp: kp, reg: reg, bill: bill, publicURL: cfg.Auth.PublicURL, logOrigin: cfg.logOrigin(), log: log}
	if err := wireExportStream(dataRequests, exportDeps); err != nil {
		return err
	}
	ui.deletion = newAccountDeletion(ui.store, dataRequests)
	ui.wireInvitationEmails(cfg, m5.notifications)
	// A monitor-mode action with an unknown consequence notifies (HR-206).
	authorityStore.Notify = m5.notifications
	m6, err := newM6(cfg, pool, reg, m5.notifications, log)
	if err != nil {
		return err
	}
	m6.fleet = newM18Fleet(m6, bill, m5.notifications)
	m6.hold = cfg.Maintenance.Hold
	m14core := wireM14Core(m6)
	wireM14A2A(m14core)
	_ = m14core // the M14 streams' wiring registers its kinds here (G0 M14 D64)
	wireM14Data(m14core, m6)
	// Sealing a GitHub App credential schedules an org scan, and a daily one
	// follows, so coverage reads its installation's permissions (F048).
	ghScans := &githubapp.Scans{Pool: pool, Ents: bill}
	m6.credentials.OnGitHubInstallation(ghScans.InstallationRecorded)
	svc.WithToolObservations(m6.connections)
	m6.connections.WithEntitlements(bill)                                      // the inventory draft is Team and above (G0 M15 D23)
	m6.hosting = newHosting(cfg, pool, m6.ca, kp, bill).WithFleet(m6.gateways) // hosted gateways (G0 M19 D203)
	m5p2, err := newM5p2(cfg, pool, bill, m5.notifications, log)
	if err != nil {
		return err
	}
	tickets := newTicketSync(pool, kp, bill)
	verification, err := newVerification(pool, reg, m5.notifications, tickets)
	if err != nil {
		return err
	}
	m6.verifications = verification
	wireM20Rotation(pool, m6, verification, bill, log)
	m6.facts = gatewayFacts(pool)
	m6.scans = agentsrpc.NewGatewayScans(aapp.NewInventory(pool, bill).WithNotify(m5.notifications))

	g, ctx := errgroup.WithContext(ctx)
	// The private admin listener, in every role (HR-382).
	if err := serveAdmin(ctx, g, cfg, tel, log); err != nil {
		return err
	}
	// apiAddr is the bound API address (role api or all).
	var apiAddr string
	// autos is the one M11 part 2 core of this process: the API and the
	// jobs share it, so every port set on it reaches both (D91 K6).
	// protect sets its ports on it in every role (D110 P1).
	autos, m11protect := newM11Core(pool, bill, cfg.Auth.PublicURL)
	closeM18IdPs(m11protect.gate, log)
	wireM11Process(autos, m11protect, pool)
	wireM14Process(autos, bill)
	wireM14A2APeer(svc, authorityStore, autos, pool)
	external := newExternalChecks(pool, cfg, bill, log)
	wireM16External(svc, m5p2, external, pool)
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
		if len(proxies) == 0 {
			// API-key IP allow lists (G0 M18 D153, HR-476) then check the
			// direct peer, which behind a proxy is the proxy itself.
			log.WarnContext(ctx, "server.api_key_ranges_use_peer", slog.String("note",
				"http.trusted_proxies is empty: API keys limited to address ranges are checked against the direct peer address"))
		}
		orgIdPs := newM18IdPs(cfg, pool, kp, log)
		go idpsWarnShadowed(ctx, pool, orgIdPs, log)
		device, err := devicehttp.New(authnapp.NewDevice(pool, tokens, cfg.Auth.PublicURL, idps, clock.System{}, log).
			WithOrgProviders(orgIdPs.resolver), cfg.Auth.PublicURL, limiter, log)
		if err != nil {
			return err
		}
		web, err := m5.web(cfg, pool, idps, limiter, log)
		if err != nil {
			return err
		}
		m5.browser.WithOrgProviders(orgIdPs.resolver)
		ui.wireBrowser(m5.browser, web)
		m6.mountPages(web)
		m5p2.mountPages(web, m5)
		mountM7Pages(web, pool, verification, m5)
		mountCoveragePages(web, pool, cfg)
		device.WithBrowserCallback(web.Callback)
		roots, err := packageRoots(ctx, cfg, log)
		if err != nil {
			return err
		}
		sessions, err := browserSessions(cfg, pool, idps, log)
		if err != nil {
			return err
		}
		sup := newSupport(cfg, pool, entsSvc, m5.notifications, log)
		handler, err := apiHandler(apiDeps{
			pool: pool, reg: reg, log: log, authority: svc, billing: bill,
			auth: rpcauth.New(authn, procedurePermissions, nil,
				rpcauth.WithRefusals(&rpcauth.AuditRefusals{Pool: pool, Log: log}),
				cfg.APILimits(pool, log),
				rpcauth.WithPlanGate(planGate(entsSvc, cfg.Billing.RequirePlan)),
				rpcauth.WithBrowserSessions(sessions, log),
				ui.accountSessions(web, sessions.PublicOrigin()),
				supportSessions(sup)),
			support:   sup,
			apiKeyEnv: credential.Env(cfg.Auth.APIKeyEnv),
			cel:       cfg.CEL,
			oauth: oauthhttp.New(authnapp.NewOAuth(pool, tokens, cfg.Auth.PublicURL, clock.System{}, log),
				cfg.Auth.PublicURL, limiter),
			device:    device,
			publicURL: cfg.Auth.PublicURL, clientIP: limiter.ClientIP, clusters: clusters, subjects: subjects, identity: cfg.Identity,
			logOrigin:    cfg.logOrigin(),
			packageRoots: roots,
			github:       cfg.GitHub,
			web:          web,
			m5:           m5,
			captures:     captures,
			m6:           m6,
			m5p2:         m5p2,
			verification: verification,
			tickets:      tickets,
			kp:           kp,
			freshness:    freshnessOf(cfg),
			m10ops:       m10OpsDeps{authn: authn, tokens: tokens, sessions: sessions},
			autos:        autos,
			m11protect:   m11protect,
			ext:          ext,
			extDeps:      ui.extensionDeps(xdeps),
			ui:           ui,
			workers:      workers,
			hold:         cfg.Maintenance.Hold,
			data:         dataRequests,
			external:     external,
			idps:         orgIdPs,
		})
		if err != nil {
			return err
		}
		if err := m6.serveGateways(ctx, g, cfg, svc, log, nil); err != nil {
			return err
		}
		certs, err := publicCertReloader(cfg, log)
		if err != nil {
			return err
		}
		srv, ln, err := listen(ctx, cfg, handler, certs, log)
		if err != nil {
			return err
		}
		serveCertReloads(ctx, g, certs)
		// Tests learn the address once the process can be ready: with the
		// workers in this process, after they started (HR-370).
		apiAddr = ln.Addr().String()
		if onStart != nil && cfg.Role != RoleAll {
			onStart(apiAddr)
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
		dataJobs, closeData, err := registerDataWorkers(ctx, jreg, cfg, dataRequests, log)
		if err != nil {
			return err
		}
		defer closeData()
		accountJobs, err := registerAccountDeletion(jreg, ui.deletion)
		if err != nil {
			return err
		}
		if err := newSupport(cfg, pool, entsSvc, m5.notifications, log).Register(jreg); err != nil {
			return err
		}
		if err := chainer.Register(jreg, pool, log); err != nil {
			return err
		}
		if err := authority.RegisterSweeper(jreg, pool, svc, cfg.Authority.StaleDispatch.D()); err != nil {
			return err
		}
		evidenceJobs, err := registerEvidenceWorkers(jreg, cfg, pool, reg, m5.notifications, autos, bill, captures, log)
		if err != nil {
			return err
		}
		retentionJobs, closeRetention, err := registerRetention(ctx, jreg, cfg, pool, log)
		if err != nil {
			return err
		}
		defer closeRetention()
		evidenceJobs = append(evidenceJobs, retentionJobs...)
		sandboxJobs, err := registerSandboxJobs(jreg, pool, log)
		if err != nil {
			return err
		}
		evidenceJobs = append(evidenceJobs, sandboxJobs...)
		rangeJobs, err := registerRangeJobs(jreg, pool, log)
		if err != nil {
			return err
		}
		evidenceJobs = append(evidenceJobs, rangeJobs...)
		if evidenceJobs, err = registerPolicyRolloutJobs(evidenceJobs, jreg, pool, bill, m5, kp, log); err != nil {
			return err
		}
		exceptionJobs, err := registerPolicyExceptionJobs(jreg, pool, m5.notifications, log)
		if err != nil {
			return err
		}
		evidenceJobs = append(evidenceJobs, exceptionJobs...)
		responseJobs, err := registerResponseJobs(jreg, pool, responseNotifier(m5), bill, log)
		if err != nil {
			return err
		}
		evidenceJobs = append(evidenceJobs, responseJobs...)
		if err := registerSuggestionJobs(jreg, pool, log); err != nil {
			return err
		}
		if evidenceJobs, err = registerExposureJobs(evidenceJobs, jreg, pool, bill, log); err != nil {
			return err
		}
		if evidenceJobs, err = registerM10OpsJobs(evidenceJobs, jreg, pool, bill, log); err != nil {
			return err
		}
		if evidenceJobs, err = registerM21OutcomeJobs(evidenceJobs, jreg, pool, bill, log); err != nil {
			return err
		}
		if evidenceJobs, err = registerM11GovernJobs(evidenceJobs, jreg, pool, log); err != nil {
			return err
		}
		if evidenceJobs, err = registerM10EdgesJobs(evidenceJobs, jreg, pool, kp, bill, m5, cfg.Auth.PublicURL, log); err != nil {
			return err
		}
		if evidenceJobs, err = registerM20ExportsJobs(evidenceJobs, jreg, exportDeps); err != nil {
			return err
		}
		if evidenceJobs, err = registerAutomationTriggersJobs(evidenceJobs, jreg, pool, kp, bill, cfg.Auth.PublicURL, autos, log); err != nil {
			return err
		}
		if evidenceJobs, err = registerAutomationEngineJobs(evidenceJobs, jreg, autos, cfg, kp, bill,
			m5.notifications, log); err != nil {
			return err
		}
		reflexJobs, err := registerReflexCoreJobs(jreg, pool, cfg.CEL, bill, m5.notifications, log)
		if err != nil {
			return err
		}
		evidenceJobs = append(evidenceJobs, reflexJobs...)
		if evidenceJobs, err = registerAutomationsCoreJobs(evidenceJobs, jreg, autos, log); err != nil {
			return err
		}
		if err := registerSimulationJobs(jreg, pool, kp, bill, log); err != nil {
			return err
		}
		if evidenceJobs, err = registerAutomationAssuranceJobs(evidenceJobs, jreg, autos, bill, log); err != nil {
			return err
		}
		if evidenceJobs, err = registerLimitsJobs(evidenceJobs, jreg, pool, log); err != nil {
			return err
		}
		if evidenceJobs, err = registerM15GatewayJobs(evidenceJobs, jreg, pool, log); err != nil {
			return err
		}
		if evidenceJobs, err = registerM19HostingJobs(evidenceJobs, jreg, cfg, pool, kp, log); err != nil {
			return err
		}
		if evidenceJobs, err = registerM18FleetJobs(evidenceJobs, jreg, m6.fleet, log); err != nil {
			return err
		}
		if evidenceJobs, err = registerM20WebhookJobs(evidenceJobs, jreg, pool, kp, log); err != nil {
			return err
		}
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
		coverageJobs, err := registerCoverageWorkers(jreg, cfg, pool)
		if err != nil {
			return err
		}
		evidenceJobs = append(evidenceJobs, coverageJobs...)
		if err := githubapp.Register(jreg, ghScans); err != nil {
			return err
		}
		rewrapJobs, closeKeystore, err := registerKeyRewrap(ctx, jreg, cfg, pool, kp, log)
		if err != nil {
			return err
		}
		defer closeKeystore()
		evidenceJobs = append(evidenceJobs, rewrapJobs...)
		client, err := jobs.NewClient(pool, jreg, jobs.Config{
			Queues: map[string]int{river.QueueDefault: cfg.WorkerConcurrency, napp.Queue: cfg.Notifications.Concurrency},
			PeriodicJobs: slices.Concat(chainer.PeriodicJobs(), authority.SweeperPeriodicJobs(), authnapp.JanitorPeriodicJobs(),
				iapp.JanitorPeriodicJobs(), napp.PeriodicJobs(), m5p2.periodicJobs(), txapp.PeriodicJobs(), githubapp.PeriodicJobs()),
			Logger: log,
		})
		if err != nil {
			return err
		}
		client.PeriodicJobs().AddMany(supportPeriodicJobs())
		client.PeriodicJobs().AddMany(evidenceJobs)
		observeJobs(ctx, client)
		client.PeriodicJobs().AddMany(dataJobs)
		client.PeriodicJobs().AddMany(accountJobs)
		if err := client.Start(ctx); err != nil {
			return fmt.Errorf("server: start workers: %w", err)
		}
		log.InfoContext(ctx, "server.workers_started", slog.Int("concurrency", cfg.WorkerConcurrency))
		workers.serve(ctx, g, client)
		if onStart != nil && cfg.Role == RoleAll {
			onStart(apiAddr)
		}
		// Role worker: /livez and /readyz on the health listener (HR-397).
		healthAddr, err := serveHealth(ctx, g, cfg, pool, workers, log)
		if err != nil {
			return err
		}
		if onStart != nil && healthAddr != "" {
			onStart(healthAddr)
		}
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

func listen(ctx context.Context, cfg *Config, handler http.Handler, certs *httpx.CertReloader, log *slog.Logger) (*http.Server, net.Listener, error) {
	var tlsConf *tls.Config
	if certs != nil {
		// The pair is re-read from disk when it changes (HR-371).
		tlsConf = httpx.ReloadingServerTLSConfig(certs)
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
	// external is the external policy check service (G0 M16 D81).
	external *externalchecks.Service
	data     *datarequests.Service
	// idps are the organization identity providers (G0 M18 D155).
	idps m18IdPs
	pool *db.Pool
	// cel are the configured CEL limits (cel).
	cel       celenv.Limits
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
	// identity is the workload identity configuration (presets, M17).
	identity IdentityConfig
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
	// M8: GitHub sign-in (P2f).
	github GitHubConfig
	// captures seal and open restricted payload captures (M7 B9).
	captures *captureServices
	// kp opens sealed evaluation inputs for decision replay (M7 track B).
	kp keys.KeyProvider
	// freshness is coverage's freshness contract (M9 track A).
	freshness coverage.Freshness
	// M10 ops: the live stream's bearer authentication.
	m10ops m10OpsDeps
	// M11 protect: the protected-change Gate and compromised publishers.
	m11protect m11Protect
	// ui is the UI phase's core services (wiring_ui_tenancy.go); nil in
	// tests that do not need them.
	ui *uiTenancy
	// autos is the process's M11 part 2 core (nil: apiHandler builds one).
	autos *automationsCore
	// ext is what this build adds (internal/extension; zero: nothing), and
	// extDeps what it is handed.
	ext     extension.Set
	extDeps extension.Deps
	// workers is the job workers' heartbeat that /readyz requires (role
	// all); nil when this process runs no workers.
	workers *workerHeartbeat
	// hold is the operator's maintenance hold (HR-379).
	hold bool
	// support is customer-approved support access (wiring_m13_support.go);
	// nil or off when not configured.
	support supportService
	// tickets is ticket sync (wiring_m20_tickets.go); nil: apiHandler builds
	// one.
	tickets *tsapp.Service
}

// apiHandler mounts the RPC services, health endpoints and the JWKS.
func apiHandler(d apiDeps) (http.Handler, error) {
	pool, reg, log := d.pool, d.reg, d.log
	if d.m11protect.gate == nil {
		d.m11protect = newM11Protect(d.pool, d.billing)
	}
	rs, err := rpc.NewServer(rpc.Options{
		Logger:       log,
		Public:       publicProcedures(),
		Authenticate: holdAuthenticator(d.hold, heldOnAPI, d.auth),
	})
	if err != nil {
		return nil, err
	}
	pantherclawv1connect.RegisterSystemServiceHandler(rs, systemService{})
	pantherclawv1connect.RegisterAuthorityServiceHandler(rs, authority.NewHandler(d.authority))
	pantherclawv1connect.RegisterTenancyServiceHandler(rs, tenancyHandler(tenancyrpc.NewTenancy(tapp.NewHierarchy(pool, d.billing)), d.ui))
	pantherclawv1connect.RegisterAccessServiceHandler(rs, accessHandler(tenancyrpc.NewAccess(tapp.NewAccess(pool, log).WithEntitlements(d.billing)).WithDeployment(string(d.extDeps.Deployment)), d.ui, d.extDeps.Deployment))
	pantherclawv1connect.RegisterServiceAccountServiceHandler(rs, tenancyrpc.NewServiceAccounts(tapp.NewServiceAccounts(pool, d.apiKeyEnv).WithEntitlements(d.billing)))
	// autos is the M11 part 2 core, set below once grants and runs exist;
	// ListAgents reads it only while serving.
	var autos *automationsCore
	pantherclawv1connect.RegisterAgentServiceHandler(rs, d.m5p2.agents(agentsrpc.NewAgents(aapp.NewInventory(pool, d.billing).WithNotify(d.m5.notifications)).
		WithAutomations(func(ctx context.Context) ([]*pantherclawv1.AutomationIdentity, string, error) {
			return autos.identities(ctx)
		})))
	pantherclawv1connect.RegisterWaitlistServiceHandler(rs, d.m5p2.waitlist())
	attestors, err := newAttestors(d.clusters, d.identity)
	if err != nil {
		return nil, err
	}
	identity := iapp.New(pool, reg, d.publicURL, clock.System{}).WithAttestors(attestors).WithEntitlements(d.billing)
	pantherclawv1connect.RegisterIdentityServiceHandler(rs, identityrpc.NewIdentity(identity, d.clusters))
	grants, runs := m11Issuance(d)
	wireM14Grants(grants, d)
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
		account := accountrpc.New(authnapp.NewAccount(pool, d.m5.webauthn, d.m5.notifications))
		if d.ui != nil && d.ui.deletion != nil {
			account.WithAccountDeleter(d.ui.deletion)
		}
		pantherclawv1connect.RegisterAccountServiceHandler(rs, account)
		pantherclawv1connect.RegisterNotificationServiceHandler(rs, notificationsrpc.New(d.m5.notifications))
	}
	d.m6.registerPublic(rs)
	d.m5p2.registerPublic(rs)
	registerM7(rs, pool, d.kp, d.verification, consoleBaseURL(d.publicURL, d.ext))
	var githubNotify githubapp.Notifier
	if d.m5 != nil {
		githubNotify = d.m5.notifications
	}
	if err := registerM8G(rs, pool, githubNotify, d.github, d.billing); err != nil {
		return nil, err
	}
	evidenceSvc, err := registerEvidence(rs, d)
	if err != nil {
		return nil, err
	}
	registerEvidenceAdmin(rs, d)
	registerCoverage(rs, d)
	registerSandbox(rs, d)
	registerRanges(rs, d, evidenceSvc)
	registerPolicyRollouts(rs, d)
	if err := registerSimulation(rs, d); err != nil {
		return nil, err
	}
	registerReleases(rs, pool, d.m11protect)
	registerPolicyExceptions(rs, d)
	registerM21Outcomes(rs, d)
	mountM10Ops, err := registerM10Ops(rs, d)
	if err != nil {
		return nil, err
	}
	registerM11Search(rs, d)
	registerCases(rs, d, grants)
	registerResponse(rs, d)
	registerExposure(rs, d)
	registerSuggestions(rs, d)
	registerRecommendations(rs, d)
	edges, err := registerM10Edges(rs, d)
	if err != nil {
		return nil, err
	}
	if err := registerM20Exports(rs, d); err != nil {
		return nil, err
	}
	registerReflexCore(rs, d)
	registerM11Govern(rs, d)
	registerSlackChannels(d)
	registerTeamsChannels(d)
	autos = registerAutomationsCore(rs, d, grants, runs)
	if err := registerAutomationAssurance(rs, d, autos); err != nil {
		return nil, err
	}
	if err := registerAutomationsEngine(rs, d, workload, autos); err != nil {
		return nil, err
	}
	if err := registerAutomationTemplates(rs, d, autos); err != nil {
		return nil, err
	}
	automationTriggers, err := registerAutomationTriggers(rs, d, autos)
	if err != nil {
		return nil, err
	}
	registerM11Protect(rs, d, autos)
	registerM17Rules(rs, d)
	registerM18IdPs(rs, d)
	authzen := registerAuthZEN(rs, d)
	registerUITenancy(rs, d)
	registerUsage(rs, d)
	registerDataRequests(rs, d)
	registerM20Webhooks(rs, d)
	registerM20Tickets(rs, d)
	registerSupport(rs, d)
	registerM16External(rs, d)
	mux := http.NewServeMux()
	edges.mount(mux)
	automationTriggers.mount(mux)
	authzen.mount(mux)
	mountTicketWebhooks(mux, d)
	if err := mountM14A2A(mux, d); err != nil {
		return nil, err
	}
	rpc.Mount(mux, rs)
	d.m5p2.mount(mux, workload)
	d.oauth.Mount(mux)
	d.device.Mount(mux, d.oauth)
	if d.web != nil {
		d.web.Mount(mux)
		mountSupport(mux, d)
	}
	mountDataRequests(mux, d)
	if d.web != nil && d.ui != nil && d.ui.deletion != nil {
		d.web.MountAccountDeletion(mux, d.ui.deletion)
	}
	mountM14Data(mux, d)
	mountM16External(mux, d)
	mountWebhookJWKS(mux, webhookJWKSOf(d), d.clientIP, log)
	mux.HandleFunc("GET /livez", livez(pool))
	mux.Handle("GET /readyz", readiness{pool: pool, workers: d.workers, held: d.hold, log: log})
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
	mountM10Ops(mux)
	// Extension routes come last, so they can be checked against every
	// core route (HR-341).
	if err := mountConsole(mux, d.ext); err != nil {
		return nil, err
	}
	if err := mountExtension(mux, d.ext, d.extDeps, d.web, d.clientIP); err != nil {
		return nil, err
	}
	// The client address goes into every request's context for the account
	// procedures' per-IP limits (G0 UI D85).
	return httpx.ClientIPMiddleware(workloadrpc.RawBody(holdHTTP(d.hold, heldHTTPPath, mux), d.clientIP), d.clientIP), nil
}

// attestTimeout bounds one call to an issuer or a cluster API server.
const attestTimeout = 10 * time.Second

// newAttestors returns the L2 verifiers: GitHub keys through the egress
// client (public addresses only), the configured clusters (HR-142) and
// the M17 presets (attestors_m17.go).
func newAttestors(clusters *kube.Directory, cfg IdentityConfig) (iapp.Attestors, error) {
	gh, err := issuerkeys.New(httpx.NewEgressClient(httpx.EgressConfig{Timeout: attestTimeout}), issuers.GitHubIssuer, nil)
	if err != nil {
		return iapp.Attestors{}, err
	}
	kc, err := kube.NewClient(clusters, attestTimeout)
	if err != nil {
		return iapp.Attestors{}, err
	}
	att := iapp.Attestors{GitHub: gh, Kube: kc, Clusters: clusters}
	if err := presetAttestors(&att, cfg); err != nil {
		return iapp.Attestors{}, err
	}
	return att, nil
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
	backupPW := fs.String("backup-password-file", "", "optional: password file for pc_backup, the read-only role of the backup job")
	deleterPW := fs.String("deleter-password-file", "", "optional: password file for pc_deleter, the role of the org deletion job")
	keystorePW := fs.String("keystore-password-file", "", "optional: password file for pc_keystore, the role of the key re-wrap job")
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
	if *backupPW != "" {
		// Before the database grants, which give an existing pc_backup
		// its read access (G0 M13 D21).
		bpw, err := config.ReadSecretFile(*backupPW)
		if err != nil {
			return err
		}
		if err := db.BootstrapBackupRole(ctx, conn, bpw); err != nil {
			return err
		}
	}
	if *deleterPW != "" {
		// Before the database grants, which give an existing pc_deleter
		// its org tables (G0 M13 D34).
		dpw, err := config.ReadSecretFile(*deleterPW)
		if err != nil {
			return err
		}
		if err := db.BootstrapDeleterRole(ctx, conn, dpw); err != nil {
			return err
		}
	}
	if *keystorePW != "" {
		// Before the database grants, which give an existing pc_keystore its
		// re-wrap columns (G0 M18 D171).
		kpw, err := config.ReadSecretFile(*keystorePW)
		if err != nil {
			return err
		}
		if err := db.BootstrapKeystoreRole(ctx, conn, kpw); err != nil {
			return err
		}
	}
	if err := db.BootstrapDatabase(ctx, conn); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "bootstrapped roles %s, %s, %s, %s, %s and schema %s in database %s\n",
		db.RoleMigrator, db.RoleApp, db.RoleAuditRO, db.RoleRetention, db.RoleLister, db.Schema, cc.Database)
	if *backupPW != "" {
		_, _ = fmt.Fprintf(stdout, "bootstrapped the read-only backup role %s\n", db.RoleBackup)
	}
	if *deleterPW != "" {
		_, _ = fmt.Fprintf(stdout, "bootstrapped the org deletion role %s\n", db.RoleDeleter)
	}
	if *keystorePW != "" {
		_, _ = fmt.Fprintf(stdout, "bootstrapped the key re-wrap role %s\n", db.RoleKeystore)
	}
	return nil
}

func cmdKeys(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) > 0 {
		switch args[0] {
		case "rotate-gateway-ca":
			return cmdRotateGatewayCA(ctx, args[1:], stdout, stderr, env)
		case "rotate-receipts":
			return cmdRotateSigning(ctx, rotateReceipts, args[1:], stdout, stderr, env)
		case "rotate-evidence":
			return cmdRotateSigning(ctx, rotateEvidence, args[1:], stdout, stderr, env)
		case "bump-epochs":
			return cmdBumpEpochs(ctx, args[1:], stdout, stderr, env)
		}
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
	pantherclawv1connect.RegisterFactServiceHandler(rs, factsrpc.New(&factsapp.Service{Store: facts, Authz: authz, Reads: facts, Packages: packageFacts(d.pool)}))
	roots := d.packageRoots
	if roots == nil {
		var err error
		if roots, err = trust.EmbeddedRoots(); err != nil {
			return err
		}
	}
	pantherclawv1connect.RegisterPackageServiceHandler(rs, packagesrpc.New(protectPackages(&defsapp.Admin{
		Importer: &defsapp.Importer{Roots: roots, Repo: defs, Keys: defs, Clock: clock.System{}}, Reads: defs, Authz: authz,
		Ents: d.billing, Checks: activationChecks(d.pool, d.cel), Pool: d.pool,
	}, d)))
	registerPolicyGate(rs, d)
	return nil
}
