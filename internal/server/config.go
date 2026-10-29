// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/awssts"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/issuerkeys"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Roles a server process can run.
const (
	RoleAPI    = "api"
	RoleWorker = "worker"
	RoleAll    = "all"
)

// Config is the pantherclaw-server configuration (JSON file + PC_* env).
// Secrets are referenced by file path only (SB-7).
type Config struct {
	Role string `json:"role" env:"PC_ROLE"`
	// Deployment is development, staging or production (config_ui_web.go).
	Deployment string `json:"deployment" env:"PC_DEPLOYMENT"`
	// Maintenance is the operator's maintenance hold (wiring_m13_platform.go).
	Maintenance MaintenanceConfig `json:"maintenance"`
	// Health is the worker role's health listener (wiring_m13_install.go).
	Health HealthConfig `json:"health"`
	Log    LogConfig    `json:"log"`
	HTTP   HTTPConfig   `json:"http"`
	DB     DBConfig     `json:"database"`
	// Support is customer-approved support access (config_m13_support.go).
	Support SupportConfig `json:"support"`
	// KEKFiles are key-encryption-key files; the first wraps new keys.
	KEKFiles    []string `json:"kek_files" env:"PC_KEK_FILES"`
	LicenceFile string   `json:"licence_file" env:"PC_LICENCE_FILE"`
	// WorkerConcurrency is the number of concurrent jobs per worker process.
	WorkerConcurrency int             `json:"worker_concurrency" env:"PC_WORKER_CONCURRENCY"`
	Authority         AuthorityConfig `json:"authority"`
	// CEL bounds the compilation and evaluation of every policy, mapping and
	// consequence expression (HR-043; G0 M4 decision 4). Defaults:
	// celenv.DefaultLimits.
	CEL      celenv.Limits  `json:"cel"`
	Auth     AuthConfig     `json:"auth"`
	Identity IdentityConfig `json:"identity"`
	// WebAuthn and Notifications are M5 part 1 (config_m5.go).
	WebAuthn      WebAuthnConfig      `json:"webauthn"`
	Notifications NotificationsConfig `json:"notifications"`
	// Waitlist is M5 part 2 (config_m5p2.go).
	Waitlist WaitlistConfig `json:"waitlist"`
	// GatewayAPI is M6 (config_m6.go).
	GatewayAPI GatewayAPIConfig `json:"gateway_api"`
	// GitHub is M8 GitHub sign-in (config_m8.go).
	GitHub GitHubConfig `json:"github"`
	// Evidence is M7 track B (config_evidence.go).
	Evidence EvidenceConfig `json:"evidence"`
	// Coverage is M9 track A (config_coverage.go).
	Coverage CoverageConfig `json:"coverage"`
	// Gateways is M9 track C (config_connectors.go).
	Gateways GatewaysConfig `json:"gateways"`
	// Dev holds development-only settings (config_dev.go).
	Dev DevConfig `json:"dev"`
	// Billing and Signup are hosted plans and self-serve organizations
	// (G0 UI D8, D9, D12; config_ui_tenancy.go).
	Billing BillingConfig `json:"billing"`
	Signup  SignupConfig  `json:"signup"`
	// Telemetry and Admin are the OTLP exporter and the private admin
	// listener (G0 M13 D30; wiring_m13_observability.go).
	Telemetry TelemetryConfig `json:"telemetry"`
	Admin     AdminConfig     `json:"admin"`
	// Limits is the API rate limits and usage meters (G0 M13 D8, D10;
	// config_m13_limits.go).
	Limits  LimitsConfig  `json:"limits"`
	Backups BackupsConfig `json:"backups"`
}

// IdentityConfig configures workload identity (M3).
type IdentityConfig struct {
	// KubernetesClusters are the clusters the Kubernetes L2 preset may call
	// (founder decision 3: operator configuration only).
	KubernetesClusters []kube.ClusterConfig `json:"kubernetes_clusters"`
	// GitLabIssuers are the GitLab instances the GitLab CI preset trusts
	// (D119); none configured means https://gitlab.com for every org.
	GitLabIssuers []issuerkeys.GitLabIssuer `json:"gitlab_issuers"`
	// SPIFFETrustDomains are the trust domains the SPIFFE preset trusts
	// (D120); none means the preset refuses every attestation.
	SPIFFETrustDomains []issuerkeys.TrustDomain `json:"spiffe_trust_domains"`
	// AWSSTSHosts are the STS endpoints the AWS preset sends signed
	// requests to (D121); none means the global and regional
	// sts.*.amazonaws.com endpoints.
	AWSSTSHosts []string `json:"aws_sts_hosts"`
	// EntraApps pin each Entra app the Azure presets accept to one tenant
	// and one org (D129); none means those presets refuse every
	// attestation.
	EntraApps []issuerkeys.EntraApp `json:"entra_apps"`
}

// LogConfig configures logging.
type LogConfig struct {
	Level string `json:"level" env:"PC_LOG_LEVEL"`
}

// HTTPConfig configures the API listener.
type HTTPConfig struct {
	Addr                 string `json:"addr" env:"PC_HTTP_ADDR"`
	TLSCertFile          string `json:"tls_cert_file" env:"PC_HTTP_TLS_CERT_FILE"`
	TLSKeyFile           string `json:"tls_key_file" env:"PC_HTTP_TLS_KEY_FILE"`
	PlaintextBehindProxy bool   `json:"plaintext_behind_proxy" env:"PC_HTTP_PLAINTEXT_BEHIND_PROXY"`
	// TrustedProxies are the reverse proxies (IPs or CIDRs) whose
	// X-Forwarded-For header names the client, for per-client rate limits.
	// Forwarding headers from any other peer are ignored.
	TrustedProxies []string `json:"trusted_proxies" env:"PC_HTTP_TRUSTED_PROXIES"`
}

// DBConfig configures PostgreSQL access.
type DBConfig struct {
	Host                 string `json:"host" env:"PC_DB_HOST"`
	Port                 int    `json:"port" env:"PC_DB_PORT"`
	Name                 string `json:"name" env:"PC_DB_NAME"`
	SSLMode              string `json:"sslmode" env:"PC_DB_SSLMODE"`
	SSLRootCert          string `json:"sslrootcert" env:"PC_DB_SSLROOTCERT"`
	AppUser              string `json:"app_user" env:"PC_DB_APP_USER"`
	AppPasswordFile      string `json:"app_password_file" env:"PC_DB_APP_PASSWORD_FILE"`
	MigratorUser         string `json:"migrator_user" env:"PC_DB_MIGRATOR_USER"`
	MigratorPasswordFile string `json:"migrator_password_file" env:"PC_DB_MIGRATOR_PASSWORD_FILE"`
	// RetentionUser and RetentionPasswordFile are the pc_retention role's
	// (G0 M7 design decision 9): only the worker's retention job connects
	// with them. Without the password file nothing is removed and the job
	// reports ROLE_UNAVAILABLE (config_retention.go).
	RetentionUser         string          `json:"retention_user" env:"PC_DB_RETENTION_USER"`
	RetentionPasswordFile string          `json:"retention_password_file" env:"PC_DB_RETENTION_PASSWORD_FILE"`
	DeleterPasswordFile   string          `json:"deleter_password_file" env:"PC_DB_DELETER_PASSWORD_FILE"`
	MaxConns              int             `json:"max_conns" env:"PC_DB_MAX_CONNS"`
	StatementTimeout      config.Duration `json:"statement_timeout" env:"PC_DB_STATEMENT_TIMEOUT"`
	LockTimeout           config.Duration `json:"lock_timeout" env:"PC_DB_LOCK_TIMEOUT"`
	IdleInTxTimeout       config.Duration `json:"idle_in_transaction_timeout" env:"PC_DB_IDLE_IN_TX_TIMEOUT"`
}

// DefaultConfig returns safe defaults: loopback listener, TLS-verified DB.
func DefaultConfig() Config {
	d := db.Defaults()
	return Config{
		// Deployment stays empty, which means development, so a build with
		// an extension can tell that it was never set (config_ui_web.go).
		Role: RoleAll,
		Log:  LogConfig{Level: "info"},
		HTTP: HTTPConfig{Addr: "127.0.0.1:8080"},
		DB: DBConfig{
			Host: d.Host, Port: d.Port, Name: d.Database, SSLMode: d.SSLMode,
			AppUser: db.RoleApp, MigratorUser: db.RoleMigrator, MaxConns: int(d.MaxConns),
			StatementTimeout: config.Duration(d.StatementTimeout), LockTimeout: config.Duration(d.LockTimeout),
			IdleInTxTimeout: config.Duration(d.IdleInTxTimeout),
		},
		WorkerConcurrency: 10,
		Backups:           BackupsConfig{RetentionDays: 60},
		Authority: AuthorityConfig{
			GrantMaxPerAction: "100", GrantCurrency: "USD", BudgetName: "dev-refunds",
			PermitTTL: config.Duration(5 * time.Second), StaleDispatch: config.Duration(30 * time.Second),
			BudgetLockTimeout: config.Duration(100 * time.Millisecond),
		},
		Auth:     AuthConfig{PublicURL: "http://127.0.0.1:8080", APIKeyEnv: string(credential.EnvLive)},
		WebAuthn: WebAuthnConfig{RPName: "PantherClaw"},
		Notifications: NotificationsConfig{
			Concurrency: 5,
			SMTP:        SMTPConfig{Port: 587, TLS: "starttls"},
		},
		Waitlist:  defaultWaitlist(),
		CEL:       celenv.DefaultLimits,
		Telemetry: defaultTelemetry(),
		Limits:    defaultLimits(),
	}
}

// Validate implements config.Validator.
func (c *Config) Validate() error {
	var errs []error
	if !slices.Contains([]string{RoleAPI, RoleWorker, RoleAll}, c.Role) {
		errs = append(errs, fmt.Errorf("role must be %s, %s or %s", RoleAPI, RoleWorker, RoleAll))
	}
	if _, ok := pclog.ParseLevel(c.Log.Level); !ok {
		errs = append(errs, errors.New("log.level must be debug, info, warn or error"))
	}
	if _, err := kube.NewDirectory(c.Identity.KubernetesClusters); err != nil {
		errs = append(errs, fmt.Errorf("identity.kubernetes_clusters: %w", err))
	}
	if err := issuerkeys.ValidateGitLab(c.Identity.GitLabIssuers); err != nil {
		errs = append(errs, fmt.Errorf("identity.gitlab_issuers: %w", err))
	}
	if err := issuerkeys.ValidateSPIFFE(c.Identity.SPIFFETrustDomains); err != nil {
		errs = append(errs, fmt.Errorf("identity.spiffe_trust_domains: %w", err))
	}
	if err := awssts.ValidateHosts(c.Identity.AWSSTSHosts); err != nil {
		errs = append(errs, fmt.Errorf("identity.aws_sts_hosts: %w", err))
	}
	if err := issuerkeys.ValidateEntra(c.Identity.EntraApps); err != nil {
		errs = append(errs, fmt.Errorf("identity.entra_apps: %w", err))
	}
	if (c.HTTP.TLSCertFile == "") != (c.HTTP.TLSKeyFile == "") {
		errs = append(errs, errors.New("http.tls_cert_file and http.tls_key_file must be set together"))
	}
	if c.DB.AppPasswordFile == "" {
		errs = append(errs, errors.New("database.app_password_file is required"))
	}
	if c.DB.AppUser == db.RoleMigrator || c.DB.AppUser == "postgres" {
		errs = append(errs, errors.New("database.app_user must be the unprivileged application role"))
	}
	if len(c.KEKFiles) == 0 {
		errs = append(errs, errors.New("kek_files is required (generate one with: pantherclaw-server keys gen-kek --out FILE)"))
	}
	if c.WorkerConcurrency < 1 || c.WorkerConcurrency > 1000 {
		errs = append(errs, errors.New("worker_concurrency must be 1..1000"))
	}
	errs = append(errs, c.validateDeployment()...)
	errs = append(errs, c.validateHealth()...)
	errs = append(errs, c.validateSupport()...)
	errs = append(errs, c.validateTenancy()...)
	errs = append(errs, c.validateAuthority()...)
	errs = append(errs, c.validateAuth()...)
	errs = append(errs, c.validateOIDC()...)
	errs = append(errs, c.validateM5()...)
	errs = append(errs, c.validateM5p2()...)
	errs = append(errs, c.validateM6()...)
	errs = append(errs, c.validateM8()...)
	errs = append(errs, c.validateEvidence()...)
	errs = append(errs, c.validateRetention()...)
	errs = append(errs, c.validateDataRequests()...)
	errs = append(errs, c.validateCoverage()...)
	errs = append(errs, c.validateGateways()...)
	errs = append(errs, c.validateDev()...)
	errs = append(errs, c.validateDevSlack()...)
	errs = append(errs, c.validateObservability()...)
	errs = append(errs, c.validateLimits()...)
	if err := c.CEL.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("cel: %w", err))
	}
	if _, err := c.trustedProxies(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// dbConfig builds a pool configuration for user with the password from file.
func (c *Config) dbConfig(user, passwordFile string, maxConns int) (db.Config, error) {
	pw, err := config.ReadSecretFile(passwordFile)
	if err != nil {
		return db.Config{}, err
	}
	return db.Config{
		Host: c.DB.Host, Port: c.DB.Port, Database: c.DB.Name, User: user, Password: pw,
		SSLMode: c.DB.SSLMode, SSLRootCert: c.DB.SSLRootCert,
		MaxConns:         int32(maxConns), //nolint:gosec // G115: validated by db.Config.Validate (≤ 1000)
		StatementTimeout: c.DB.StatementTimeout.D(), LockTimeout: c.DB.LockTimeout.D(),
		IdleInTxTimeout: c.DB.IdleInTxTimeout.D(), ApplicationName: "pantherclaw-server",
		RequireUnprivileged: user != c.DB.MigratorUser,
	}, nil
}

// shutdownGrace bounds graceful shutdown.
const shutdownGrace = 20 * time.Second

// AuthorityConfig configures permit timing, and the terms of the grant
// `dev seed` issues to its workload: at most grant_max_per_action per refund,
// in grant_currency. budget_name named the M1.5 development budget; since
// M4 decisions use grants and it is ignored: it may be left out, and is still
// accepted so existing configurations load. budget_lock_timeout is how long a decision waits for
// a contended budget or counter row before it answers CANNOT_AUTHORIZE
// BUDGET_BUSY (ADR-0015).
type AuthorityConfig struct {
	GrantMaxPerAction string          `json:"grant_max_per_action" env:"PC_AUTHORITY_GRANT_MAX"`
	GrantCurrency     string          `json:"grant_currency" env:"PC_AUTHORITY_GRANT_CURRENCY"`
	BudgetName        string          `json:"budget_name" env:"PC_AUTHORITY_BUDGET_NAME"`
	PermitTTL         config.Duration `json:"permit_ttl" env:"PC_AUTHORITY_PERMIT_TTL"`
	StaleDispatch     config.Duration `json:"stale_dispatch_after" env:"PC_AUTHORITY_STALE_DISPATCH"`
	BudgetLockTimeout config.Duration `json:"budget_lock_timeout" env:"PC_AUTHORITY_BUDGET_LOCK_TIMEOUT"`
}

func (c *Config) validateAuthority() []error {
	var errs []error
	if m, err := money.ParseMoney(c.Authority.GrantMaxPerAction, c.Authority.GrantCurrency); err != nil {
		errs = append(errs, fmt.Errorf("authority.grant_max_per_action/currency: %w", err))
	} else if m.Amount.Sign() <= 0 {
		errs = append(errs, errors.New("authority.grant_max_per_action must be positive"))
	}
	if c.Authority.PermitTTL.D() < time.Second || c.Authority.PermitTTL.D() > time.Minute {
		errs = append(errs, errors.New("authority.permit_ttl must be 1s..1m (HR-009 expects about 5s)"))
	}
	if c.Authority.StaleDispatch.D() < 30*time.Second {
		errs = append(errs, errors.New("authority.stale_dispatch_after must be at least 30s (the sweep lister looks for dispatches older than 30s)"))
	}
	if d := c.Authority.BudgetLockTimeout.D(); d < 10*time.Millisecond || d > time.Second {
		errs = append(errs, errors.New("authority.budget_lock_timeout must be 10ms..1s, well below the gateway's timeout (ADR-0015)"))
	}
	return errs
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// AuthConfig configures control-plane authentication (ADR-0016).
type AuthConfig struct {
	// PublicURL is the server's external base URL. It is the access-token
	// issuer and the base of the OAuth and device-login endpoints. HTTPS is
	// required unless the host is loopback.
	PublicURL string `json:"public_url" env:"PC_AUTH_PUBLIC_URL"`
	// APIKeyEnv is the pck_ key environment this deployment accepts and
	// mints: dev, test or live.
	APIKeyEnv string `json:"api_key_env" env:"PC_AUTH_API_KEY_ENV"`
	// OIDCProviders are the identity providers for pclaw login.
	OIDCProviders []OIDCProviderConfig `json:"oidc_providers"`
}

func (c *Config) validateAuth() []error {
	var errs []error
	u, err := url.Parse(c.Auth.PublicURL)
	switch {
	case err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || strings.HasSuffix(c.Auth.PublicURL, "/"):
		errs = append(errs, errors.New("auth.public_url must be an absolute URL without path, query or trailing slash, for example https://pantherclaw.example.com"))
	case u.Scheme == "https":
	case u.Scheme == "http" && loopback(u.Host):
	case u.Scheme == "http" && u.Port() == "" && loopback(u.Host+":80"):
	default:
		errs = append(errs, errors.New("auth.public_url must use https unless the host is loopback"))
	}
	if !credential.Env(c.Auth.APIKeyEnv).Valid() {
		errs = append(errs, errors.New("auth.api_key_env must be dev, test or live"))
	}
	return errs
}

// oauthRateLimit bounds requests per client IP per minute to the
// unauthenticated OAuth endpoints (SB-2 brute-force limits).
const oauthRateLimit = 120

// OIDCProviderConfig configures one OpenID provider PantherClaw signs people
// in with (ADR-0016). Register <public_url>/oauth2/callback/<name> as its
// redirect URI.
type OIDCProviderConfig struct {
	Name             string   `json:"name"`
	Issuer           string   `json:"issuer"`
	ClientID         string   `json:"client_id"`
	ClientSecretFile string   `json:"client_secret_file"`
	Scopes           []string `json:"scopes"`
	// TrustEmail accepts the email claim without email_verified (for an
	// administered directory such as Entra ID).
	TrustEmail bool `json:"trust_email"`
	// AllowInsecureLoopback allows an http:// issuer on a loopback host
	// (local Keycloak). Development only.
	AllowInsecureLoopback bool `json:"allow_insecure_loopback"`
	// SubjectTokenAudience, when set, accepts this provider's tokens as RFC
	// 8693 subject tokens at StartRun when their aud contains it, so a run
	// can represent a signed-in user (HR-145). Leave it empty otherwise.
	SubjectTokenAudience string `json:"subject_token_audience"`
	// TokenAuth is how the client secret goes to the token endpoint:
	// basic (client_secret_basic, the default) or post
	// (client_secret_post) (G0 UI D32).
	TokenAuth string `json:"token_auth"`
	// Dev marks a development identity provider (a mock server or a local
	// Keycloak realm); a production deployment refuses it (HR-346).
	Dev bool `json:"dev"`
}

func (c *Config) validateOIDC() []error {
	var errs []error
	seen := map[string]bool{}
	for i, p := range c.Auth.OIDCProviders {
		at := fmt.Sprintf("auth.oidc_providers[%d]", i)
		if seen[p.Name] {
			errs = append(errs, fmt.Errorf("%s: duplicate name %q", at, p.Name))
		}
		seen[p.Name] = true
		if p.ClientSecretFile == "" {
			errs = append(errs, fmt.Errorf("%s: client_secret_file is required", at))
		}
		if _, err := oidcrp.New(oidcrp.Config{
			Name: p.Name, Issuer: p.Issuer, ClientID: p.ClientID, ClientSecret: pclog.NewSecret([]byte("x")),
			AllowInsecureLoopback: p.AllowInsecureLoopback, SubjectTokenAudience: p.SubjectTokenAudience, TokenAuth: p.TokenAuth,
		}); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", at, err))
		}
	}
	return errs
}

// oidcProviders builds the configured providers, reading their secrets.
func (c *Config) oidcProviders() ([]*oidcrp.Provider, error) {
	var out []*oidcrp.Provider
	for _, p := range c.Auth.OIDCProviders {
		secret, err := config.ReadSecretFile(p.ClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("oidc provider %q: %w", p.Name, err)
		}
		prov, err := oidcrp.New(oidcrp.Config{
			Name: p.Name, Issuer: p.Issuer, ClientID: p.ClientID, ClientSecret: secret, Scopes: p.Scopes,
			TrustEmail: p.TrustEmail, AllowInsecureLoopback: p.AllowInsecureLoopback, SubjectTokenAudience: p.SubjectTokenAudience, TokenAuth: p.TokenAuth,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, prov)
	}
	return out, nil
}

// trustedProxies parses http.trusted_proxies (single addresses become
// host prefixes).
func (c *Config) trustedProxies() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.HTTP.TrustedProxies))
	for _, s := range c.HTTP.TrustedProxies {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("http.trusted_proxies: %q is not an IP address or CIDR", s)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}
