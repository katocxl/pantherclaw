// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

func isWindows() bool { return runtime.GOOS == "windows" }

// session supplies a bearer credential: an API key from the environment, or
// the stored CLI session, refreshed shortly before the access token expires.
type session struct {
	a      *app
	server string
	apiKey string

	mu    sync.Mutex
	creds Credentials
}

func (a *app) session() (*session, error) {
	if key, ok := a.env("PANTHERCLAW_API_KEY"); ok && key != "" {
		server, _ := a.env("PANTHERCLAW_SERVER")
		base, err := checkServer(server)
		if err != nil {
			return nil, fmt.Errorf("PANTHERCLAW_SERVER: %w", err)
		}
		return &session{a: a, server: base, apiKey: key}, nil
	}
	c, err := loadCreds(a.env)
	if err != nil {
		return nil, err
	}
	return &session{a: a, server: c.Server, creds: c}, nil
}

// bearer returns a valid credential, refreshing the stored session if its
// access token expires within a minute.
func (s *session) bearer(ctx context.Context) (string, error) {
	if s.apiKey != "" {
		return s.apiKey, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Until(s.creds.AccessExpiry) > time.Minute {
		return s.creds.AccessToken, nil
	}
	priv, err := s.creds.deviceKey()
	if err != nil {
		return "", err
	}
	tr, err := (oauthClient{server: s.server, http: s.a.http}).refresh(ctx, s.creds.RefreshToken, priv)
	var oe *oauthError
	if errors.As(err, &oe) && oe.Code == "invalid_grant" {
		return "", errors.New("your session has ended (expired, revoked or logged out elsewhere); run pclaw login again")
	} else if err != nil {
		return "", err
	}
	s.creds.AccessToken, s.creds.RefreshToken = tr.AccessToken, tr.RefreshToken
	s.creds.AccessExpiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	if err := saveCreds(s.a.env, s.creds); err != nil {
		return "", fmt.Errorf("pclaw: saving the refreshed session: %w", err)
	}
	return s.creds.AccessToken, nil
}

type authTransport struct {
	s    *session
	base http.RoundTripper
}

func (t authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tok, err := t.s.bearer(r.Context())
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+tok)
	return t.base.RoundTrip(r)
}

func (s *session) connect() *connect.Client {
	base := s.a.http.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	hc := &http.Client{Transport: authTransport{s: s, base: base}, Timeout: s.a.http.Timeout, CheckRedirect: s.a.http.CheckRedirect}
	return connect.NewClient(connecthttp.NewTransport(hc, s.server))
}

type clients struct {
	tenancy  pantherclawv1connect.TenancyServiceClient
	access   pantherclawv1connect.AccessServiceClient
	sa       pantherclawv1connect.ServiceAccountServiceClient
	agents   pantherclawv1connect.AgentServiceClient
	identity pantherclawv1connect.IdentityServiceClient
	waitlist pantherclawv1connect.WaitlistServiceClient
	runs     pantherclawv1connect.RunServiceClient
	// M5 part 1.
	account       pantherclawv1connect.AccountServiceClient
	notifications pantherclawv1connect.NotificationServiceClient
	// M4.
	grants     pantherclawv1connect.GrantServiceClient
	guardrails pantherclawv1connect.GuardrailServiceClient
	facts      pantherclawv1connect.FactServiceClient
	packages   pantherclawv1connect.PackageServiceClient
	policies   pantherclawv1connect.PolicyServiceClient
	m6Clients
	m5p2Clients
	m7Clients
}

func (a *app) clients() (clients, error) {
	s, err := a.session()
	if err != nil {
		return clients{}, err
	}
	c := s.connect()
	return clients{
		tenancy:       pantherclawv1connect.NewTenancyServiceClient(c),
		access:        pantherclawv1connect.NewAccessServiceClient(c),
		sa:            pantherclawv1connect.NewServiceAccountServiceClient(c),
		agents:        pantherclawv1connect.NewAgentServiceClient(c),
		identity:      pantherclawv1connect.NewIdentityServiceClient(c),
		waitlist:      pantherclawv1connect.NewWaitlistServiceClient(c),
		runs:          pantherclawv1connect.NewRunServiceClient(c),
		account:       pantherclawv1connect.NewAccountServiceClient(c),
		notifications: pantherclawv1connect.NewNotificationServiceClient(c),
		grants:        pantherclawv1connect.NewGrantServiceClient(c),
		guardrails:    pantherclawv1connect.NewGuardrailServiceClient(c),
		facts:         pantherclawv1connect.NewFactServiceClient(c),
		packages:      pantherclawv1connect.NewPackageServiceClient(c),
		policies:      pantherclawv1connect.NewPolicyServiceClient(c),
		m6Clients: m6Clients{
			gateways:    pantherclawv1connect.NewGatewayAdminServiceClient(c),
			containment: pantherclawv1connect.NewContainmentServiceClient(c),
			connections: pantherclawv1connect.NewConnectionServiceClient(c),
		},
		m5p2Clients: m5p2Clients{approvals: pantherclawv1connect.NewApprovalServiceClient(c)},
		m7Clients: m7Clients{
			transactions:    pantherclawv1connect.NewTransactionServiceClient(c),
			reconciliations: pantherclawv1connect.NewReconciliationServiceClient(c),
			evidence:        pantherclawv1connect.NewEvidenceServiceClient(c),
		},
	}, nil
}

func whoami(ctx context.Context, a *app, args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	res, err := c.access.WhoAmI(ctx, &pantherclawv1.WhoAmIRequest{})
	if err != nil {
		return err
	}
	var roles []string
	for _, b := range res.GetBindings() {
		scope := strings.ToLower(strings.TrimPrefix(b.GetScope().GetType().String(), "SCOPE_TYPE_"))
		if b.GetScope().GetId() != "" {
			scope += " " + b.GetScope().GetId()
		}
		roles = append(roles, b.GetRole()+" ("+scope+")")
	}
	if len(roles) == 0 {
		roles = []string{"none"}
	}
	_, err = fmt.Fprintf(a.stdout, "Signed in to %s (%s) as %s via %s\nRoles: %s\n",
		res.GetOrgName(), res.GetOrgId(), res.GetPrincipal().GetDisplayName(), res.GetCredential(), strings.Join(roles, ", "))
	return err
}
