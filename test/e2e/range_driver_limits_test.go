// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/server"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// M13's range step (G0 M13 D8, D27; RT-065): api.flood sends calls through
// the API's authentication layer, built exactly as the server builds it
// with the server's default limits, as one credential of a person of the
// org holding the role as. The services behind it answer every call that
// gets through, so only authentication, permissions and the limits decide.

// floodState is one API layer for a scenario's api.flood steps, so their
// calls share the limits: each role is one person with one session (one
// credential), all in the stack's org.
type floodState struct {
	srv   *httptest.Server
	users map[string]ids.UUID // role → the person's session
}

// floodAuthn authenticates the bearer "role:<role>" as the session of the
// org's person holding role.
type floodAuthn struct {
	org   ids.OrgID
	users map[string]ids.UUID
}

func (f floodAuthn) Authenticate(_ context.Context, bearer string) (tapp.Caller, error) {
	role, _ := strings.CutPrefix(bearer, "role:")
	session, ok := f.users[role]
	if !ok {
		return tapp.Caller{}, tapp.ErrNoCaller
	}
	return tapp.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: session},
		Bindings: []td.Binding{{Role: td.RoleName(role), Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}},
	}, Credential: tapp.CredAccessToken, Session: session}, nil
}

// floodServer starts the scenario's API layer: the server's own
// authentication interceptor with its default limits (D8, D27), over
// AgentService and ResponseService handlers that answer Unimplemented.
func (d *rangeDriver) floodServer() (*floodState, error) {
	if d.flood != nil {
		return d.flood, nil
	}
	fs := &floodState{users: map[string]ids.UUID{}}
	cfg := server.DefaultConfig()
	srv, err := rpc.NewServer(rpc.Options{
		Authenticate: rpcauth.New(floodAuthn{org: d.s.org, users: fs.users}, server.ProcedurePermissions(), nil, cfg.APILimits()),
	})
	if err != nil {
		return nil, err
	}
	pantherclawv1connect.RegisterAgentServiceHandler(srv, pantherclawv1connect.UnimplementedAgentServiceHandler{})
	pantherclawv1connect.RegisterResponseServiceHandler(srv, pantherclawv1connect.UnimplementedResponseServiceHandler{})
	mux := http.NewServeMux()
	rpc.Mount(mux, srv)
	fs.srv = httptest.NewServer(mux)
	d.t.Cleanup(fs.srv.Close)
	d.flood = fs
	return fs, nil
}

// apiFlood runs one api.flood step.
func (d *rangeDriver) apiFlood(st domain.Step) (domain.Observation, error) {
	var w struct {
		Procedure string `json:"procedure"`
		As        string `json:"as"`
		Calls     int    `json:"calls"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	if _, ok := server.ProcedurePermissions()[w.Procedure]; !ok {
		return domain.Observation{Outcome: domain.OutcomeNotFound, Detail: "not served"}, nil
	}
	if !strings.HasPrefix(w.Procedure, "/pantherclaw.v1.AgentService/") && !strings.HasPrefix(w.Procedure, "/pantherclaw.v1.ResponseService/") {
		return domain.Observation{Outcome: domain.OutcomeNotFound, Detail: "api.flood serves AgentService and ResponseService"}, nil
	}
	fs, err := d.floodServer()
	if err != nil {
		return domain.Observation{}, err
	}
	if _, ok := fs.users[w.As]; !ok {
		fs.users[w.As] = ids.NewV7()
	}
	ts := fs.srv
	allowed, limited, other, firstOther := 0, 0, 0, ""
	for range w.Calls {
		req, err := http.NewRequest(http.MethodPost, ts.URL+w.Procedure, strings.NewReader("{}"))
		if err != nil {
			return domain.Observation{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer role:"+w.As)
		res, err := ts.Client().Do(req)
		if err != nil {
			return domain.Observation{}, err
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		through := res.StatusCode == http.StatusNotImplemented || res.StatusCode == http.StatusBadRequest
		if !through && res.StatusCode != http.StatusTooManyRequests && firstOther == "" {
			firstOther = fmt.Sprintf("%d %s", res.StatusCode, body)
		}
		switch {
		case through: // past the limits: the request check (400) or the handler (501)
			allowed++
		case res.StatusCode == http.StatusTooManyRequests && res.Header.Get("Retry-After") != "":
			limited++
		default:
			other++
		}
	}
	detail := fmt.Sprintf("%d of %d calls got through, %d rate-limited, %d refused otherwise %s", allowed, w.Calls, limited, other, firstOther)
	switch {
	case other > 0:
		return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "PERMISSION_DENIED", Detail: detail}, nil
	case limited > 0:
		return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "RATE_LIMITED", Detail: detail}, nil
	}
	return domain.Observation{Outcome: domain.OutcomeAllow, Detail: detail}, nil
}
