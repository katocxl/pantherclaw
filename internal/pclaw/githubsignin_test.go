// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/github/adapters/githubhttp"
	"github.com/katocxl/pantherclaw/internal/platform/log"
	simgithub "github.com/katocxl/pantherclaw/internal/sim/github"
)

// proveService is a server whose GitHub sign-in is the simulator: it asks
// the simulator, as the server asks GitHub, which account a token is.
type proveService struct {
	pantherclawv1connect.UnimplementedGitHubServiceHandler
	web    string
	unlink []bool
}

func (p *proveService) GetSignIn(context.Context, *pantherclawv1.GetSignInRequest) (*pantherclawv1.GetSignInResponse, error) {
	return &pantherclawv1.GetSignInResponse{ClientId: "Iv1.pantherclaw", WebUrl: p.web}, nil
}

func (p *proveService) ProveIdentity(ctx context.Context, req *pantherclawv1.ProveIdentityRequest) (*pantherclawv1.ProveIdentityResponse, error) {
	u, err := (&githubhttp.Verifier{APIURL: p.web, ClientID: "Iv1.pantherclaw", ClientSecret: log.NewSecret([]byte("s3cret"))}).User(ctx, req.GetGithubUserToken())
	if err != nil {
		return nil, err
	}
	p.unlink = append(p.unlink, req.GetUnlink())
	return &pantherclawv1.ProveIdentityResponse{Identity: &pantherclawv1.GitHubIdentity{GithubLogin: u.Login, GithubUserId: u.ID}}, nil
}

// TestHR207_GitHubLinkSignsInToGitHub (P2f): pclaw github link runs the
// GitHub App's device flow, shows the code to enter at GitHub, and hands
// the user access token of the account signed in to the server, which
// links it; pclaw github unlink proves the account the same way to remove
// the link. Neither writes the token anywhere, and neither signs in at a
// GitHub address that is not https (plain http only on this machine).
func TestHR207_GitHubLinkSignsInToGitHub(t *testing.T) {
	sim := simgithub.New(log.Discard())
	sim.RegisterSignInApp("Iv1.pantherclaw", "s3cret")
	sim.SignInAs(simgithub.DeviceUser{ID: 101, Login: "alice-gh"})
	gh := httptest.NewServer(sim.Handler())
	t.Cleanup(gh.Close)
	svc := &proveService{web: gh.URL}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterGitHubServiceHandler(cs, svc)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})

	code, out, errs := run(t, env, "github", "link")
	if code != 0 || !strings.Contains(out, "alice-gh") || !strings.Contains(out, "101") || !strings.Contains(errs, "enter the code") {
		t.Fatalf("github link = %d\n%s\n%s", code, out, errs)
	}
	if code, out, errs := run(t, env, "github", "unlink"); code != 0 || !strings.Contains(out, "alice-gh") ||
		!strings.Contains(errs, "to unlink") {
		t.Fatalf("github unlink = %d\n%s\n%s", code, out, errs)
	}
	if len(svc.unlink) != 2 || svc.unlink[0] || !svc.unlink[1] {
		t.Fatalf("proofs %v", svc.unlink)
	}
	if strings.Contains(out, "ghu_") || strings.Contains(errs, "ghu_") {
		t.Fatal("pclaw printed the GitHub token")
	}
	if code, _, _ := run(t, env, "github", "link", "extra"); code == 0 {
		t.Fatal("github link took an argument")
	}
	for _, web := range []string{"http://github.example.com", "ftp://github.com", "https://u:p@github.com"} {
		svc.web = web
		if code, _, errs := run(t, env, "github", "link"); code == 0 || !strings.Contains(errs, "not https") {
			t.Errorf("%s: %d %s", web, code, errs)
		}
	}
}
