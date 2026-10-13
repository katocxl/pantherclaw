// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/github/deviceflow"
)

// GitHub sign-in (G0 M8 P2f, HR-207): pclaw github link proves which GitHub
// account is yours. It runs the GitHub App's device flow, so you sign in to
// GitHub in a browser, then hands the user access token to the server once;
// the server asks GitHub which account it belongs to and links it to you.
// pclaw github unlink removes your link the same way. The token is never
// written anywhere.

func init() {
	commands["github link"] = command{usage: "github link", run: githubSignIn(false)}
	commands["github unlink"] = command{usage: "github unlink", run: githubSignIn(true)}
}

func githubSignIn(unlink bool) func(context.Context, *app, []string) error {
	return func(ctx context.Context, a *app, args []string) error {
		if len(args) != 0 {
			return errUsage
		}
		c, err := a.clients()
		if err != nil {
			return err
		}
		cfg, err := c.github.GetSignIn(ctx, &pantherclawv1.GetSignInRequest{})
		if err != nil {
			return err
		}
		if !githubWeb(cfg.GetWebUrl()) {
			return fmt.Errorf("the server's GitHub sign-in address %q is not https (plain http only on this machine)", cfg.GetWebUrl())
		}
		verb := "link"
		if unlink {
			verb = "unlink"
		}
		flow := &deviceflow.Flow{WebURL: cfg.GetWebUrl(), ClientID: cfg.GetClientId(), Client: a.http}
		token, err := flow.Token(ctx, func(code deviceflow.Code) {
			_, _ = fmt.Fprintf(a.stderr, "Sign in to GitHub as the account to %s: open %s and enter the code %s (it expires in %d minutes).\n",
				verb, code.VerificationURI, code.UserCode, int(time.Until(code.Expires).Minutes()))
		})
		if err != nil {
			return err
		}
		res, err := c.github.ProveIdentity(ctx, &pantherclawv1.ProveIdentityRequest{GithubUserToken: token, Unlink: unlink})
		if err != nil {
			return err
		}
		return a.print(res)
	}
}

// githubWeb reports whether GitHub's web origin, where the code is entered,
// is https, or plain http on this machine (the GitHub simulator).
func githubWeb(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())))
}
