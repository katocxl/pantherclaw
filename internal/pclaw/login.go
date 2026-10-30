// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

// login runs the device login (ADR-0016): a fresh device key, the code the
// person confirms in the browser, polling, and the stored session.
func login(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	server := fs.String("server", "", "PantherClaw server URL, for example https://pantherclaw.example.com")
	org := fs.String("org", "", "organization id")
	invitation := fs.String("invitation", "", "invitation or bootstrap admin token (pci_…), when joining")
	idp := fs.String("idp", "", "identity provider name, when the server has several")
	noBrowser := fs.Bool("no-browser", false, "do not open a browser; print the link only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *org == "" || fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	base, err := checkServer(*server)
	if err != nil {
		return err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pk, err := publicJWK(priv)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	o := oauthClient{server: base, http: a.http}
	var da deviceAuthorization
	if err := o.post(ctx, devicePath, url.Values{
		"client_id": {clientID}, "org": {*org}, "device_jwk": {string(pk.Canonical)}, "device_name": {host},
		"invitation": {*invitation}, "idp": {*idp},
	}, &da); err != nil {
		return fmt.Errorf("pclaw login: %w", err)
	}
	if !strings.HasPrefix(da.VerificationURIComplete, base+"/") {
		return errors.New("pclaw login: the server returned a sign-in link on another site; refusing to use it")
	}
	_, _ = fmt.Fprintf(a.stdout, "To sign in, open:\n\n  %s\n\nand confirm the code %s (it expires in %d minutes).\n",
		da.VerificationURIComplete, da.UserCode, da.ExpiresIn/60)
	if !*noBrowser && a.openBrowser != nil {
		if err := a.openBrowser(ctx, da.VerificationURIComplete); err != nil {
			_, _ = fmt.Fprintln(a.stderr, "(could not open a browser; open the link yourself)")
		}
	}
	tr, err := pollDevice(ctx, o, da, priv, a.stdout)
	if err != nil {
		return fmt.Errorf("pclaw login: %w", err)
	}
	c := Credentials{
		Server: base, Org: *org, AccessToken: tr.AccessToken, AccessExpiry: time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		RefreshToken: tr.RefreshToken, DeviceKey: base64.RawURLEncoding.EncodeToString(priv.Seed()),
	}
	if err := saveCredsTo(a.env, c, a.stderr); err != nil {
		return err
	}
	return whoami(ctx, a, nil)
}

// pollDevice polls the token endpoint at the server's interval until the
// sign-in is approved, denied or expired (RFC 8628 §3.4).
func pollDevice(ctx context.Context, o oauthClient, da deviceAuthorization, priv ed25519.PrivateKey, out io.Writer) (tokenResponse, error) {
	interval := max(time.Duration(da.Interval)*time.Second, minPollInterval)
	deadline := time.Now().Add(time.Duration(da.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return tokenResponse{}, ctx.Err()
		case <-t.C:
		}
		form, err := o.withAssertion(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {da.DeviceCode}}, priv)
		if err != nil {
			return tokenResponse{}, err
		}
		var tr tokenResponse
		err = o.post(ctx, tokenPath, form, &tr)
		var oe *oauthError
		switch {
		case err == nil:
			return tr, nil
		case errors.As(err, &oe) && oe.Code == "authorization_pending":
		case errors.As(err, &oe) && oe.Code == "slow_down":
			interval += slowDownStep
		case errors.As(err, &oe) && oe.Code == "access_denied":
			return tokenResponse{}, errors.New("the sign-in was denied (see the message in the browser)")
		case errors.As(err, &oe) && oe.Code == "expired_token":
			return tokenResponse{}, errExpired
		default:
			return tokenResponse{}, err
		}
		_, _ = fmt.Fprint(out, ".")
	}
	return tokenResponse{}, errExpired
}

// logout revokes the refresh token and deletes the credentials file.
func logout(ctx context.Context, a *app, args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	c, err := loadCreds(a.env)
	if errors.Is(err, ErrNotLoggedIn) {
		_, _ = fmt.Fprintln(a.stdout, "not logged in")
		return nil
	} else if err != nil {
		return err
	}
	if err := (oauthClient{server: c.Server, http: a.http}).revoke(ctx, c.RefreshToken); err != nil {
		_, _ = fmt.Fprintf(a.stderr, "warning: the server did not confirm the logout (%v); the session ends when it expires\n", err)
	}
	if err := deleteCreds(a.env); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(a.stdout, "logged out")
	return nil
}

// Polling pace (RFC 8628 §3.5): never faster than 5 seconds, and 5 seconds
// slower after each slow_down. Variables only so that tests can run fast.
var (
	minPollInterval = 5 * time.Second
	slowDownStep    = 5 * time.Second
)
