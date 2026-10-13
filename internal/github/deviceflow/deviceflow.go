// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package deviceflow runs a GitHub App's device flow for a user access
// token (G0 M8 P2f, RFC 8628): the person signs in to GitHub in a browser,
// and the token lets PantherClaw ask GitHub which account they signed in
// as. pclaw hands the token to the server once and keeps it nowhere.
package deviceflow

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// Errors that end a sign-in.
var (
	ErrDenied  = errors.New("deviceflow: the sign-in was refused at GitHub")
	ErrExpired = errors.New("deviceflow: the code expired before anyone signed in")
)

// maxWait caps how long a sign-in may take whatever GitHub says.
const maxWait = 15 * time.Minute

// grantType is the device flow's grant (RFC 8628).
const grantType = "urn:ietf:params:oauth:grant-type:device_code"

// Code is what the person enters, and where.
type Code struct {
	UserCode        string
	VerificationURI string
	Expires         time.Time
}

// Flow asks GitHub for a user access token through the device flow.
type Flow struct {
	// WebURL is GitHub's web origin (https://github.com, or the simulator).
	WebURL string
	// ClientID is the GitHub App's client id.
	ClientID string
	// Client sends the requests; nil uses a 15-second client that follows no
	// redirects and ignores proxy variables.
	Client *http.Client
	// Wait waits between polls; nil sleeps (tests replace it).
	Wait func(ctx context.Context, d time.Duration) error
}

// Token asks GitHub for a device code, shows its user code, and polls until
// the person signs in (the token), refuses (ErrDenied) or the code expires
// (ErrExpired).
func (f *Flow) Token(ctx context.Context, show func(Code)) (string, error) {
	var start struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
		Error           string `json:"error"`
	}
	if err := f.post(ctx, "/login/device/code", url.Values{"client_id": {f.ClientID}}, &start); err != nil {
		return "", err
	}
	if start.DeviceCode == "" || start.UserCode == "" {
		return "", fmt.Errorf("deviceflow: GitHub gave no device code (%q): is the App's device flow enabled?", start.Error)
	}
	if !sameOrigin(start.VerificationURI, f.WebURL) {
		return "", fmt.Errorf("deviceflow: the sign-in page %q is not on %s", start.VerificationURI, f.WebURL)
	}
	interval := time.Duration(max(start.Interval, 1)) * time.Second
	life := min(time.Duration(start.ExpiresIn)*time.Second, maxWait)
	if life <= 0 {
		life = maxWait
	}
	deadline := time.Now().Add(life)
	show(Code{UserCode: start.UserCode, VerificationURI: start.VerificationURI, Expires: deadline})
	for time.Now().Before(deadline) {
		if err := f.wait(ctx, interval); err != nil {
			return "", err
		}
		var poll struct {
			AccessToken string `json:"access_token"`
			Error       string `json:"error"`
			Interval    int    `json:"interval"`
		}
		if err := f.post(ctx, "/login/oauth/access_token", url.Values{
			"client_id": {f.ClientID}, "device_code": {start.DeviceCode}, "grant_type": {grantType},
		}, &poll); err != nil {
			return "", err
		}
		switch poll.Error {
		case "":
			if poll.AccessToken == "" {
				return "", errors.New("deviceflow: GitHub answered without a token")
			}
			return poll.AccessToken, nil
		case "authorization_pending":
		case "slow_down":
			interval = max(interval+5*time.Second, time.Duration(poll.Interval)*time.Second)
		case "expired_token":
			return "", ErrExpired
		case "access_denied":
			return "", ErrDenied
		default:
			return "", fmt.Errorf("deviceflow: GitHub refused the sign-in: %s", poll.Error)
		}
	}
	return "", ErrExpired
}

// sameOrigin reports whether a sign-in page is on GitHub's web origin, so
// the code a person is shown is entered at GitHub and nowhere else.
func sameOrigin(page, web string) bool {
	p, err := url.Parse(page)
	w, werr := url.Parse(web)
	return err == nil && werr == nil && p.User == nil && p.Scheme == w.Scheme && strings.EqualFold(p.Host, w.Host) && p.Host != ""
}

func (f *Flow) wait(ctx context.Context, d time.Duration) error {
	if f.Wait != nil {
		return f.Wait(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// post sends a form to GitHub's web origin and decodes its JSON answer;
// GitHub answers the device flow's errors as JSON too.
func (f *Flow) post(ctx context.Context, path string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(f.WebURL, "/")+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	c := f.Client
	if c == nil {
		c = httpx.NewControlClient(httpx.ControlConfig{Timeout: 15 * time.Second})
	}
	res, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("deviceflow: %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("deviceflow: %s: %w", path, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("deviceflow: %s answered HTTP %d that is not JSON", path, res.StatusCode)
	}
	return nil
}
