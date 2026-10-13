// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// GitHubConfig configures GitHub sign-in (G0 M8 P2f, HR-207): how a person
// proves which GitHub account is theirs before it is linked to them. It is
// a dedicated sign-in App, not the App that merges: a GitHub App with no
// permissions, installed nowhere, with its device flow enabled, so the
// token a sign-in gives can do nothing at GitHub. The server checks each
// token with the App's client secret and then revokes it.
type GitHubConfig struct {
	// ClientID is the sign-in App's client id. Empty turns GitHub sign-in
	// off: nobody can link a GitHub account, so nobody approves GitHub
	// merges.
	ClientID string `json:"client_id" env:"PC_GITHUB_CLIENT_ID"`
	// ClientSecretFile holds the sign-in App's client secret (SB-7: by
	// file path only). Required with client_id.
	ClientSecretFile string `json:"client_secret_file" env:"PC_GITHUB_CLIENT_SECRET_FILE"`
	// WebURL is where people sign in and pclaw asks for device codes
	// (default https://github.com).
	WebURL string `json:"web_url" env:"PC_GITHUB_WEB_URL"`
	// APIURL is where the server asks which account a sign-in's token
	// belongs to (default https://api.github.com; GitHub Enterprise Server
	// serves it at https://host/api/v3).
	APIURL string `json:"api_url" env:"PC_GITHUB_API_URL"`
}

// clientIDRe is what GitHub App client ids look like (Iv1.…, Iv23…).
var clientIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// URLs are the web and API URLs in effect: GitHub's own unless set.
func (g GitHubConfig) URLs() (web, api string) {
	web, api = g.WebURL, g.APIURL
	if web == "" {
		web = "https://github.com"
	}
	if api == "" {
		api = "https://api.github.com"
	}
	return web, api
}

func (c *Config) validateM8() []error {
	g := c.GitHub
	if g.ClientID == "" {
		if g.WebURL != "" || g.APIURL != "" || g.ClientSecretFile != "" {
			return []error{errors.New("github: web_url, api_url and client_secret_file need github.client_id")}
		}
		return nil
	}
	web, api := g.URLs()
	var errs []error
	if !clientIDRe.MatchString(g.ClientID) {
		errs = append(errs, errors.New("github.client_id must be the GitHub App's client id"))
	}
	if g.ClientSecretFile == "" {
		errs = append(errs, errors.New("github.client_secret_file is required with github.client_id: the sign-in App's client secret checks and revokes each sign-in's token"))
	}
	if !githubURL(web, false) {
		errs = append(errs, errors.New("github.web_url must be https://host[:port] (http only for a loopback simulator)"))
	}
	if !githubURL(api, true) {
		errs = append(errs, errors.New("github.api_url must be https://host[:port], or https://host[:port]/api/v3 for GitHub Enterprise Server (http only for a loopback simulator)"))
	}
	return errs
}

// githubURL accepts https://host[:port], or http to a loopback address (the
// GitHub simulator); an API URL may also have GitHub Enterprise Server's
// /api/v3 path.
func githubURL(raw string, api bool) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := strings.TrimSuffix(u.Path, "/")
	if u.Host == "" || u.User != nil || (path != "" && (!api || path != "/api/v3")) || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback()))
}
