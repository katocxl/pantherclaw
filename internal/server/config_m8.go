// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"net"
	"net/url"
	"regexp"
)

// GitHubConfig configures GitHub sign-in (G0 M8 P2f, HR-207): how a person
// proves which GitHub account is theirs before it is linked to them. The
// GitHub App's device flow must be enabled.
type GitHubConfig struct {
	// ClientID is the GitHub App's client id. Empty turns GitHub sign-in
	// off: nobody can link a GitHub account, so nobody approves GitHub
	// merges.
	ClientID string `json:"client_id" env:"PC_GITHUB_CLIENT_ID"`
	// WebURL is where people sign in and pclaw asks for device codes
	// (default https://github.com).
	WebURL string `json:"web_url" env:"PC_GITHUB_WEB_URL"`
	// APIURL is where the server asks which account a sign-in's token
	// belongs to (default https://api.github.com).
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
		if g.WebURL != "" || g.APIURL != "" {
			return []error{errors.New("github: web_url and api_url need github.client_id")}
		}
		return nil
	}
	web, api := g.URLs()
	var errs []error
	if !clientIDRe.MatchString(g.ClientID) {
		errs = append(errs, errors.New("github.client_id must be the GitHub App's client id"))
	}
	for name, raw := range map[string]string{"github.web_url": web, "github.api_url": api} {
		if !githubURL(raw) {
			errs = append(errs, errors.New(name+" must be https://host[:port] (http only for a loopback simulator)"))
		}
	}
	return errs
}

// githubURL accepts https://host[:port], or http to a loopback address (the
// GitHub simulator).
func githubURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback()))
}
