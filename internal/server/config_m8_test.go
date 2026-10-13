// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import "testing"

// TestGitHubSignInConfigIsValidated (P2f): GitHub sign-in is off without a
// client id, and then takes no URLs or secret; on, it needs the sign-in
// App's client secret file and uses GitHub's own origins unless https ones
// are set (an API URL may have GitHub Enterprise Server's /api/v3), and
// plain http only for a loopback simulator.
func TestGitHubSignInConfigIsValidated(t *testing.T) {
	cases := map[string]struct {
		cfg GitHubConfig
		ok  bool
	}{
		"off":                       {GitHubConfig{}, true},
		"on, GitHub's own":          {GitHubConfig{ClientID: "Iv23liAbCd", ClientSecretFile: "/run/secrets/gh"}, true},
		"GitHub Enterprise":         {GitHubConfig{ClientID: "Iv1.abc", ClientSecretFile: "s", WebURL: "https://ghe.example.com", APIURL: "https://ghe.example.com/api/v3"}, true},
		"the simulator":             {GitHubConfig{ClientID: "Iv1.abc", ClientSecretFile: "s", WebURL: "http://127.0.0.1:9090", APIURL: "http://localhost:9090"}, true},
		"no client secret":          {GitHubConfig{ClientID: "Iv1.abc"}, false},
		"a secret without a client": {GitHubConfig{ClientSecretFile: "s"}, false},
		"a web URL with a path":     {GitHubConfig{ClientID: "Iv1.abc", ClientSecretFile: "s", WebURL: "https://ghe.example.com/api/v3"}, false},
		"URLs without a client":     {GitHubConfig{WebURL: "https://github.com"}, false},
		"a client id with spaces":   {GitHubConfig{ClientID: "Iv1 abc", ClientSecretFile: "s"}, false},
		"plain http elsewhere":      {GitHubConfig{ClientID: "Iv1.abc", ClientSecretFile: "s", APIURL: "http://api.example.com"}, false},
		"an API URL with a path":    {GitHubConfig{ClientID: "Iv1.abc", ClientSecretFile: "s", APIURL: "https://example.com/v3"}, false},
		"credentials in the URL":    {GitHubConfig{ClientID: "Iv1.abc", ClientSecretFile: "s", WebURL: "https://u:p@github.com"}, false},
	}
	for name, c := range cases {
		cfg := Config{GitHub: c.cfg}
		if errs := cfg.validateM8(); (len(errs) == 0) != c.ok {
			t.Errorf("%s: %v", name, errs)
		}
	}
	if web, api := (GitHubConfig{ClientID: "Iv1.abc"}).URLs(); web != "https://github.com" || api != "https://api.github.com" {
		t.Errorf("defaults %s %s", web, api)
	}
}
