// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import "testing"

// TestGitHubSignInConfigIsValidated (P2f): GitHub sign-in is off without a
// client id, and then takes no URLs; on, it uses GitHub's own origins
// unless https ones are set, and plain http only for a loopback simulator.
func TestGitHubSignInConfigIsValidated(t *testing.T) {
	cases := map[string]struct {
		cfg GitHubConfig
		ok  bool
	}{
		"off":                     {GitHubConfig{}, true},
		"on, GitHub's own":        {GitHubConfig{ClientID: "Iv23liAbCd"}, true},
		"GitHub Enterprise":       {GitHubConfig{ClientID: "Iv1.abc", WebURL: "https://ghe.example.com", APIURL: "https://ghe.example.com/"}, true},
		"the simulator":           {GitHubConfig{ClientID: "Iv1.abc", WebURL: "http://127.0.0.1:9090", APIURL: "http://localhost:9090"}, true},
		"URLs without a client":   {GitHubConfig{WebURL: "https://github.com"}, false},
		"a client id with spaces": {GitHubConfig{ClientID: "Iv1 abc"}, false},
		"plain http elsewhere":    {GitHubConfig{ClientID: "Iv1.abc", APIURL: "http://api.example.com"}, false},
		"an API URL with a path":  {GitHubConfig{ClientID: "Iv1.abc", APIURL: "https://example.com/api/v3"}, false},
		"credentials in the URL":  {GitHubConfig{ClientID: "Iv1.abc", WebURL: "https://u:p@github.com"}, false},
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
