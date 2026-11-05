// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"io"
	"strings"
	"testing"
)

// sandboxRunArgs are the flags sandbox run needs, then extra ones.
func sandboxRunArgs(extra ...string) []string {
	return append([]string{
		"--agent", "a", "--connection", "anthropic", "--grant", "g", "--gateway", "http://127.0.0.1:8090",
		"--image", "x@sha256:" + strings.Repeat("a", 64), "--edge-image", "sha256:" + strings.Repeat("b", 64),
		"--probe-image", "sha256:" + strings.Repeat("c", 64),
	}, extra...)
}

// TestHR697_SandboxRunEnvRefusesWhatTheSandboxSetsAndCredentials: --env
// passes an ordinary variable and a run cap; it refuses the proxy, CA,
// home, model key and PantherClaw names (any case) and a value the edge's
// detector names as a credential, and the error names the variable
// without its value (G0 M29 D822, D823).
//
// Covers: F983, F984, HR-697
func TestHR697_SandboxRunEnvRefusesWhatTheSandboxSetsAndCredentials(t *testing.T) {
	a := &app{stderr: io.Discard, env: func(string) (string, bool) { return "", false }}
	f, err := parseSandboxRun(a, sandboxRunArgs("--env", "TASK_MODE=review", "--env", "LOG_LEVEL=debug", "--max-tokens", "5000"))
	if err != nil || len(f.env) != 2 || f.maxTokens != 5000 {
		t.Fatalf("an ordinary --env and --max-tokens: %+v, %v", f, err)
	}
	// A key-shaped value, built from parts so no scanner flags this file.
	key := "sk-" + "ant-" + "api03-" + strings.Repeat("Q", 40)
	pem := "-----" + "BEGIN PRIVATE KEY-----"
	for _, entry := range []string{
		"HTTPS_PROXY=http://evil.example:3128", "https_proxy=http://evil.example:3128", "ALL_PROXY=socks5://x", "NO_PROXY=*",
		"SSL_CERT_FILE=/tmp/ca.pem", "NODE_EXTRA_CA_CERTS=/tmp/ca.pem", "NODE_TLS_REJECT_UNAUTHORIZED=0", "NODE_USE_ENV_PROXY=0",
		"HOME=/root", "ANTHROPIC_API_KEY=x", "openai_api_key=x", "PC_RUN=x", "PANTHERCLAW_TOKEN=x",
		"MY_KEY=" + key, "MY_PEM=" + pem, "BAD-NAME=x", "1X=x", "X=a\nb",
	} {
		_, err := parseSandboxRun(a, sandboxRunArgs("--env", entry))
		if err == nil {
			t.Errorf("--env %q passed", entry)
			continue
		}
		if _, value, _ := strings.Cut(entry, "="); len(value) > 1 && strings.Contains(err.Error(), value) {
			t.Errorf("--env %q: the error repeats the value: %v", entry, err)
		}
	}
	for _, n := range []string{"-1", "1000000000001"} {
		if _, err := parseSandboxRun(a, sandboxRunArgs("--max-tokens", n)); err == nil {
			t.Errorf("--max-tokens %s passed", n)
		}
	}
	many := []string{}
	for range 65 {
		many = append(many, "--env", "A=b")
	}
	if _, err := parseSandboxRun(a, sandboxRunArgs(many...)); err == nil {
		t.Error("65 --env entries passed")
	}
}

// TestT317_AKeyOrAProxyOverrideCannotBeSmuggledIntoTheSandbox: the
// variations an attacker would try first (mixed case, the OpenAI legacy
// and project key formats, a key after a prefix of its own) are refused
// before anything starts.
//
// Covers: HR-697
func TestT317_AKeyOrAProxyOverrideCannotBeSmuggledIntoTheSandbox(t *testing.T) {
	a := &app{stderr: io.Discard, env: func(string) (string, bool) { return "", false }}
	for _, entry := range []string{
		"Https_Proxy=http://evil.example", "Node_Extra_Ca_Certs=/x", "Requests_Ca_Bundle=/x", "Git_Ssl_Cainfo=/x",
		"Anthropic_Auth_Token=x", "Pc_anything=x",
		"K=" + "sk-" + "proj-" + strings.Repeat("a", 40),
		"K=" + "sk-" + strings.Repeat("A1", 20),
	} {
		if _, err := parseSandboxRun(a, sandboxRunArgs("--env", entry)); err == nil {
			t.Errorf("--env %q passed", entry)
		}
	}
	// A short sk- value is not a key format: it passes, as a value only.
	if _, err := parseSandboxRun(a, sandboxRunArgs("--env", "K=sk-short")); err != nil {
		t.Errorf("a short sk- value: %v", err)
	}
}
