// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"crypto/rsa"
	"errors"
	"flag"
	"io"
	"os"
	"regexp"
	"strings"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/linear"
	"github.com/katocxl/pantherclaw/internal/sim/notion"
	"github.com/katocxl/pantherclaw/internal/sim/salesforce"
	"github.com/katocxl/pantherclaw/internal/sim/snowflake"
)

// runSnowflake serves the simulated Snowflake SQL API (G0 M31 D962).
func runSnowflake(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("snowflake", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["snowflake"], "listen address (loopback)")
	keyFile := fs.String("public-key-file", "", "the user's RSA public key (PEM): only JWTs it verifies pass (otherwise any well-formed one does)")
	async := fs.Int("async", 0, "answer the first N statements 202 (still running)")
	rate := fs.Int("rate-limit", 0, "answer the first N requests with 429")
	unauthorized := fs.Bool("unauthorized", false, "answer every request 401 (a removed public key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var pub *rsa.PublicKey
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		if pub, err = snowflake.ParsePublicKey(b); err != nil {
			return err
		}
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := snowflake.New(pub, snowflake.Faults{Async: *async, RateLimit: *rate, Unauthorized: *unauthorized}, log)
	return serve(ctx, *addr, sim.Handler(), log, "sim.snowflake_listening")
}

var (
	notionTokenPattern = regexp.MustCompile(`^(secret_|ntn_)[A-Za-z0-9]{40,60}$`)
	linearKeyPattern   = regexp.MustCompile(`^lin_api_[A-Za-z0-9]{40}$`)
)

// readSecret reads a one-line secret file.
func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// runSalesforce serves the simulated Salesforce org (G0 M31 D960).
func runSalesforce(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("salesforce", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["salesforce"], "listen address (loopback)")
	clientFile := fs.String("client-file", "", "file holding the only client accepted, as CLIENT_ID:CLIENT_SECRET (otherwise any is)")
	invalidClient := fs.Bool("invalid-client", false, "refuse every token request (invalid_client)")
	expire := fs.Bool("expire-tokens", false, "treat every issued token as expired (401)")
	rate := fs.Int("rate-limit", 0, "answer the first N API requests with 403 REQUEST_LIMIT_EXCEEDED")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var req salesforce.Require
	if *clientFile != "" {
		v, err := readSecret(*clientFile)
		if err != nil {
			return err
		}
		id, secret, ok := strings.Cut(v, ":")
		if !ok || id == "" || secret == "" {
			return errors.New("--client-file must hold CLIENT_ID:CLIENT_SECRET")
		}
		req = salesforce.Require{ClientID: id, ClientSecret: secret}
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := salesforce.New(salesforce.Faults{InvalidClient: *invalidClient, ExpireTokens: *expire, RateLimit: *rate}, log).WithRequire(req)
	return serve(ctx, *addr, sim.Handler(), log, "sim.salesforce_listening")
}

// runNotion serves the simulated Notion API (G0 M31 D960).
func runNotion(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("notion", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["notion"], "listen address (loopback)")
	tokenFile := fs.String("token-file", "", "file holding the only integration token accepted (otherwise any secret_ or ntn_ token is)")
	rate := fs.Int("rate-limit", 0, "answer the first N requests with 429 rate_limited")
	unauthorized := fs.Bool("unauthorized", false, "answer every request 401 (a revoked integration)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var token string
	if *tokenFile != "" {
		v, err := readSecret(*tokenFile)
		if err != nil {
			return err
		}
		if !notionTokenPattern.MatchString(v) {
			return errors.New("--token-file must hold a secret_ or ntn_ integration token")
		}
		token = v
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	return serve(ctx, *addr, notion.New(token, notion.Faults{RateLimit: *rate, Unauthorized: *unauthorized}, log).Handler(), log, "sim.notion_listening")
}

// runLinear serves the simulated Linear GraphQL API (G0 M31 D960).
func runLinear(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("linear", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["linear"], "listen address (loopback)")
	keyFile := fs.String("key-file", "", "file holding the only API key accepted (otherwise any lin_api_ key is)")
	rate := fs.Int("rate-limit", 0, "answer the first N requests with RATELIMITED")
	unauthorized := fs.Bool("unauthorized", false, "answer every request 401 (a revoked key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var key string
	if *keyFile != "" {
		v, err := readSecret(*keyFile)
		if err != nil {
			return err
		}
		if !linearKeyPattern.MatchString(v) {
			return errors.New("--key-file must hold a lin_api_ key")
		}
		key = v
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	return serve(ctx, *addr, linear.New(key, linear.Faults{RateLimit: *rate, Unauthorized: *unauthorized}, log).Handler(), log, "sim.linear_listening")
}
