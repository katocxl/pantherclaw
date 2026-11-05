// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pc-agentcore-interceptor: the request interceptor Lambda of one
// Amazon Bedrock AgentCore gateway (G0 M34 D995; HR-766). AgentCore calls it
// before each request reaches a target; it asks the customer's own
// PantherClaw gateway (POST /runtime/agentcore, PAP/1) and returns the
// gateway's interceptor output. Any error answers with a deny: a tool call
// PantherClaw cannot decide does not run.
//
// It uses only the standard library's HTTP client to run the Lambda Runtime
// API loop (no aws-lambda-go). With --local ADDR it serves POST /invoke on a
// loopback address instead, for the simulator and end-to-end tests.
//
// Its workload key is an Ed25519 key made in memory at cold start, never
// written anywhere. It enrolls with an aws_iam attestation signed with the
// Lambda role's credentials. Tool arguments are never logged.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The configuration's environment variables (D995).
const (
	envServerURL  = "PC_SERVER_URL"
	envGatewayURL = "PC_GATEWAY_URL"
	envOrg        = "PC_ORG"
	envRuntimeAPI = "AWS_LAMBDA_RUNTIME_API"
	envFunction   = "AWS_LAMBDA_FUNCTION_NAME"
	envLogStream  = "AWS_LAMBDA_LOG_STREAM_NAME"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stderr)
	stop()
	os.Exit(code)
}

// config is the interceptor's configuration.
type config struct {
	server, gateway string
	org             ids.OrgID
	local           string
	runtimeAPI      string
	runName         string
	aws             workloadclient.AWSCredentials
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	fs := flag.NewFlagSet("pc-agentcore-interceptor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	local := fs.String("local", "", "serve POST /invoke on this loopback address (simulator and tests) instead of the Lambda Runtime API")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := loadConfig(*local)
	if err != nil {
		log.Error("interceptor.config", "error", err.Error())
		return 2
	}
	ic, err := newInterceptor(c, log)
	if err != nil {
		log.Error("interceptor.start", "error", err.Error())
		return 1
	}
	// Enrolment, token renewal and the run go on in the background: until
	// they are in place every invocation is answered with a deny.
	go ic.identity(ctx)
	if c.local != "" {
		err = ic.serveLocal(ctx, c.local)
	} else {
		err = ic.serveLambda(ctx, c.runtimeAPI)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Error("interceptor.stopped", "error", err.Error())
		return 1
	}
	return 0
}

func loadConfig(local string) (config, error) {
	get := func(k string) string { return strings.TrimSpace(os.Getenv(k)) }
	c := config{local: local, runtimeAPI: get(envRuntimeAPI)}
	var err error
	if c.server, err = baseURL(envServerURL, get(envServerURL)); err != nil {
		return c, err
	}
	if c.gateway, err = baseURL(envGatewayURL, get(envGatewayURL)); err != nil {
		return c, err
	}
	if c.org, err = ids.Parse[ids.Org](get(envOrg)); err != nil {
		return c, fmt.Errorf("%s must be the org's id", envOrg)
	}
	if local != "" {
		if ap, perr := netip.ParseAddrPort(local); perr != nil || !ap.Addr().IsLoopback() {
			return c, fmt.Errorf("--local listens on a loopback address only, not %q", local)
		}
	} else if c.runtimeAPI == "" {
		return c, fmt.Errorf("%s is not set: run in AWS Lambda, or pass --local", envRuntimeAPI)
	}
	c.aws = workloadclient.AWSCredentials{
		AccessKey: get("AWS_ACCESS_KEY_ID"), SecretKey: get("AWS_SECRET_ACCESS_KEY"), SessionToken: get("AWS_SESSION_TOKEN"),
		Region: get("AWS_REGION"),
	}
	if c.aws.Region == "" {
		c.aws.Region = get("AWS_DEFAULT_REGION")
	}
	if c.aws.AccessKey == "" || c.aws.SecretKey == "" {
		return c, errors.New("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set (the Lambda role's credentials)")
	}
	fn, stream := get(envFunction), get(envLogStream)
	if fn == "" || stream == "" {
		return c, fmt.Errorf("%s and %s are not set", envFunction, envLogStream)
	}
	c.runName = runName(fn, stream)
	return c, nil
}

// maxRunName is the longest run name StartRuntimeRun takes (D992).
const maxRunName = 200

// runName is the Lambda's run name, agentcore:<function>:<log stream>
// (G0 M34 D995a): every character outside [A-Za-z0-9._:/-] becomes "-"
// (a log stream's "[$LATEST]" becomes "--LATEST-"), and a name over 200
// characters loses the end of its function part, so the stream stays
// whole.
func runName(fn, stream string) string {
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			switch {
			case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', strings.ContainsRune("._:/-", r):
				return r
			}
			return '-'
		}, s)
	}
	fn, stream = clean(fn), clean(stream)
	if over := len("agentcore:"+fn+":"+stream) - maxRunName; over > 0 {
		fn = fn[:max(len(fn)-over, 0)]
	}
	name := "agentcore:" + fn + ":" + stream
	if len(name) > maxRunName {
		// Only a stream over 189 characters gets here; Lambda's are far shorter.
		name = name[:maxRunName]
	}
	return name
}

// baseURL checks a base URL: https, or plain http to a loopback address.
func baseURL(name, raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%s is not set", name)
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return "", fmt.Errorf("%s %q must be a base URL", name, raw)
	}
	if u.Scheme != "https" {
		a, perr := netip.ParseAddr(u.Hostname())
		if u.Scheme != "http" || perr != nil || !a.IsLoopback() {
			return "", fmt.Errorf("%s %q must use https", name, raw)
		}
	}
	return u.Scheme + "://" + u.Host, nil
}
