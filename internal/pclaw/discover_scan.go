// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"slices"
	"strings"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
)

// `pclaw discover scan` starts a gateway's scan of a SaaS tenant or a cloud
// agent runtime through a connection, and `pclaw discover schedule set|clear`
// asks for or stops its daily scan (G0 M34 D997, HR-768). A scan of a
// runtime source (aws_agentcore, vertex_agent_engine, azure_foundry) is also
// scheduled daily unless --daily=false (FQ34-3). A person runs these: each
// daily scan is started as them.

const discoverSources = "copilot_studio|chatgpt_enterprise|aws_agentcore|vertex_agent_engine|azure_foundry"

func init() {
	commands["discover scan"] = command{
		usage: "discover scan --source " + discoverSources + " --connection <id> --tenant <tenant> [--daily=true]",
		run:   discoverScan,
	}
	commands["discover schedule set"] = command{
		usage: "discover schedule set --source " + discoverSources + " --connection <id> --tenant <tenant>",
		run:   func(ctx context.Context, a *app, args []string) error { return discoverSchedule(ctx, a, args, true) },
	}
	commands["discover schedule clear"] = command{
		usage: "discover schedule clear --source " + discoverSources + " --connection <id> --tenant <tenant>",
		run:   func(ctx context.Context, a *app, args []string) error { return discoverSchedule(ctx, a, args, false) },
	}
}

// tenantHelp says what a tenant is for each source.
const tenantHelp = "the Dataverse organization id, the ChatGPT workspace id, the AWS account (AgentCore), " +
	"<project>/<location> (Vertex Agent Engine) or the Foundry project name"

func discoverScan(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("discover scan", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	source := fs.String("source", "", strings.ReplaceAll(discoverSources, "|", ", "))
	connection := fs.String("connection", "", "the connection to scan through")
	tenant := fs.String("tenant", "", tenantHelp)
	daily := fs.Bool("daily", true, "also scan daily (runtime sources only; set --daily=false to scan once)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *source == "" || *connection == "" || *tenant == "" {
		return errUsage
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	client := pantherclawv1connect.NewSaasDiscoveryServiceClient(s.connect())
	res, err := client.StartSaasScan(ctx, &pb.StartSaasScanRequest{ConnectionId: *connection, Source: *source, Tenant: *tenant})
	if err != nil {
		return err
	}
	if err := a.print(res); err != nil {
		return err
	}
	if !*daily || !slices.Contains(domain.RuntimeSources, *source) {
		return nil
	}
	sch, err := client.SetSaaSScanSchedule(ctx, &pb.SetSaaSScanScheduleRequest{Source: *source, ConnectionId: *connection, Tenant: *tenant, Daily: true})
	if err != nil {
		_, _ = fmt.Fprintln(a.stderr, "the scan started, but its daily scan was not set")
		return err
	}
	return a.print(sch)
}

func discoverSchedule(ctx context.Context, a *app, args []string, daily bool) error {
	name := "discover schedule clear"
	if daily {
		name = "discover schedule set"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	source := fs.String("source", "", strings.ReplaceAll(discoverSources, "|", ", "))
	connection := fs.String("connection", "", "the connection scanned")
	tenant := fs.String("tenant", "", tenantHelp)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *source == "" || *connection == "" || *tenant == "" {
		return errUsage
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	res, err := pantherclawv1connect.NewSaasDiscoveryServiceClient(s.connect()).SetSaaSScanSchedule(ctx, &pb.SetSaaSScanScheduleRequest{
		Source: *source, ConnectionId: *connection, Tenant: *tenant, Daily: daily,
	})
	if err != nil {
		return err
	}
	return a.print(res)
}
