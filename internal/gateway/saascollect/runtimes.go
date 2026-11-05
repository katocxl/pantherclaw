// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package saascollect

import (
	"context"
	"encoding/json/v2"
	"net/url"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/parse"
)

// The cloud agent runtimes (G0 M34 D997): each reads one list, page by
// page, through its read-only collector connection. The first decode keeps
// only a record's id, name, times and status (parse.AgentCorePage,
// VertexPage, FoundryPage); an agent's code, role, environment and
// instructions go with the page (HR-635).

// Poster sends one JSON body to a path of the vendor's API with the
// connection's credential placed (AgentCore lists with a POST).
type Poster func(ctx context.Context, path string, body []byte) (egress.Response, error)

// The runtimes' paths, as their packages dispatch them: AgentCore
// ListAgentRuntimes (agentcore.runtimes.list, D993a), Vertex
// reasoningEngines.list (vertex.reasoning_engines.list) and Foundry's
// project agents (foundry.agents.list; its shape is unconfirmed, R-85).
const (
	agentCoreRuntimesPath = "/runtimes/"
	foundryAgentsPath     = "/assistants"
	// FoundryAPIVersion is the Foundry Agent Service api-version the list
	// asks for (unconfirmed until the live checks, R-85).
	FoundryAPIVersion = "v1"
)

// AgentCore reads the agent runtimes of the account tenant in region.
func AgentCore(ctx context.Context, post Poster, tenant, region string) Result {
	r := domain.NewReport(domain.SourceAWSAgentCore, tenant)
	page := func(token string) (egress.Response, error) {
		in := map[string]any{"maxResults": pageSize}
		if token != "" {
			in["nextToken"] = token
		}
		body, err := json.Marshal(in, json.Deterministic(true))
		if err != nil {
			return egress.Response{}, err
		}
		return post(ctx, agentCoreRuntimesPath, body)
	}
	// Each page is asked for by its token; the path never changes.
	get := func(ctx context.Context, token string) (egress.Response, error) { return page(token) }
	runtimes, why := pages(ctx, get, "", parse.AgentCorePage, func(token string) (string, bool) { return token, true })
	return finishRuntime(r, domain.ReadRuntimes, why, len(runtimes) > 0, func() { parse.AgentCoreFindings(r, region, runtimes) })
}

// VertexAgentEngine reads the reasoning engines of the tenant
// <project>/<location>.
func VertexAgentEngine(ctx context.Context, get Getter, tenant string) Result {
	r := domain.NewReport(domain.SourceVertexAgentEngine, tenant)
	project, location, ok := domain.VertexTenant(tenant)
	if !ok {
		r.Note(domain.NoteTenant, "the tenant is not a project and location")
		return Result{Report: r}
	}
	list := "/v1/projects/" + url.PathEscape(project) + "/locations/" + url.PathEscape(location) + "/reasoningEngines"
	at := func(token string) string {
		u := list + "?pageSize=" + strconv.Itoa(pageSize)
		if token != "" {
			u += "&pageToken=" + url.QueryEscape(token)
		}
		return u
	}
	engines, why := pages(ctx, get, at(""), parse.VertexPage, func(token string) (string, bool) { return at(token), true })
	return finishRuntime(r, domain.ReadReasoningEngines, why, len(engines) > 0, func() { parse.VertexFindings(r, engines) })
}

// Foundry reads the agents of the Foundry project tenant. get reaches the
// project endpoint, so its paths are relative to /api/projects/<tenant>.
func Foundry(ctx context.Context, get Getter, tenant string) Result {
	r := domain.NewReport(domain.SourceAzureFoundry, tenant)
	at := func(after string) string {
		u := foundryAgentsPath + "?api-version=" + FoundryAPIVersion + "&limit=" + strconv.Itoa(pageSize) + "&order=asc"
		if after != "" {
			u += "&after=" + url.QueryEscape(after)
		}
		return u
	}
	agents, why := pages(ctx, get, at(""), parse.FoundryPage, func(cursor string) (string, bool) { return at(cursor), true })
	return finishRuntime(r, domain.ReadAgents, why, len(agents) > 0, func() { parse.FoundryFindings(r, agents) })
}

// finishRuntime marks the one read, or notes why it stopped short: with
// nothing read at all the tenant could not be reached, which fails the run.
func finishRuntime(r *domain.Report, read, why string, some bool, add func()) Result {
	switch {
	case why == "":
		r.Read(read)
	case !some:
		r.Note(domain.NoteTenant, why)
		return Result{Report: r}
	default:
		r.Note(read, why)
	}
	add()
	return Result{Report: r, Reached: true}
}
