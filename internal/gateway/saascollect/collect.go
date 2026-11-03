// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package saascollect reads SaaS agent metadata through a gateway's
// connection (G0 M26 D407), page by page, into the parsers' report. Where the
// vendor takes a column list (Dataverse's $select) it asks only for the
// columns discovery keeps, so a bot's prompts are never fetched; where it
// takes none (the Compliance API) the first decode drops all else. Either
// way a prompt or instruction is never kept, logged or sent to the server,
// and a conversation is never asked for (H3, F789, HR-635). A next-page link is
// taken apart and rebuilt with those same columns: a vendor's link never
// chooses what is read. What it could not read stays not scanned (HR-637).
package saascollect

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/parse"
)

// Getter reads one path of the vendor's API with the connection's credential
// placed. The client is pinned to the connection's host.
type Getter func(ctx context.Context, path string) (egress.Response, error)

// The vendors' paths. The Compliance API's is uncertain: see the header of
// the parser's fixture.
const (
	dataversePath = "/api/data/v9.2"
	botsPath      = dataversePath + "/bots"
	partsPath     = dataversePath + "/botcomponents"
	whoAmIPath    = dataversePath + "/WhoAmI"
	gptsPrefix    = "/v1/compliance/workspaces/"
	pageSize      = 100
)

// maxPages bounds one list: past it the rest is reported not scanned.
const maxPages = 100

// Result is what a collection did. Reached is false when the tenant could not
// be read at all, which fails the run.
type Result struct {
	Report  *domain.Report
	Reached bool
}

// listURL is a list's first page, or with a skip token a later one: only the
// columns discovery keeps.
func listURL(path, sel, skip string) string {
	u := path + "?$select=" + sel
	if skip != "" {
		u += "&$skiptoken=" + url.QueryEscape(skip)
	}
	return u
}

// skipOf is the skip token of an OData next link, which must continue the same
// collection.
func skipOf(link, path string) (string, bool) {
	u, err := url.Parse(link)
	if err != nil || u.Path != path {
		return "", false
	}
	skip := u.Query().Get("$skiptoken")
	return skip, skip != ""
}

// reason words why a page could not be read: fixed text, never a vendor's.
func reason(ctx context.Context, res egress.Response, err error) string {
	switch {
	case ctx.Err() != nil:
		return "time limit: the lease's time ran out before it was read"
	case err != nil:
		return "the vendor could not be reached"
	case res.Status == 401 || res.Status == 403:
		return "the connection may not read it (HTTP " + strconv.Itoa(res.Status) + ")"
	case res.Status == 429:
		return "the vendor limited the rate of reads"
	case res.Status != 200:
		return "the vendor answered HTTP " + strconv.Itoa(res.Status)
	case res.Truncated:
		return "a page was larger than the connection's response limit"
	}
	return ""
}

// pages reads a list to its end. It returns what it read, and why it stopped
// short ("" when it did not).
func pages[T any](ctx context.Context, get Getter, first string, decode func([]byte) ([]T, string, error),
	next func(string) (string, bool),
) ([]T, string) {
	var out []T
	path := first
	for range maxPages {
		res, err := get(ctx, path)
		if why := reason(ctx, res, err); why != "" {
			return out, why
		}
		list, more, err := decode(res.Body)
		// The first decode keeps only a record's metadata fields: what else
		// the page held (a GPT's instructions) goes with the page, never
		// logged, kept or sent to the server (HR-635).
		clear(res.Body)
		if err != nil {
			return out, "a page had an unknown shape"
		}
		out = append(out, list...)
		if len(out) > parse.MaxRecords {
			return out[:parse.MaxRecords], "only the first " + strconv.Itoa(parse.MaxRecords) + " records were kept"
		}
		if more == "" {
			return out, ""
		}
		var ok bool
		if path, ok = next(more); !ok {
			return out, "a next-page link left the list"
		}
	}
	return out, "only the first " + strconv.Itoa(maxPages) + " pages were read"
}

// CopilotStudio reads the agents of the Dataverse organization tenant.
func CopilotStudio(ctx context.Context, get Getter, tenant string) Result {
	r := domain.NewReport(domain.SourceCopilotStudio, tenant)
	res, err := get(ctx, whoAmIPath)
	if why := reason(ctx, res, err); why != "" {
		r.Note(domain.NoteTenant, why)
		return Result{Report: r}
	}
	var who struct {
		OrganizationID string `json:"OrganizationId"`
	}
	if json.Unmarshal(res.Body, &who) != nil || !strings.EqualFold(who.OrganizationID, tenant) {
		// A connection to another organization must not read as this one.
		r.Note(domain.NoteTenant, "the connection does not reach this organization")
		return Result{Report: r}
	}
	bots, why := pages(ctx, get, listURL(botsPath, parse.BotSelect, ""), parse.CopilotBots, func(link string) (string, bool) {
		skip, ok := skipOf(link, botsPath)
		return listURL(botsPath, parse.BotSelect, skip), ok
	})
	if why == "" {
		r.Read(domain.ReadBots)
	} else {
		r.Note(domain.ReadBots, why)
	}
	comps, why := pages(ctx, get, listURL(partsPath, parse.ComponentSelect, ""), parse.CopilotComponents, func(link string) (string, bool) {
		skip, ok := skipOf(link, partsPath)
		return listURL(partsPath, parse.ComponentSelect, skip), ok
	})
	if why == "" {
		r.Read(domain.ReadBotComponents)
	} else {
		r.Note(domain.ReadBotComponents, why)
	}
	parse.CopilotFindings(r, bots, comps)
	return Result{Report: r, Reached: true}
}

// ChatGPTEnterprise reads the custom GPTs of the workspace tenant. No field
// filter of the Compliance API is known (its reference is behind an
// enterprise sign-in), so a page may carry a GPT's instructions: the first
// decode (parse.ChatGPTPage, closed structs) drops them before the parser
// sees a record, and the page is cleared.
func ChatGPTEnterprise(ctx context.Context, get Getter, tenant string) Result {
	r := domain.NewReport(domain.SourceChatGPTEnterprise, tenant)
	list := gptsPrefix + url.PathEscape(tenant) + "/gpts"
	at := func(after string) string {
		u := list + "?limit=" + strconv.Itoa(pageSize)
		if after != "" {
			u += "&after=" + url.QueryEscape(after)
		}
		return u
	}
	gpts, why := pages(ctx, get, at(""), parse.ChatGPTPage, func(cursor string) (string, bool) { return at(cursor), true })
	switch {
	case why == "":
		r.Read(domain.ReadGPTs)
	case len(gpts) == 0:
		// Nothing read: the workspace could not be reached.
		r.Note(domain.NoteTenant, why)
		return Result{Report: r}
	default:
		r.Note(domain.ReadGPTs, why)
	}
	r.Read(domain.ReadGPTConfigs) // with the list; a record it could not read is marked on its own
	parse.ChatGPTFindings(r, gpts)
	return Result{Report: r, Reached: true}
}

// ErrSource refuses a source no collector reads.
var ErrSource = errors.New("saascollect: unknown source")
