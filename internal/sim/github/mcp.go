// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
)

// MCPTools are the GitHub MCP server's tools this simulator serves (the
// subset pc.github maps), with the parameters the real server takes, for a
// simulated MCP server (internal/sim/mcpsim) to list.
var MCPTools = []jsontext.Value{
	tool("get_file_contents", "Get the contents of a file or directory.", `"owner","repo"`, `"owner":{"type":"string"},"repo":{"type":"string"},"path":{"type":"string"},"ref":{"type":"string"}`),
	tool("list_branches", "List branches in a repository.", `"owner","repo"`, `"owner":{"type":"string"},"repo":{"type":"string"},"page":{"type":"number"}`),
	tool("create_branch", "Create a new branch.", `"owner","repo","branch"`, `"owner":{"type":"string"},"repo":{"type":"string"},"branch":{"type":"string"},"from_branch":{"type":"string"}`),
	tool("create_pull_request", "Create a new pull request.", `"owner","repo","title","head","base"`,
		`"owner":{"type":"string"},"repo":{"type":"string"},"title":{"type":"string"},"body":{"type":"string"},"head":{"type":"string"},"base":{"type":"string"},"draft":{"type":"boolean"}`),
	tool("pull_request_read", "Read a pull request: get or get_reviews.", `"method","owner","repo","pullNumber"`,
		`"method":{"type":"string","enum":["get","get_reviews"]},"owner":{"type":"string"},"repo":{"type":"string"},"pullNumber":{"type":"number"}`),
	tool("merge_pull_request", "Merge a pull request.", `"owner","repo","pullNumber"`,
		`"owner":{"type":"string"},"repo":{"type":"string"},"pullNumber":{"type":"number"},"merge_method":{"type":"string"},"expectedHeadSha":{"type":"string"},"commit_title":{"type":"string"},"commit_message":{"type":"string"}`),
}

func tool(name, description, required, props string) jsontext.Value {
	return jsontext.Value(`{"name":"` + name + `","description":"` + description + `","inputSchema":{"type":"object","properties":{` + props +
		`},"required":[` + required + `]}}`)
}

// toolArgs are the arguments of every tool above.
type toolArgs struct {
	Owner           string `json:"owner"`
	Repo            string `json:"repo"`
	Path            string `json:"path"`
	Ref             string `json:"ref"`
	Page            int    `json:"page"`
	Branch          string `json:"branch"`
	FromBranch      string `json:"from_branch"`
	Title           string `json:"title"`
	Body            string `json:"body"`
	Head            string `json:"head"`
	Base            string `json:"base"`
	Draft           bool   `json:"draft"`
	Method          string `json:"method"`
	PullNumber      int    `json:"pullNumber"`
	MergeMethod     string `json:"merge_method"`
	ExpectedHeadSHA string `json:"expectedHeadSha"`
	CommitTitle     string `json:"commit_title"`
	CommitMessage   string `json:"commit_message"`
}

// CallTool runs one of MCPTools as the GitHub MCP server does: it calls
// the REST API with the token the server was configured with, so the call
// is authorized, scoped and recorded like any other request. It returns
// the API's answer and whether it is a tool error; ok is false for an
// unknown tool.
func (s *Server) CallTool(ctx context.Context, token, name string, args jsontext.Value) (result jsontext.Value, isError, ok bool) {
	var a toolArgs
	if json.Unmarshal(args, &a) != nil {
		return jsontext.Value(`{"error":"invalid arguments"}`), true, true
	}
	repo := "/repos/" + url.PathEscape(a.Owner) + "/" + url.PathEscape(a.Repo)
	pr := repo + "/pulls/" + strconv.Itoa(a.PullNumber)
	var method, path string
	var body any
	switch name {
	case "get_file_contents":
		method, path = http.MethodGet, repo+"/contents/"+a.Path
		if a.Ref != "" {
			path += "?ref=" + url.QueryEscape(a.Ref)
		}
	case "list_branches":
		method, path = http.MethodGet, repo+"/branches?page="+strconv.Itoa(max(a.Page, 1))
	case "create_branch":
		from := a.FromBranch
		if from == "" {
			from, _ = s.RepoSettings(a.Owner + "/" + a.Repo)
		}
		method, path, body = http.MethodPost, repo+"/git/refs", map[string]string{"ref": "refs/heads/" + a.Branch, "sha": s.Branch(a.Owner+"/"+a.Repo, from)}
	case "create_pull_request":
		method, path, body = http.MethodPost, repo+"/pulls", map[string]any{"title": a.Title, "body": a.Body, "head": a.Head, "base": a.Base, "draft": a.Draft}
	case "pull_request_read":
		method, path = http.MethodGet, pr
		if a.Method == "get_reviews" {
			path += "/reviews"
		}
	case "merge_pull_request":
		method, path, body = http.MethodPut, pr+"/merge", map[string]any{
			"sha": a.ExpectedHeadSHA, "merge_method": a.MergeMethod, "commit_title": a.CommitTitle, "commit_message": a.CommitMessage,
		}
	default:
		return nil, false, false
	}
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequestWithContext(ctx, method, path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return jsontext.Value(rec.Body.Bytes()), rec.Code >= http.StatusBadRequest, true
}
