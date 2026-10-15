// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"bytes"
	"fmt"

	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
)

// MergeTool is the GitHub MCP server's merge tool (MCPTools).
const MergeTool = "merge_pull_request"

// MCPMergePackage rewrites the pc.github package (raw) for a connection to
// GitHub's MCP server, for tests and demos: version becomes version, and
// github.pull.merge dispatches to merge_pull_request, pinned to digest (the
// upstream digest of MCPTools' merge tool), instead of the REST API, with
// the same credential scope. The tool takes the pull request number as a
// number, so the merge gains an optional integer param pull_number, which
// its MCP mapping extracts from pullNumber. Every other operation keeps its
// REST dispatch, which a kind-mcp connection does not serve.
func MCPMergePackage(raw []byte, version, digest string) ([]byte, error) {
	for _, r := range [][2]string{
		{"\nversion: " + pcgithub.Version + "\n", "\nversion: " + version + "\n"},
		{
			"      merge_method:\n        type: enum\n        material: true\n        values: [merge, squash, rebase]\n    effects:\n      - kind: repository.branch.merge\n",
			"      merge_method:\n        type: enum\n        material: true\n        values: [merge, squash, rebase]\n" +
				"      pull_number:\n        type: integer\n        unit: count\n        min: \"1\"\n" +
				"    effects:\n      - kind: repository.branch.merge\n",
		},
		{
			"            sha: input.expectedHeadSha\n            merge_method: input.?merge_method\n    dispatch:\n      http:\n" +
				"        method: PUT\n        path: /repos/{target.id.owner}/{target.id.repo}/pulls/{target.id.number}/merge\n" +
				"        body:\n          sha: params.sha\n          merge_method: params.merge_method\n",
			"            sha: input.expectedHeadSha\n            merge_method: input.?merge_method\n            pull_number: input.pullNumber\n" +
				"    dispatch:\n      mcp:\n        tool: " + MergeTool + "\n        upstream_digest: " + digest + "\n        arguments:\n" +
				"          owner: target.id.owner\n          repo: target.id.repo\n          pullNumber: params.pull_number\n" +
				"          expectedHeadSha: params.sha\n          merge_method: params.merge_method\n",
		},
	} {
		if bytes.Count(raw, []byte(r[0])) != 1 {
			return nil, fmt.Errorf("the pc.github package: %q not found once", r[0])
		}
		raw = bytes.Replace(raw, []byte(r[0]), []byte(r[1]), 1)
	}
	return raw, nil
}
