// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"maps"
	"net/http"
	"strings"
)

// blobSHA is a file's simulated blob name: 40 hex digits of its content's
// SHA-256, the shape of git's.
func blobSHA(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:20])
}

// putContents creates or updates one file on a branch as one commit (PUT
// .../contents/{path}), as GitHub does: an update names the current blob
// SHA (409 otherwise), a create names none, and a write under
// .github/workflows/ needs the workflows permission, which PantherClaw's
// tokens never hold (G0 M8).
func (s *Server) putContents(w http.ResponseWriter, req *http.Request, r *Repo, t *Token) int {
	var b struct {
		Message string `json:"message"`
		Content string `json:"content"`
		Branch  string `json:"branch"`
		SHA     string `json:"sha"`
	}
	if !decode(req, &b) || b.Message == "" {
		return fail(w, http.StatusUnprocessableEntity, "Invalid request")
	}
	path := strings.Trim(req.PathValue("path"), "/")
	if strings.HasPrefix(path, ".github/workflows/") && !covers(t.Permissions["workflows"], "write") {
		return fail(w, http.StatusForbidden, "refusing to allow a GitHub App to create or update workflow `"+path+"` without `workflows` permission")
	}
	raw, err := base64.StdEncoding.DecodeString(b.Content)
	if err != nil || path == "" {
		return fail(w, http.StatusUnprocessableEntity, "Invalid request")
	}
	if b.Branch == "" {
		b.Branch = r.DefaultBranch
	}
	head := r.Branches[b.Branch]
	if head == "" {
		return fail(w, http.StatusNotFound, "Branch "+b.Branch+" not found")
	}
	cur, exists := r.Commits[head].Files[path]
	switch {
	case exists && b.SHA == "":
		return fail(w, http.StatusUnprocessableEntity, `Invalid request. "sha" wasn't supplied.`)
	case exists && b.SHA != blobSHA(cur):
		return fail(w, http.StatusConflict, path+" does not match "+b.SHA)
	case !exists && b.SHA != "":
		return fail(w, http.StatusUnprocessableEntity, "sha is only for updating a file")
	}
	tree := maps.Clone(r.Commits[head].Files)
	tree[path] = string(raw)
	sha := s.commit(r, actor(t), []string{head}, tree)
	s.advance(r, b.Branch, sha, actor(t), "push")
	status := http.StatusCreated
	if exists {
		status = http.StatusOK
	}
	return reply(w, status, map[string]any{
		"content": map[string]any{"path": path, "sha": blobSHA(string(raw))}, "commit": map[string]any{"sha": sha}, "simulated": true,
	})
}
