// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// installation answers GET /app/installations/{id} for the App's JWT: the
// account, the permissions the owner granted and the repository selection,
// which a connection records and M9 compares with what is used (F048).
func (s *Server) installation(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := Request{Method: r.Method, Path: r.URL.Path}
	rec.Status = s.describe(w, r)
	s.requests = append(s.requests, rec)
}

func (s *Server) describe(w http.ResponseWriter, r *http.Request) int {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return fail(w, http.StatusUnauthorized, "A JSON web token could not be decoded")
	}
	jwt, err := s.verifyJWT(bearer)
	if err != nil {
		return fail(w, http.StatusUnauthorized, err.Error())
	}
	s.jwts = append(s.jwts, jwt)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	in := s.installs[id]
	if in == nil {
		return fail(w, http.StatusNotFound, "Not Found")
	}
	return reply(w, http.StatusOK, map[string]any{
		"id": in.ID, "app_id": s.appID, "account": map[string]any{"login": in.Account, "id": accountID(in.Account)},
		"repository_selection": "selected", "permissions": maps.Clone(in.Permissions), "simulated": true,
	})
}

// accountID is a stable simulated GitHub id for an account login.
func accountID(login string) int64 {
	var n uint64 = 1000
	for _, c := range []byte(login) {
		n = n*31 + uint64(c)
	}
	return int64(n%1_000_000_000) + 1 // positive, as GitHub's ids are
}

// installationRepositories answers GET /installation/repositories: the
// repositories the installation token reaches. It is the connection test's
// harmless read (G0 M8, C2).
func (s *Server) installationRepositories(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := Request{Method: r.Method, Path: r.URL.Path}
	t, status := s.authenticate(r)
	switch {
	case t == nil:
		rec.Status = fail(w, status, "Bad credentials")
	case t.Installation == 0:
		rec.Status = fail(w, http.StatusForbidden, "This endpoint is for installation tokens")
	default:
		t.Uses++
		rec.Token, rec.Installation, rec.Repos, rec.Permissions = Fingerprint(t.value), t.Installation, slices.Clone(t.Repos), maps.Clone(t.Permissions)
		repos := []map[string]any{}
		for _, full := range t.Repos {
			if repo := s.repos[full]; repo != nil {
				repos = append(repos, map[string]any{"name": repo.Name, "full_name": repo.full(), "default_branch": repo.DefaultBranch})
			}
		}
		rec.Status = reply(w, http.StatusOK, map[string]any{"total_count": len(repos), "repositories": repos, "simulated": true})
	}
	s.requests = append(s.requests, rec)
}
