// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gitlab

import (
	"maps"
	"net/http"
	"slices"
	"strconv"
)

// Deployment is one deployment of a commit to an environment.
type Deployment struct {
	ID          int    `json:"id"`
	Project     int    `json:"project_id"`
	Environment string `json:"environment"`
	Ref         string `json:"ref"`
	SHA         string `json:"sha"`
	// Status is running, success, failed or canceled.
	Status string `json:"status"`
}

// Deployments returns a project's deployments, oldest first.
func (s *Server) Deployments(project int) []Deployment {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Deployment{}
	for _, id := range slices.Sorted(maps.Keys(s.deploys)) {
		if d := s.deploys[id]; d.Project == project {
			out = append(out, *d)
		}
	}
	return out
}

// SetDeployment sets a deployment's status (a job finished or failed).
func (s *Server) SetDeployment(id int, status string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.deploys[id]
	if ok {
		d.Status = status
	}
	return ok
}

// startDeployments starts a deployment of the merge commit to each of the
// project's environments, as a pipeline on the target branch does.
func (s *Server) startDeployments(p *Project, m *MergeRequest) {
	for _, e := range p.Environments {
		s.seq++
		s.deploys[s.seq] = &Deployment{ID: s.seq, Project: p.ID, Environment: e, Ref: m.Target, SHA: m.MergeCommit, Status: "running"}
	}
}

// deployments answers the environments and deployments reads; it reports
// whether rest named one of them.
func (s *Server) deployments(w http.ResponseWriter, r *http.Request, p *Project, rest []string) bool {
	switch {
	case r.Method == http.MethodGet && len(rest) == 1 && rest[0] == "environments":
		out := []map[string]any{}
		for i, e := range p.Environments {
			out = append(out, map[string]any{"id": i + 1, "name": e, "state": "available"})
		}
		writeJSON(w, http.StatusOK, out)
	case r.Method == http.MethodGet && len(rest) == 1 && rest[0] == "deployments":
		out := []map[string]any{}
		env := r.URL.Query().Get("environment")
		for _, id := range slices.Backward(slices.Sorted(maps.Keys(s.deploys))) {
			if d := s.deploys[id]; d.Project == p.ID && (env == "" || d.Environment == env) {
				out = append(out, deploymentJSON(d))
			}
		}
		writeJSON(w, http.StatusOK, out)
	case r.Method == http.MethodGet && len(rest) == 2 && rest[0] == "deployments":
		n, _ := strconv.Atoi(rest[1])
		d, ok := s.deploys[n]
		if !ok || d.Project != p.ID {
			writeJSON(w, http.StatusNotFound, msg("404 Not found"))
			return true
		}
		writeJSON(w, http.StatusOK, deploymentJSON(d))
	default:
		return false
	}
	return true
}

func deploymentJSON(d *Deployment) map[string]any {
	return map[string]any{
		"id": d.ID, "ref": d.Ref, "sha": d.SHA, "status": d.Status, "environment": map[string]any{"name": d.Environment},
	}
}
