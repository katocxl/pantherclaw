// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/gitlab"
)

// The simulated GitLab project acme/payments (id GitLabProject), which
// deploys to GitLabEnvironment on a merge, with an
// open merge request GitLabMergeRequest at GitLabHead whose pipeline
// GitLabPipeline succeeded, needing one approval, and an open merge request
// GitLabUnverifiedMergeRequest at GitLabUnverifiedHead whose pipeline
// GitLabRunningPipeline is still running.
const (
	GitLabProject      = 42
	GitLabMergeRequest = 7
	GitLabPipeline     = 900
	GitLabHead         = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	GitLabEnvironment  = "production"

	GitLabUnverifiedMergeRequest = 8
	GitLabRunningPipeline        = 901
	GitLabUnverifiedHead         = "9daeafb9864cf43055ae93beb0afd6c7d144bfa4"
)

// GitLabStart is the simulator's starting instance.
func GitLabStart() ([]gitlab.Project, []gitlab.MergeRequest, []gitlab.Pipeline) {
	return []gitlab.Project{{
		ID: GitLabProject, Path: "acme/payments", DefaultBranch: "main", PipelineMustSucceed: true,
		Environments: []string{GitLabEnvironment},
		Protected:    map[string]gitlab.Protection{"main": {}},
	}}, []gitlab.MergeRequest{{
		Project: GitLabProject, IID: GitLabMergeRequest, Title: "Retry failed refunds", Source: "retry-refunds", Target: "main",
		SHA: GitLabHead, Author: "developer", ApprovalsRequired: 1, Pipeline: GitLabPipeline,
	}, {
		Project: GitLabProject, IID: GitLabUnverifiedMergeRequest, Title: "Change the refund limit", Source: "refund-limit", Target: "main",
		SHA: GitLabUnverifiedHead, Author: "developer", Pipeline: GitLabRunningPipeline,
	}}, []gitlab.Pipeline{{
		ID: GitLabPipeline, Project: GitLabProject, Ref: "retry-refunds", SHA: GitLabHead, Status: gitlab.PipelineSuccess, Source: "push",
	}, {
		ID: GitLabRunningPipeline, Project: GitLabProject, Ref: "refund-limit", SHA: GitLabUnverifiedHead, Status: gitlab.PipelineRunning, Source: "push",
	}}
}

// runGitLab serves the simulated GitLab REST API (G0 M20 D254).
func runGitLab(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("gitlab", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:9097", "listen address (loopback)")
	tokenFile := fs.String("token-file", "", "file holding the only access token accepted (otherwise any glpat- token is)")
	approved := fs.Bool("approved", false, "start the merge request approved")
	rate := fs.Int("rate-limit", 0, "answer the first N requests with 429 and Retry-After")
	invalidAuth := fs.Bool("invalid-auth", false, "answer every request 401 (a revoked token)")
	notFound := fs.Bool("not-found", false, "answer every project call 404")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var req gitlab.Require
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		req.Token = strings.TrimSpace(string(b))
		if !strings.HasPrefix(req.Token, "glpat-") {
			return errors.New("--token-file must hold a glpat- access token")
		}
	}
	projects, mrs, pipelines := GitLabStart()
	if *approved {
		mrs[0].Approvers = []string{"reviewer"}
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := gitlab.New(projects, mrs, pipelines, gitlab.Faults{RateLimit: *rate, InvalidAuth: *invalidAuth, NotFound: *notFound}, log).WithRequire(req)
	return serve(ctx, *addr, sim.Handler(), log, "sim.gitlab_listening")
}
