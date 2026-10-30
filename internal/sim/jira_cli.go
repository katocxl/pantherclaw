// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"os"
	"slices"
	"strings"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/jira"
)

// Simulated Jira projects: an engineering (software) and an operations
// (business) project, internal to the organization, and a help desk
// (service_desk) whose customers read what is written there. Each starts
// with one issue; JiraRestricted carries an issue security level.
const (
	JiraEngineering = "ENG"
	JiraOperations  = "OPS"
	JiraHelpDesk    = "HELP"
	JiraIssue       = "ENG-1"
	JiraRestricted  = "ENG-2"
	JiraTicket      = "HELP-1"
)

// JiraProjects and JiraIssues are the simulator's starting site.
func JiraProjects() []jira.Project {
	return []jira.Project{
		{Key: JiraEngineering, Name: "Engineering", Type: jira.TypeSoftware},
		{Key: JiraOperations, Name: "Operations", Type: jira.TypeBusiness},
		{Key: JiraHelpDesk, Name: "Help desk", Type: jira.TypeServiceDesk},
	}
}

// JiraIssues are the simulator's starting issues.
func JiraIssues() []jira.Issue {
	return []jira.Issue{
		{Key: JiraIssue, Summary: "Payments retries", Type: "Task"},
		{Key: JiraRestricted, Summary: "Key rotation", Type: "Task", Security: "Internal"},
		{Key: JiraTicket, Summary: "Refund not received", Type: "Support"},
	}
}

// runJira serves the simulated Jira Cloud REST API (G0 M20 D254).
func runJira(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("jira", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:9096", "listen address (loopback)")
	secretFile := fs.String("secret-file", "", "file holding the only Basic credential accepted, base64 of email:api-token (otherwise any is)")
	customer := fs.String("customer-visible", "", "comma-separated project keys to make service desks (customer-visible)")
	webhookURL := fs.String("webhook-url", "", "post Jira-shaped webhooks for issue changes to this URL")
	webhookSecretFile := fs.String("webhook-secret-file", "", "with --webhook-url: file holding the secret webhooks are signed with")
	rate := fs.Int("rate-limit", 0, "answer the first N requests with 429 and Retry-After")
	invalidAuth := fs.Bool("invalid-auth", false, "answer every request 401 (a revoked API token)")
	notFound := fs.Bool("not-found", false, "answer every project and issue call 404")
	if err := fs.Parse(args); err != nil {
		return err
	}
	projects := JiraProjects()
	for i := range projects {
		if slices.Contains(slackList(*customer), projects[i].Key) {
			projects[i].Type = jira.TypeServiceDesk
		}
	}
	var req jira.Require
	if *secretFile != "" {
		b, err := os.ReadFile(*secretFile)
		if err != nil {
			return err
		}
		req.Secret = strings.TrimSpace(string(b))
		raw, err := base64.StdEncoding.DecodeString(req.Secret)
		if user, tok, ok := strings.Cut(string(raw), ":"); err != nil || !ok || !strings.Contains(user, "@") || tok == "" {
			return errors.New("--secret-file must hold base64 of email:api-token")
		}
	}
	var hook jira.Webhook
	if *webhookURL != "" {
		hook.URL = *webhookURL
		if *webhookSecretFile != "" {
			b, err := os.ReadFile(*webhookSecretFile)
			if err != nil {
				return err
			}
			hook.Secret = strings.TrimSpace(string(b))
		}
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := jira.New(projects, JiraIssues(), jira.Faults{RateLimit: *rate, InvalidAuth: *invalidAuth, NotFound: *notFound}, log).WithRequire(req)
	sim.SetWebhook(hook)
	return serve(ctx, *addr, sim.Handler(), log, "sim.jira_listening")
}
