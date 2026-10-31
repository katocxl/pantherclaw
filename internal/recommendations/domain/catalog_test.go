// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/recommendations/domain"
)

// storedID is the migration's CHECK on recommendation_id.
var storedID = regexp.MustCompile(`^[a-z][a-z_]*(\.[a-z0-9_]+){1,3}$`)

// TestHR535_EveryEntryStatesWhatStaysUnsupported: a recommendation says what
// it enables and what stays unsupported, and carries a link to its evidence;
// a need with no integration names no target and is stated as unsupported.
//
// Covers: F343
func TestHR535_EveryEntryStatesWhatStaysUnsupported(t *testing.T) {
	seen := map[domain.ID]bool{}
	for _, e := range domain.Catalog() {
		if seen[e.ID] {
			t.Errorf("%s: duplicate id", e.ID)
		}
		seen[e.ID] = true
		if !storedID.MatchString(string(e.ID)) {
			t.Errorf("%s: the dismissals table refuses this id", e.ID)
		}
		if e.Title == "" || e.Detail == "" || e.Category == "" || e.Source == "" {
			t.Errorf("%s: incomplete: %+v", e.ID, e)
		}
		if e.Reach != domain.AgentBacked && e.Reach != domain.OrgWide {
			t.Errorf("%s: no reach", e.ID)
		}
		if !strings.HasPrefix(e.Link, "/pantherclaw.v1.") {
			t.Errorf("%s: evidence link %q", e.ID, e.Link)
		}
		if len(e.StillUnsupported) == 0 || slices.Contains(e.StillUnsupported, "") {
			t.Errorf("%s: states nothing unsupported", e.ID)
		}
		if none := e.Category == domain.Unsupported; none != (len(e.Targets) == 0) || none != (len(e.Enables) == 0) {
			t.Errorf("%s: %s with %d targets and %d enables", e.ID, e.Category, len(e.Targets), len(e.Enables))
		}
	}
}

// TestHR535_EvaluationLeavesFactsUnchanged: the catalog is closed,
// and evaluating it leaves its facts as they were.
//
// Covers: F343
func TestHR535_EvaluationLeavesFactsUnchanged(t *testing.T) {
	a := ids.NewV7()
	f := domain.Facts{
		Agents: map[string]domain.Group{domain.ContextCI: {Count: 1, IDs: []ids.UUID{a}}},
		Integrations: domain.Integrations{
			Issuers: []string{}, Packages: []string{"pc.github"}, Channels: []string{},
		},
	}
	for _, e := range domain.Catalog() {
		e.Evaluate(f)
	}
	if got := f.Agents[domain.ContextCI]; got.Count != 1 || got.IDs[0] != a || len(f.Integrations.Packages) != 1 {
		t.Fatalf("facts changed: %+v", f)
	}
	if _, ok := domain.Lookup("identity.customer_rule"); ok {
		t.Fatal("an id outside the catalog was found")
	}
}

// TestHR536_IntegrationStateNeedsOrgScope: an entry a scoped viewer can see
// applies whatever the org has connected, so it says nothing about that
// (D317).
//
// Covers: F343
func TestHR536_IntegrationStateNeedsOrgScope(t *testing.T) {
	txn := ids.NewV7()
	bare := domain.Facts{
		Agents: map[string]domain.Group{
			domain.ContextCI: group(1), domain.ContextKubernetes: group(1), domain.ContextService: group(1),
		},
		Secrets:    map[string]domain.Group{"aws_access_key_id": group(1), "openai_api_key": group(1)},
		DataAgents: group(1), FirstDecision: &txn, FirstHold: &txn,
	}
	connected := bare
	connected.Integrations = domain.Integrations{
		Issuers: domain.IntegrationKinds(), Channels: domain.IntegrationKinds(), SIEM: true, FactProviders: true,
		Packages: []string{domain.PackageGitLab, domain.PackageJira, domain.PackageTeams, domain.PackageAWS},
	}
	var scoped int
	for _, e := range domain.Catalog() {
		_, before := e.Evaluate(bare)
		_, after := e.Evaluate(connected)
		if !before {
			t.Errorf("%s: does not apply", e.ID)
		}
		if e.Reach == domain.AgentBacked {
			scoped++
			if !after {
				t.Errorf("%s: turns on the org's integrations, so it needs org scope", e.ID)
			}
		}
	}
	if scoped == 0 {
		t.Fatal("no entry reaches a scoped viewer")
	}
}

// TestCatalogTargets: the M20 integrations are named by their D254 package
// names.
//
// Covers: F343
func TestCatalogTargets(t *testing.T) {
	var names, packages []string
	for _, e := range domain.Catalog() {
		for _, x := range e.Targets {
			names = append(names, x.Name)
			if x.Package != "" {
				packages = append(packages, x.Package)
			}
		}
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"GitLab", "Jira", "Teams", "AWS", "Slack", "SIEM"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no target names %s: %s", want, joined)
		}
	}
	for _, want := range []string{domain.PackageJira, domain.PackageAWS} {
		if !slices.Contains(packages, want) {
			t.Errorf("no target uses %s: %v", want, packages)
		}
	}
	// pc.teams is the agents' tool package: a Teams channel closes the approval
	// entry, so connecting the package would not.
	if slices.Contains(packages, domain.PackageTeams) {
		t.Errorf("a target uses %s: %v", domain.PackageTeams, packages)
	}
}

// TestCatalogPackagesExist checks the merged tree (D306, D313): each named
// package has a directory whose manifest carries that name. It fails, and
// never skips, while a package is missing.
//
// Covers: F343
func TestCatalogPackagesExist(t *testing.T) {
	for dir, name := range map[string]string{
		"pc-gitlab": domain.PackageGitLab, "pc-jira": domain.PackageJira,
		"pc-teams": domain.PackageTeams, "pc-aws": domain.PackageAWS, "pc-aws-ecs": domain.PackageAWSECS,
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", dir, "package.yaml"))
		if err != nil {
			t.Error(err)
			continue
		}
		if !regexp.MustCompile(`(?m)^name: ` + regexp.QuoteMeta(name) + `\r?$`).Match(raw) {
			t.Errorf("packages/%s is not named %s", dir, name)
		}
	}
}

// sqlComment is a line or block comment of a migration.
var sqlComment = regexp.MustCompile(`(?m)--.*$|(?s:/\*.*?\*/)`)

// TestCatalogKindsExist checks the merged tree (D313, D317): an issuer or
// channel kind no migration allows would keep its entry open after the
// integration is added. Only the Up statements count, not comments or Down
// sections.
//
// Covers: F343
func TestCatalogKindsExist(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "migrations", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations: %d, %v", len(files), err)
	}
	var all strings.Builder
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		up, _, _ := strings.Cut(string(raw), "-- +goose Down")
		all.WriteString(sqlComment.ReplaceAllString(up, ""))
	}
	for _, kind := range domain.IntegrationKinds() {
		if !strings.Contains(all.String(), "'"+kind+"'") {
			t.Errorf("no migration allows kind %s", kind)
		}
	}
}

func group(n int) domain.Group {
	g := domain.Group{Count: n}
	for range min(n, domain.MaxRecords) {
		g.IDs = append(g.IDs, ids.NewV7())
	}
	return g
}

// TestCatalogSignals: each entry applies on its signal and goes away once
// the integration exists.
//
// Covers: F343
func TestCatalogSignals(t *testing.T) {
	txn := ids.NewV7()
	for _, c := range []struct {
		id        domain.ID
		fires     domain.Facts
		satisfied func(*domain.Facts)
		kind      string
	}{
		{
			domain.CIWorkload,
			domain.Facts{Agents: map[string]domain.Group{domain.ContextCI: group(2)}},
			func(f *domain.Facts) { f.Integrations.Issuers = []string{"gitlab_ci"} }, domain.RecordAgent,
		},
		{
			domain.KubeWorkload,
			domain.Facts{Agents: map[string]domain.Group{domain.ContextKubernetes: group(1)}},
			func(f *domain.Facts) { f.Integrations.Issuers = []string{"kubernetes"} }, domain.RecordAgent,
		},
		{
			domain.CloudWorkload,
			domain.Facts{Agents: map[string]domain.Group{domain.ContextService: group(1)}},
			func(f *domain.Facts) { f.Integrations.Issuers = []string{"aws_iam"} }, domain.RecordAgent,
		},
		{
			domain.AWSKeys,
			domain.Facts{Secrets: map[string]domain.Group{"aws_access_key_id": group(1)}},
			func(f *domain.Facts) { f.Integrations.Packages = []string{domain.PackageAWS} }, domain.RecordDiscovery,
		},
		{
			domain.AWSKeys,
			domain.Facts{Secrets: map[string]domain.Group{"aws_access_key_id": group(1)}},
			func(f *domain.Facts) { f.Integrations.Packages = []string{domain.PackageAWSECS} }, domain.RecordDiscovery,
		},
		{
			domain.DataClasses,
			domain.Facts{DataAgents: group(1)},
			func(f *domain.Facts) { f.Integrations.FactProviders = true }, domain.RecordAgent,
		},
		{
			domain.ApprovalChat,
			domain.Facts{FirstHold: &txn},
			func(f *domain.Facts) { f.Integrations.Channels = []string{"teams_app"} }, domain.RecordTransaction,
		},
		{
			domain.IncidentTicket,
			domain.Facts{FirstDecision: &txn},
			func(f *domain.Facts) { f.Integrations.Packages = []string{domain.PackageJira} }, domain.RecordTransaction,
		},
		{
			domain.SIEMExport,
			domain.Facts{FirstDecision: &txn},
			func(f *domain.Facts) { f.Integrations.SIEM = true }, domain.RecordTransaction,
		},
		{
			domain.ModelKeys,
			domain.Facts{Secrets: map[string]domain.Group{"openai_api_key": group(1)}},
			func(f *domain.Facts) { f.Secrets = nil }, domain.RecordDiscovery,
		},
	} {
		e, ok := domain.Lookup(c.id)
		if !ok {
			t.Fatalf("%s: not in the catalog", c.id)
		}
		if _, ok := e.Evaluate(domain.Facts{}); ok {
			t.Errorf("%s: applies with no signal", c.id)
		}
		ev, ok := e.Evaluate(c.fires)
		if !ok || ev.Count == 0 || ev.Source != e.Source || ev.Link != e.Link || len(ev.Records) == 0 || ev.Records[0].Kind != c.kind {
			t.Errorf("%s: evidence %+v, applies %v", c.id, ev, ok)
		}
		c.satisfied(&c.fires)
		if _, ok := e.Evaluate(c.fires); ok {
			t.Errorf("%s: still applies once satisfied", c.id)
		}
	}
}

// TestCatalogCapsRecords: a recommendation lists at most MaxRecords
// records and still counts them all.
//
// Covers: F343
func TestCatalogCapsRecords(t *testing.T) {
	e, _ := domain.Lookup(domain.AWSKeys)
	ev, ok := e.Evaluate(domain.Facts{Secrets: map[string]domain.Group{
		"aws_access_key_id": group(15), "aws_secret_access_key": group(15),
	}})
	if !ok || ev.Count != 30 || len(ev.Records) != domain.MaxRecords {
		t.Fatalf("count %d, %d records, applies %v", ev.Count, len(ev.Records), ok)
	}
}

// TestSecretKindsAreClosed: only the credential kinds the catalog reads
// reach the discovery query.
//
// Covers: F343
func TestSecretKindsAreClosed(t *testing.T) {
	want := []string{"anthropic_api_key", "aws_access_key_id", "aws_secret_access_key", "google_api_key", "openai_api_key"}
	got := domain.SecretKinds()
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
}
