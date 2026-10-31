// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the closed recommendation catalog (G0 M21 D302,
// D306; F343; HR-535). An entry maps a signal to an integration: what it
// enables, what stays unsupported and where the evidence is. Customers add
// no entries. Evaluation is a pure function of Facts, and nothing here can
// act: an entry only has text and a signal.
//
// GitLab, Jira, Teams and AWS are named by their D254 package names; this
// package imports no M20 code. Anything the catalog has no integration for
// is stated as unsupported.
package domain

import (
	"slices"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ID is a catalog entry's stable id; dismissals store it.
type ID string

// Entry ids.
const (
	CIWorkload     ID = "identity.ci_workload"
	KubeWorkload   ID = "identity.kubernetes_workload"
	CloudWorkload  ID = "identity.cloud_workload"
	AWSKeys        ID = "identity.aws_credentials"
	DataClasses    ID = "classification.data_connections"
	ApprovalChat   ID = "approval.chat_channel"
	IncidentTicket ID = "incident.ticket_sync"
	SIEMExport     ID = "export.siem"
	ModelKeys      ID = "unsupported.model_provider_keys"
	// ManagedSettings is managed_settings_missing of G0 M23 D114; a stored id
	// has a category before a dot.
	ManagedSettings ID = "unsupported.managed_settings_missing"
)

// Category is what kind of need an entry answers.
type Category string

// Categories, as the API names them.
const (
	Identity       Category = "IDENTITY"
	Classification Category = "CLASSIFICATION"
	Approval       Category = "APPROVAL"
	Incident       Category = "INCIDENT"
	Export         Category = "EXPORT"
	Unsupported    Category = "UNSUPPORTED"
)

// Source is where an entry's evidence comes from.
type Source string

// Sources, as the API names them.
const (
	FromDiscoveries Source = "DISCOVERIES"
	FromCoverage    Source = "COVERAGE"
	FromOnboarding  Source = "ONBOARDING"
	FromAgents      Source = "AGENTS"
)

// Reach says who may see an entry (HR-536).
type Reach int

// Reaches.
const (
	// AgentBacked entries rest on agents alone: a viewer sees one over the
	// agents their posture.read reaches.
	AgentBacked Reach = iota + 1
	// OrgWide entries turn on the org's integrations, so whether one applies
	// says what the org has connected: only a viewer with posture.read at
	// org scope sees one (D317).
	OrgWide
)

// Execution contexts (pc.agents.execution_context).
const (
	ContextCI         = "ci"
	ContextKubernetes = "kubernetes"
	ContextService    = "service"
)

// Record kinds of evidence.
const (
	RecordAgent       = "agent"
	RecordDiscovery   = "discovery"
	RecordTransaction = "transaction"
)

// MaxRecords caps the records one recommendation lists.
const MaxRecords = 20

// Record is one record behind a recommendation.
type Record struct {
	Kind string
	ID   ids.UUID
}

// Group is the records of one signal the viewer may see. Count may exceed
// len(IDs), which the queries cap at MaxRecords.
type Group struct {
	Count int
	IDs   []ids.UUID
}

// Integrations is what the org has connected.
type Integrations struct {
	Issuers       []string // active trusted issuer kinds
	Packages      []string // packages of active connections
	Channels      []string // active notification channel kinds
	SIEM          bool     // an active SIEM destination
	FactProviders bool     // an active fact provider
}

// Facts are the signals of one read. Agents, Secrets and DataAgents hold
// only what the viewer may see; Integrations and the onboarding fields are
// the org's.
type Facts struct {
	Agents       map[string]Group // per execution context
	Secrets      map[string]Group // open scan discoveries per credential kind
	DataAgents   Group
	// ManagedSettings are the open scan discoveries a scan found on a machine
	// with no managed settings file (G0 M23 D114).
	ManagedSettings Group
	Integrations    Integrations
	// FirstDecision and FirstHold are the onboarding records that show the
	// org makes real decisions and holds real actions; nil until it does.
	FirstDecision, FirstHold *ids.UUID
}

// Evidence is what made an entry apply.
type Evidence struct {
	Source  Source
	Count   int
	Records []Record
	Link    string
}

// Target is an integration that would help. Package is empty when it is
// not a connection.
type Target struct {
	Name    string
	Package string
}

// Entry is one catalog entry.
type Entry struct {
	ID               ID
	Category         Category
	Reach            Reach
	Title            string
	Detail           string
	Targets          []Target
	Enables          []string
	StillUnsupported []string
	Source           Source
	// Link is the read procedure that lists the evidence.
	Link string
	// signal returns the evidence's records and whether the entry applies.
	signal func(Facts) (Group, string, bool)
}

// Evaluate returns the entry's evidence, and whether it applies to f.
func (e Entry) Evaluate(f Facts) (Evidence, bool) {
	g, kind, ok := e.signal(f)
	if !ok {
		return Evidence{}, false
	}
	ev := Evidence{Source: e.Source, Count: g.Count, Link: e.Link}
	for _, id := range g.IDs[:min(len(g.IDs), MaxRecords)] {
		ev.Records = append(ev.Records, Record{Kind: kind, ID: id})
	}
	return ev, true
}

// Tool packages the catalog points to. The GitLab, Jira, Teams and AWS
// names come from the G0 M20 D254 plans.
const (
	PackageGitLab = "pc.gitlab"
	PackageJira   = "pc.jira"
	PackageTeams  = "pc.teams"
	PackageAWS    = "pc.aws"
	// PackageAWSECS is an AWS connection too (D284: one host per connection).
	PackageAWSECS = "pc.aws.ecs"
)

// Procedures that list evidence.
const (
	linkAgents       = "/pantherclaw.v1.AgentService/ListAgents"
	linkCoverage     = "/pantherclaw.v1.CoverageService/ListCoverage"
	linkOnboarding   = "/pantherclaw.v1.OnboardingService/GetProgress"
	linkChannels     = "/pantherclaw.v1.NotificationService/ListChannels"
	linkConnections  = "/pantherclaw.v1.ConnectionService/ListConnections"
	linkDestinations = "/pantherclaw.v1.SIEMService/ListSIEMDestinations"
)

// SecretKinds are the credential kinds entries read from discoveries, the
// only values of an untrusted discovery that matter.
var (
	awsSecrets   = []string{"aws_access_key_id", "aws_secret_access_key"}
	modelSecrets = []string{"anthropic_api_key", "google_api_key", "openai_api_key"}
)

// SecretKinds returns every credential kind the catalog reads.
func SecretKinds() []string { return slices.Concat(awsSecrets, modelSecrets) }

// The integration kinds that close an entry, as the database stores them.
var (
	ciIssuers    = []string{"github_actions", "gitlab_ci"}
	kubeIssuers  = []string{"kubernetes", "spiffe_jwt"}
	cloudIssuers = []string{"aws_iam", "gcp_workload", "azure_mi", "entra_agent_id", "spiffe_jwt"}
	chatChannels = []string{"slack", "slack_app", "teams_app"}
)

// IntegrationKinds returns every issuer and channel kind the catalog reads.
func IntegrationKinds() []string {
	return slices.Concat(ciIssuers, kubeIssuers, cloudIssuers, chatChannels)
}

func anyOf(have []string, want ...string) bool {
	return slices.ContainsFunc(want, func(w string) bool { return slices.Contains(have, w) })
}

// agents applies when the viewer sees agents of context and the org has no
// active issuer of the kinds.
func agents(context string, issuers ...string) func(Facts) (Group, string, bool) {
	return func(f Facts) (Group, string, bool) {
		g := f.Agents[context]
		return g, RecordAgent, g.Count > 0 && !anyOf(f.Integrations.Issuers, issuers...)
	}
}

// secrets sums the groups of the credential kinds.
func secrets(f Facts, kinds []string) Group {
	var out Group
	for _, k := range kinds {
		g := f.Secrets[k]
		out.Count += g.Count
		out.IDs = append(out.IDs, g.IDs...)
	}
	return out
}

// record is one onboarding record as evidence; nil is none.
func record(id *ids.UUID) Group {
	if id == nil {
		return Group{}
	}
	return Group{Count: 1, IDs: []ids.UUID{*id}}
}

// Catalog returns every entry, in the order reads return them.
func Catalog() []Entry {
	return []Entry{
		{
			ID: CIWorkload, Category: Identity, Reach: OrgWide, Source: FromAgents, Link: linkAgents,
			Title:  "Connect your CI system's workload identity",
			Detail: "Agents run in CI, and no CI identity issuer is active, so they cannot prove which pipeline they run in.",
			Targets: []Target{
				{Name: "GitHub Actions workload identity"},
				{Name: "GitLab CI workload identity"},
			},
			Enables: []string{
				"Agents enroll from the pipeline's own short-lived token, with no stored secret.",
				"Policy can tell a protected branch's pipeline from any other.",
			},
			StillUnsupported: []string{
				"Other CI systems have no preset; they need a SPIFFE JWT-SVID issuer.",
				"X.509 and instance attestation are not supported.",
			},
			signal: agents(ContextCI, ciIssuers...),
		},
		{
			ID: KubeWorkload, Category: Identity, Reach: OrgWide, Source: FromAgents, Link: linkAgents,
			Title:   "Connect your Kubernetes clusters' workload identity",
			Detail:  "Agents run in Kubernetes, and no cluster or SPIFFE issuer is active.",
			Targets: []Target{{Name: "Kubernetes service account tokens"}, {Name: "SPIFFE JWT-SVID"}},
			Enables: []string{
				"Agents enroll from a projected service account token, with no stored secret.",
				"Policy can tell one namespace's or workload's agent from another's.",
			},
			StillUnsupported: []string{"X.509 SVIDs and node attestation are not supported."},
			signal:           agents(ContextKubernetes, kubeIssuers...),
		},
		{
			ID: CloudWorkload, Category: Identity, Reach: OrgWide, Source: FromAgents, Link: linkAgents,
			Title:  "Connect your cloud's workload identity",
			Detail: "Agents run as services, and no cloud workload issuer is active.",
			Targets: []Target{
				{Name: "AWS IAM workload identity"},
				{Name: "Google Cloud workload identity"},
				{Name: "Azure managed identity"},
				{Name: "Microsoft Entra Agent ID"},
			},
			Enables: []string{"Services enroll from their cloud identity, with no stored secret."},
			StillUnsupported: []string{
				"Instance attestation is not supported.",
				"Other clouds need a SPIFFE JWT-SVID issuer.",
			},
			signal: agents(ContextService, cloudIssuers...),
		},
		{
			ID: AWSKeys, Category: Identity, Reach: OrgWide, Source: FromDiscoveries, Link: linkAgents,
			Title:  "Put AWS access behind a connection",
			Detail: "A scan found AWS credentials beside an agent, and no AWS connection is active.",
			Targets: []Target{
				{Name: "AWS connection", Package: PackageAWS},
				{Name: "AWS IAM workload identity"},
			},
			Enables: []string{
				"Agents act through short-lived sessions narrowed to one action, with the base key held by the gateway.",
				"ECS deployments are checked against the service's state afterwards.",
			},
			StillUnsupported: []string{
				"Only ECS deployment and IAM read operations are packaged; other AWS actions are not governed.",
				"A key used outside a gateway is not seen, so remove the credentials the scan found.",
			},
			signal: func(f Facts) (Group, string, bool) {
				g := secrets(f, awsSecrets)
				return g, RecordDiscovery, g.Count > 0 && !anyOf(f.Integrations.Packages, PackageAWS, PackageAWSECS)
			},
		},
		{
			ID: DataClasses, Category: Classification, Reach: OrgWide, Source: FromCoverage, Link: linkCoverage,
			Title:   "Connect a classification source",
			Detail:  "Agents use database connections, and no fact provider is active to say what class of data they hold.",
			Targets: []Target{{Name: "Classification fact provider"}},
			Enables: []string{"Policy and data scoping can use your own data classes for what an agent reads."},
			StillUnsupported: []string{
				"PantherClaw does not scan or classify data itself; classes come only from your provider.",
				"Data without a class stays unclassified, and is not treated as safe.",
			},
			signal: func(f Facts) (Group, string, bool) {
				return f.DataAgents, RecordAgent, f.DataAgents.Count > 0 && !f.Integrations.FactProviders
			},
		},
		{
			ID: ApprovalChat, Category: Approval, Reach: OrgWide, Source: FromOnboarding, Link: linkChannels,
			Title:  "Send approvals to where your people work",
			Detail: "Actions are being held for approval, and no Slack or Teams channel is active to tell deciders.",
			Targets: []Target{
				{Name: "Slack"},
				{Name: "Microsoft Teams"},
			},
			Enables: []string{"Eligible deciders hear about a held action without watching the console."},
			StillUnsupported: []string{
				"Teams cards and Slack direct messages carry a link only; the decision is made in PantherClaw.",
				"Other chat systems are not supported.",
			},
			signal: func(f Facts) (Group, string, bool) {
				return record(f.FirstHold), RecordTransaction,
					f.FirstHold != nil && !anyOf(f.Integrations.Channels, chatChannels...)
			},
		},
		{
			ID: IncidentTicket, Category: Incident, Reach: OrgWide, Source: FromOnboarding, Link: linkConnections,
			Title:   "Connect your ticket system",
			Detail:  "PantherClaw is making real decisions, and no Jira connection is active to carry its cases.",
			Targets: []Target{{Name: "Jira", Package: PackageJira}},
			Enables: []string{"Cases sync with Jira issues, with one owner for each field."},
			StillUnsupported: []string{
				"Jira is the only ticket system; others are not supported.",
				"Containment and restoration never follow a Jira field.",
			},
			signal: func(f Facts) (Group, string, bool) {
				return record(f.FirstDecision), RecordTransaction,
					f.FirstDecision != nil && !slices.Contains(f.Integrations.Packages, PackageJira)
			},
		},
		{
			ID: SIEMExport, Category: Export, Reach: OrgWide, Source: FromOnboarding, Link: linkDestinations,
			Title:   "Export decisions to your SIEM",
			Detail:  "PantherClaw is making real decisions, and no SIEM destination is active.",
			Targets: []Target{{Name: "SIEM export (OCSF)"}},
			Enables: []string{"Decisions, alerts, incidents, audit, containment and coverage reach your SIEM as OCSF events."},
			StillUnsupported: []string{
				"SIEM export needs the Business edition.",
				"OCSF over HTTPS is the only format.",
			},
			signal: func(f Facts) (Group, string, bool) {
				return record(f.FirstDecision), RecordTransaction, f.FirstDecision != nil && !f.Integrations.SIEM
			},
		},
		{
			ID: ModelKeys, Category: Unsupported, Reach: AgentBacked, Source: FromDiscoveries, Link: linkAgents,
			Title:  "Model provider keys have no integration",
			Detail: "A scan found model provider keys beside an agent. No integration governs an agent's own model calls.",
			StillUnsupported: []string{
				"PantherClaw has no connection for model provider APIs, so these calls are not decided or recorded.",
			},
			signal: func(f Facts) (Group, string, bool) {
				g := secrets(f, modelSecrets)
				return g, RecordDiscovery, g.Count > 0
			},
		},
		{
			ID: ManagedSettings, Category: Unsupported, Reach: AgentBacked, Source: FromDiscoveries, Link: linkAgents,
			Title: "Managed settings are missing",
			Detail: "A scan found agents on a machine with no managed settings file, so nothing there pins the PantherClaw hook or the allowed MCP servers. " +
				"pclaw managed-settings generate writes the files for your own device management to install.",
			StillUnsupported: []string{
				"pclaw reads only the platform's managed settings file: registry, MDM and server-managed settings cannot be read, so a machine they manage still shows here.",
				"A managed settings file is not coverage: generating or finding one changes no coverage state.",
			},
			signal: func(f Facts) (Group, string, bool) {
				return f.ManagedSettings, RecordDiscovery, f.ManagedSettings.Count > 0
			},
		},
	}
}

// Lookup returns the entry with id.
func Lookup(id ID) (Entry, bool) {
	for _, e := range Catalog() {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}
