// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package mapping holds PantherClaw's own threat-map tables (G0 M28 D710,
// D714): the Prevent controls, the kinds of behavior and content signals,
// the techniques outside PantherClaw and those inside an agent platform's
// reach that PantherClaw ships no control for. Pure data; it imports only
// the catalog. A mapping says "this control acts on this technique when
// an AI agent carries it out through PantherClaw".
package mapping

import "slices"

// Surface is where a Prevent control acts (D714).
type Surface string

// Surfaces (closed).
const (
	SurfaceAuthority  Surface = "AUTHORITY"
	SurfaceGateway    Surface = "GATEWAY"
	SurfaceSandbox    Surface = "SANDBOX"
	SurfaceCredential Surface = "CREDENTIAL"
	// SurfaceConnector: a connector refuses the act itself, before anything is
	// sent (G0 M30 D948).
	SurfaceConnector Surface = "CONNECTOR"
	// SurfaceBrowser: the managed browser extension refuses or holds the act
	// before the browser does it; cooperative (G0 M33 D987).
	SurfaceBrowser Surface = "BROWSER"
)

// Surfaces lists every Surface.
func Surfaces() []Surface {
	return []Surface{SurfaceAuthority, SurfaceGateway, SurfaceSandbox, SurfaceCredential, SurfaceConnector, SurfaceBrowser}
}

// Valid reports whether s is a listed Surface.
func (s Surface) Valid() bool { return slices.Contains(Surfaces(), s) }

// Requirement is what must hold for a Prevent control to act (D714).
type Requirement string

// Requirements (closed). A control that needs anything else is a question
// for the coordinator, never a new value here.
const (
	// RequiresAlways: the control is part of every decision.
	RequiresAlways Requirement = "ALWAYS"
	// RequiresContentSignalsActive: content signals mode ACTIVE and the
	// edition's ContentSignals().
	RequiresContentSignalsActive Requirement = "CONTENT_SIGNALS_ACTIVE"
	// RequiresMCPCatalogEnforcing: the M24 MCP catalog enforcement is on.
	RequiresMCPCatalogEnforcing Requirement = "MCP_CATALOG_ENFORCING"
	// RequiresBrowserExtensionDeployed: the managed extension is
	// force-installed with its native host for the agent's browser (G0 M33
	// D987).
	RequiresBrowserExtensionDeployed Requirement = "BROWSER_EXTENSION_DEPLOYED"
)

// Requirements lists every Requirement.
func Requirements() []Requirement {
	return []Requirement{RequiresAlways, RequiresContentSignalsActive, RequiresMCPCatalogEnforcing, RequiresBrowserExtensionDeployed}
}

// Valid reports whether r is a listed Requirement.
func (r Requirement) Valid() bool { return slices.Contains(Requirements(), r) }

// PreventControl is one PantherClaw control that refuses or holds an act
// carrying out the techniques it lists (D714).
type PreventControl struct {
	// ID is "prevent.<slug>".
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	Surface Surface `json:"surface"`
	// ReasonCodes are the decisive pc.transactions.reason_code values that
	// are this control's refusals and holds.
	ReasonCodes []string `json:"reason_codes"`
	// OutcomeCodes are the execution outcome codes that are this control's
	// refusals when it acts after the decision (G0 M30 D948, F-M28-2).
	OutcomeCodes []string `json:"outcome_codes,omitzero"`
	// HR are the hardening rules (HR-###) that state the control.
	HR         []string    `json:"hr"`
	Requires   Requirement `json:"requires"`
	Techniques []string    `json:"techniques"`
	// Why gives each technique one line that cites its id.
	Why map[string]string `json:"why"`
}

// Prevent is every Prevent control (D714).
var Prevent = []PreventControl{
	{
		ID: "prevent.grant_scope", Title: "Grants name the operations, targets and limits an agent may use", Surface: SurfaceAuthority,
		ReasonCodes: []string{"NO_GRANT", "OPERATION_NOT_GRANTED", "TARGET_NOT_GRANTED", "OUTSIDE_GUARDRAIL", "GRANT_LIMIT_EXCEEDED"},
		HR:          []string{"HR-045", "HR-046"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0053", "AML.T0101", "AML.T0036", "T1213", "T1485", "T1565.001", "T1567.001"},
		Why: map[string]string{
			"AML.T0053": "AI agent tool invocation (AML.T0053): a tool call outside the agent's grant is denied before it runs.",
			"AML.T0101": "Data destruction via AI agent tool invocation (AML.T0101): a delete the grant does not name is denied.",
			"AML.T0036": "Data from information repositories (AML.T0036): reads reach only the targets and records the grant names.",
			"T1213":     "Data from information repositories (T1213): an agent's read outside its granted targets is denied.",
			"T1485":     "Data destruction (T1485): a destructive operation the grant does not name is denied.",
			"T1565.001": "Stored data manipulation (T1565.001): a write the grant does not name is denied.",
			"T1567.001": "Exfiltration to code repository (T1567.001): a push to a repository the grant does not name is denied.",
		},
	},
	{
		// G0 M28 D714f: no reason code, like sandbox_closure; the verifier's
		// refusal is the token endpoint's invalid_grant, not a decision.
		ID: "prevent.idp_assertion", Title: "Only a verified IdP assertion narrows a grant the person holds", Surface: SurfaceCredential,
		HR:         []string{"HR-620", "HR-622"},
		Requires:   RequiresAlways,
		Techniques: []string{"T1606"},
		Why: map[string]string{
			"T1606": "Forge web credentials (T1606): the ID-JAG verifier refuses forged, replayed and misaddressed assertions; RT-150 tests it.",
		},
	},
	{
		ID: "prevent.destination_grant", Title: "Writes go only to granted destinations and channels", Surface: SurfaceAuthority,
		ReasonCodes: []string{"DESTINATION_NOT_GRANTED", "DISCLOSURE_LIMIT", "CHANNEL_NOT_ALLOWED"},
		HR:          []string{"HR-079"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0086", "T1567", "T1700"},
		Why: map[string]string{
			"AML.T0086": "Exfiltration via AI agent tool invocation (AML.T0086): a write to a destination the grant does not name is denied.",
			"T1567":     "Exfiltration over web service (T1567): a post to a repository, channel or service outside the destinations is denied.",
			"T1700":     "AI-enabled exfiltration (T1700): an agent told to send data to a place its grant does not name is denied.",
		},
	},
	{
		ID: "prevent.data_flow_hold", Title: "A disclosure after a sensitive read waits for a person", Surface: SurfaceAuthority,
		ReasonCodes: []string{"DATA_FLOW_HOLD"},
		HR:          []string{"HR-431"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0086", "T1567", "T1700"},
		Why: map[string]string{
			"AML.T0086": "Exfiltration via AI agent tool invocation (AML.T0086): an external disclosure after a pii or secret read is held.",
			"T1567":     "Exfiltration over web service (T1567): a public write after a sensitive read in the run is held for a person.",
			"T1700":     "AI-enabled exfiltration (T1700): an agent led to disclose what it just read sensitively waits for a person.",
		},
	},
	{
		ID: "prevent.secret_outbound", Title: "Outgoing actions carrying a secret are refused", Surface: SurfaceGateway,
		ReasonCodes: []string{"secret_in_payload", "SECRET_IN_PAYLOAD"},
		HR:          []string{"HR-225"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0055", "AML.T0086", "T1552.001", "T1552.004", "T1567.001"},
		Why: map[string]string{
			"AML.T0055": "Unsecured credentials (AML.T0055): a found credential placed in an outgoing action is refused.",
			"AML.T0086": "Exfiltration via AI agent tool invocation (AML.T0086): a tool write carrying a secret is refused or held.",
			"T1552.001": "Credentials in files (T1552.001): a token read from a file cannot leave in an outgoing action.",
			"T1552.004": "Private keys (T1552.004): a private key found in the workspace cannot leave in an outgoing action.",
			"T1567.001": "Exfiltration to code repository (T1567.001): a commit carrying a found credential is refused or held.",
		},
	},
	{
		ID: "prevent.workload_proof", Title: "Every call proves the agent's key, once, with a fresh nonce", Surface: SurfaceCredential,
		ReasonCodes: []string{"key_mismatch", "proof_replay", "use_nonce", "invalid_proof", "IDENTITY_UNVERIFIED"},
		HR:          []string{"HR-090", "HR-091"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0091.000", "AML.T0073", "T1550.001"},
		Why: map[string]string{
			"AML.T0091.000": "Application access token (AML.T0091.000): a stolen token without its key, or with a replayed proof, is refused.",
			"AML.T0073":     "Impersonation (AML.T0073): an enforcement point asking for decisions as an agent it cannot prove to be is refused.",
			"T1550.001":     "Application access token (T1550.001): a token used apart from the bound key or with a used proof is refused.",
		},
	},
	{
		ID: "prevent.approval_independence", Title: "A held action needs an independent person, for the exact action", Surface: SurfaceAuthority,
		ReasonCodes: []string{"GRANT_REQUIRES_APPROVAL", "ACTION_TAMPERED"},
		HR:          []string{"HR-036", "HR-006", "HR-207"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0073", "T1548"},
		Why: map[string]string{
			"AML.T0073": "Impersonation (AML.T0073): a Slack action posing as a person's approval releases nothing.",
			"T1548":     "Abuse elevation control mechanism (T1548): self-approval, reused approvals and changes after approval are refused.",
		},
	},
	{
		ID: "prevent.tool_package_review", Title: "Agents get reviewed tool definitions; drift quarantines the package", Surface: SurfaceGateway,
		ReasonCodes: []string{"upstream_drift", "PACKAGE_QUARANTINED"},
		HR:          []string{"HR-081"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0110.000", "AML.T0109", "AML.T0010.005", "T1195.001"},
		Why: map[string]string{
			"AML.T0110.000": "AI agent tool poisoning, definition and instructions (AML.T0110.000): agents never see live upstream descriptions.",
			"AML.T0109":     "AI supply chain rug pull (AML.T0109): a reviewed package that changes upstream is quarantined.",
			"AML.T0010.005": "AI supply chain compromise, AI agent tool (AML.T0010.005): only the reviewed tool package reaches the agent.",
			"T1195.001":     "Compromise software dependencies and development tools (T1195.001): a tool package changed after review is quarantined.",
		},
	},
	{
		ID: "prevent.mcp_catalog", Title: "Only catalog-approved MCP servers connect", Surface: SurfaceGateway,
		ReasonCodes: []string{"CONNECTION_QUARANTINED"},
		HR:          []string{"HR-585", "HR-586"}, Requires: RequiresMCPCatalogEnforcing,
		Techniques: []string{"AML.T0010.005"},
		Why: map[string]string{
			"AML.T0010.005": "AI supply chain compromise, AI agent tool (AML.T0010.005): an MCP server outside the catalog is quarantined.",
		},
	},
	{
		ID: "prevent.sandbox_closure", Title: "The sandbox's only route is the edge", Surface: SurfaceSandbox,
		HR:       []string{"HR-122", "HR-214"},
		Requires: RequiresAlways,
		Techniques: []string{
			"AML.T0105", "AML.T0025", "AML.T0072", "T1611", "T1552.005", "T1552.004", "T1071.004", "T1048", "T1095", "T1105",
			"T1041", "T1572", "T1090",
		},
		Why: map[string]string{
			"AML.T0105": "Escape to host (AML.T0105): the sandbox has no route to the host, its gateway or docker.sock.",
			"AML.T0025": "Exfiltration via cyber means (AML.T0025): every path out of the sandbox but the edge has no route.",
			"AML.T0072": "Cyber communication channel (AML.T0072): a command channel from the sandbox has no route but the edge.",
			"T1611":     "Escape to host (T1611): sandbox networks reach neither the host nor the Docker socket.",
			"T1552.005": "Cloud instance metadata API (T1552.005): the metadata address has no route from the sandbox.",
			"T1552.004": "Private keys (T1552.004): a push over SSH with a found key has no route out of the sandbox.",
			"T1071.004": "DNS (T1071.004): the sandbox has no resolver route to the internet.",
			"T1048":     "Exfiltration over alternative protocol (T1048): IPv6, ICMP and raw ports have no route out of the sandbox.",
			"T1095":     "Non-application layer protocol (T1095): ICMP and raw sockets have no route out of the sandbox.",
			"T1105":     "Ingress tool transfer (T1105): the edge refuses every host without a mapped connection.",
			"T1041":     "Exfiltration over C2 channel (T1041): a command channel from the sandbox has no route out but the edge.",
			"T1572":     "Protocol tunneling (T1572): a tunnel from the sandbox has no route out but the edge, which maps each call.",
			"T1090":     "Proxy (T1090): a proxy outside the edge has no route from the sandbox.",
		},
	},
	{
		ID: "prevent.edge_credential_strip", Title: "The edge strips credentials the agent found", Surface: SurfaceCredential,
		HR:         []string{"HR-213"},
		Requires:   RequiresAlways,
		Techniques: []string{"AML.T0055", "T1552.001"},
		Why: map[string]string{
			"AML.T0055": "Unsecured credentials (AML.T0055): a found token sent through the sandbox edge is stripped and reported.",
			"T1552.001": "Credentials in files (T1552.001): a token read from a workspace file is stripped at the edge.",
		},
	},
	{
		ID: "prevent.egress_guard", Title: "Connections never dial private, loopback or metadata addresses", Surface: SurfaceGateway,
		ReasonCodes: []string{"egress_denied"},
		HR:          []string{"HR-071", "HR-077", "HR-072"}, Requires: RequiresAlways,
		Techniques: []string{"T1552.005"},
		Why: map[string]string{
			"T1552.005": "Cloud instance metadata API (T1552.005): a tool call or redirect toward the metadata address is denied at dial.",
		},
	},
	{
		ID: "prevent.budgets", Title: "Budgets and counters bound what an agent spends", Surface: SurfaceAuthority,
		ReasonCodes: []string{"BUDGET_EXHAUSTED", "COUNT_LIMIT_REACHED", "BUDGET_BUSY"},
		HR:          []string{"HR-048", "HR-049"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0048.000", "T1657"},
		Why: map[string]string{
			"AML.T0048.000": "Financial harm (AML.T0048.000): concurrent or split payments stop at the grant's budget.",
			"T1657":         "Financial theft (T1657): refunds and transfers past the budget or counter are denied.",
		},
	},
	{
		ID: "prevent.delegation_bounds", Title: "A child grant stays within its parent", Surface: SurfaceAuthority,
		ReasonCodes: []string{"DELEGATION_NOT_ALLOWED", "GRANT_EXPIRED", "GRANT_REVOKED"},
		HR:          []string{"HR-045", "HR-047"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0118.001"},
		Why: map[string]string{
			"AML.T0118.001": "Direct agent communication (AML.T0118.001): a delegation wider or longer than its parent is refused.",
		},
	},
	{
		ID: "prevent.content_hold", Title: "In ACTIVE, flagged content holds the run's later writes", Surface: SurfaceGateway,
		ReasonCodes: []string{"CONTENT_FLAG_HOLD"},
		HR:          []string{"HR-648", "HR-650", "HR-703"}, Requires: RequiresContentSignalsActive,
		Techniques: []string{"AML.T0051.001", "AML.T0110.002", "AML.T0099", "AML.T0093", "T1698", "AML.T0068"},
		Why: map[string]string{
			"AML.T0051.001": "Indirect prompt injection (AML.T0051.001): after an injection phrase is flagged, the run's writes wait for a person.",
			"AML.T0110.002": "AI agent tool poisoning, runtime response (AML.T0110.002): a flagged tool result holds the run's later writes.",
			"AML.T0099":     "AI agent tool data poisoning (AML.T0099): poisoned data a tool returns, once flagged, holds the run's later writes.",
			"AML.T0093":     "Prompt infiltration via public-facing application (AML.T0093): a hostile SaaS field returned to the agent, once flagged, holds the run's later writes.",
			"T1698":         "Indirect prompt injection (T1698): a write carrying or following flagged text is held.",
			"AML.T0068":     "LLM prompt obfuscation (AML.T0068): text hidden by encoding, escapes, look-alike letters or invisible characters is decoded before matching; a decoded hit holds the run's later writes.",
		},
	},
	{
		ID: "prevent.consequence_rules", Title: "An action whose consequence is unknown is held", Surface: SurfaceAuthority,
		ReasonCodes: []string{"CONSEQUENCE_UNKNOWN"},
		HR:          []string{"HR-206"}, Requires: RequiresAlways,
		Techniques: []string{"T1677"},
		Why: map[string]string{
			"T1677": "Poisoned pipeline execution (T1677): a merge that changes a CI workflow is held as an unknown consequence.",
		},
	},
	{
		ID: "prevent.mapped_routes", Title: "Only mapped, unambiguous calls reach a decision", Surface: SurfaceAuthority,
		ReasonCodes: []string{"ROUTE_UNKNOWN", "unknown_route", "AMBIGUOUS_INPUT"},
		HR:          []string{"HR-103", "HR-201"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0053"},
		Why: map[string]string{
			"AML.T0053": "AI agent tool invocation (AML.T0053): a call no package maps, or one with ambiguous input, is never allowed by default.",
		},
	},
	// G0 M30 D947, D948: the M30 controls.
	{
		ID: "prevent.mcp_token_binding", Title: "An MCP token bound to a client's key is refused without a fresh proof of that key", Surface: SurfaceCredential,
		ReasonCodes: []string{"invalid_dpop_proof", "use_dpop_nonce"},
		HR:          []string{"HR-700", "HR-701", "HR-702"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0091.000", "T1550.001"},
		Why: map[string]string{
			"AML.T0091.000": "Application access token (AML.T0091.000): a copied MCP token bound to a client's key is refused without a fresh proof of that key.",
			"T1550.001":     "Application access token (T1550.001): a bound MCP token sent as a bearer token, or with a replayed proof, is refused.",
		},
	},
	{
		ID: "prevent.read_limits", Title: "A read limit counts an agent's reads per task", Surface: SurfaceAuthority,
		ReasonCodes: []string{"COUNT_LIMIT_REACHED"},
		HR:          []string{"HR-706"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0126", "T1119"},
		Why: map[string]string{
			"AML.T0126": "Automated collection (AML.T0126): reads past the grant's read limit for the task are denied.",
			"T1119":     "Automated collection (T1119): bulk reads stop at the count the grant's read limit allows.",
		},
	},
	{
		ID: "prevent.share_accounts", Title: "A share to the public or to an account the organization does not own waits for a person", Surface: SurfaceAuthority,
		ReasonCodes: []string{"SHARE_ACCOUNT_NOT_OWNED", "SHARE_PUBLIC"},
		HR:          []string{"HR-707", "HR-708"}, Requires: RequiresAlways,
		Techniques: []string{"T1537"},
		Why: map[string]string{
			"T1537": "Transfer data to cloud account (T1537): a bucket policy, ACL, visibility change or transfer that shares with an account not on the organization's list is held.",
		},
	},
	{
		ID: "prevent.agent_config", Title: "Agent configuration and memory files are read-only in the sandbox and their writes ask the gateway", Surface: SurfaceSandbox,
		HR:         []string{"HR-710", "HR-712", "HR-713"},
		Requires:   RequiresAlways,
		Techniques: []string{"AML.T0081", "AML.T0083", "AML.T0084"},
		Why: map[string]string{
			"AML.T0081": "Modify AI agent configuration (AML.T0081): configuration and memory files are bound read-only in the sandbox, and a hooked write to one needs a grant.",
			"AML.T0083": "Credentials from AI agent configuration (AML.T0083): scans report credential formats found in agent configuration files, never the values.",
			"AML.T0084": "Discover AI agent configuration (AML.T0084): scans record a digest of each agent configuration file, never its contents.",
		},
	},
	{
		ID: "prevent.vector_writers", Title: "Only listed agents write to a vector store without a person", Surface: SurfaceAuthority,
		ReasonCodes: []string{"VECTOR_WRITE_NOT_WRITER"},
		HR:          []string{"HR-704", "HR-705"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0070", "AML.T0071"},
		Why: map[string]string{
			"AML.T0070": "RAG poisoning (AML.T0070): an upsert or delete by an agent not on the store's writer list is held, and every entry carries the run that wrote it.",
			"AML.T0071": "False RAG entry injection (AML.T0071): an entry from an agent not on the writer list waits for a person.",
		},
	},
	{
		ID: "prevent.query_scope", Title: "A database query reaches only the manifest's tables and columns", Surface: SurfaceConnector,
		OutcomeCodes: []string{"table_not_allowed", "column_not_allowed"},
		HR:           []string{"HR-307", "HR-715"}, Requires: RequiresAlways,
		Techniques: []string{"T1213.006"},
		Why: map[string]string{
			"T1213.006": "Databases (T1213.006): a query naming a table, column or record scope outside the connection's manifest is refused before it is sent.",
		},
	},
	{
		// G0 M30 D947: M29's token caps (G0 M29 D821).
		ID: "prevent.token_caps", Title: "Token rules bound what an agent spends on its model", Surface: SurfaceAuthority,
		ReasonCodes: []string{"TOKEN_BUDGET_EXHAUSTED"},
		HR:          []string{"HR-693"}, Requires: RequiresAlways,
		Techniques: []string{"AML.T0034", "AML.T0029"},
		Why: map[string]string{
			"AML.T0034": "Cost harvesting (AML.T0034): a model call past the grant's, envelope's or run's token rule is denied before it reaches the provider.",
			"AML.T0029": "Denial of AI service (AML.T0029): an agent flooding its model connection stops at its token rule.",
		},
	},
	{
		// G0 M32 D970: no reason code, like sandbox_closure; the evidence is
		// the kube closures the server records from a pod's signed probe run.
		ID: "prevent.kubernetes_closure", Title: "An agent pod's only route is its edge sidecar", Surface: SurfaceSandbox,
		HR:         []string{"HR-741", "HR-742", "HR-743"},
		Requires:   RequiresAlways,
		Techniques: []string{"T1552.005", "T1613"},
		Why: map[string]string{
			"T1552.005": "Cloud instance metadata API (T1552.005): the metadata address has no route from an agent pod, as its kube closure shows.",
			"T1613":     "Container and resource discovery (T1613): an agent pod has no route to the cluster's API server or the kubelet, as its kube closure shows.",
		},
	},
	{
		// G0 M32 D967, D970: no reason code; the admission webhook's refusal
		// is an AdmissionReview deny, audited as kubernetes.admission_denied.
		ID: "prevent.kubernetes_admission", Title: "A pod in a protected namespace runs only with its edge sidecar and an issuer entry", Surface: SurfaceSandbox,
		HR:         []string{"HR-730", "HR-732", "HR-733", "HR-734"},
		Requires:   RequiresAlways,
		Techniques: []string{"T1610"},
		Why: map[string]string{
			"T1610": "Deploy container (T1610): the admission webhook denies a pod in a protected namespace without an issuer entry, the edge sidecar or pinned images, and every ephemeral container.",
		},
	},
	{
		// G0 M33 D987: the evidence is pc.browser transactions and their
		// SITE_NOT_LISTED holds; the extension is cooperative (PARTIAL, R-78).
		ID: "prevent.browser_sites", Title: "An agent's browser opens, submits to and downloads from listed sites only, unless a person allows it", Surface: SurfaceAuthority,
		ReasonCodes: []string{"SITE_NOT_LISTED"},
		HR:          []string{"HR-745", "HR-749", "HR-751"},
		Requires:    RequiresBrowserExtensionDeployed,
		Techniques:  []string{"AML.T0100", "AML.T0131"},
		Why: map[string]string{
			"AML.T0100": "AI agent clickbait (AML.T0100): a page, submit or marked click on a site not on the org's list is held for a person before the browser acts.",
			"AML.T0131": "Crafted AI assistant links (AML.T0131): a crafted link to a site not on the org's list is held for a person before the browser opens it.",
		},
	},
	{
		// G0 M33 D987: the evidence is the gateway's BROWSER_SECRET_FIELD
		// refusals; the extension refuses the input in the page (HR-752).
		ID: "prevent.browser_secret_fields", Title: "An agent never types into or submits password, one-time-code, payment or challenge fields", Surface: SurfaceBrowser,
		ReasonCodes: []string{"BROWSER_SECRET_FIELD"},
		HR:          []string{"HR-747", "HR-752"},
		Requires:    RequiresBrowserExtensionDeployed,
		Techniques:  []string{"T1696.001"},
		Why: map[string]string{
			"T1696.001": "Automate CAPTCHA completion (T1696.001): every pointer, key and input event in a challenge frame is refused, so the agent cannot solve it.",
		},
	},
	{
		// G0 M34 D999: no reason code of its own, like sandbox_closure; the
		// evidence is the transactions of the agent.deploy operations of
		// pc.aws-agentcore, pc.vertex-agent-engine and pc.azure-foundry,
		// which no template grants and which are irreversible.
		ID: "prevent.agent_deploy", Title: "An agent deploys or changes a cloud runtime's agent only through a decided, reviewed operation", Surface: SurfaceGateway,
		HR:         []string{"HR-763"},
		Requires:   RequiresAlways,
		Techniques: []string{"AML.T0103"},
		Why: map[string]string{
			"AML.T0103": "Deploy AI agent (AML.T0103): creating or updating an AgentCore runtime, a Vertex reasoning engine or a Foundry agent through PantherClaw is an irreversible agent.deploy operation that no template grants.",
		},
	},
	{
		// G0 M34 D999: no reason code of its own; the evidence is the
		// transactions of aws.ssm.send_command and azure.vm.run_command.
		ID: "prevent.cloud_admin_command", Title: "An agent runs a command through a cloud's management service only through a decided, reviewed operation", Surface: SurfaceGateway,
		HR:         []string{"HR-763"},
		Requires:   RequiresAlways,
		Techniques: []string{"T1651"},
		Why: map[string]string{
			"T1651": "Cloud administration command (T1651): aws.ssm.send_command and azure.vm.run_command through PantherClaw are irreversible code.execute operations, decided on their document, instances and commands.",
		},
	},
}
