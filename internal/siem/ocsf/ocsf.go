// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ocsf maps evidence feed events to OCSF 1.9 events (G0 M10 D36;
// PN-018, HR-260). The mapping is pure: the same feed event always gives
// the same bytes, so a batch re-sent after a failure is identical and a
// receiver can drop duplicates by metadata.uid, which is the ledger entry
// id.
//
// Class map (D36): decisions → API Activity (6003) with authorizations[];
// alerts → Detection Finding (2004); incidents and cases → Incident
// Finding (2005); audit of a person's account → Account Change (3001),
// signing in → Authentication (3002); audit of agent identity protection
// (D1205: the lifecycle of an agent's and an instance's identity, its
// tokens, refused token or code reuse, and the trusted issuers, identity
// providers and clients that vouch for who an agent is or acts for) →
// Account Change (3001), Authentication (3002) or Entity Management
// (3004), all in the Identity & Access Management category; other audit →
// API Activity (6003); everything else → Base Event (0). Runtime firewall
// decisions stay API Activity: identity protection says which agent is
// acting and for whom, the firewall decides what it may do.
// Each event carries its actor, the decision and reason, the policy
// version, effects, coverage and uncertainty when the feed has them, and
// never a payload or a secret: the feed carries none (D2).
package ocsf

import (
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
)

// Version is the OCSF schema version of every event.
const Version = "1.9.0"

// Product names PantherClaw in metadata.product.
const Product = "PantherClaw"

// DataClass selects what a destination receives (D35).
type DataClass string

// Data classes.
const (
	ClassDecisions   DataClass = "decisions"
	ClassAlerts      DataClass = "alerts"
	ClassIncidents   DataClass = "incidents"
	ClassAudit       DataClass = "audit"
	ClassContainment DataClass = "containment"
	ClassCoverage    DataClass = "coverage"
)

// DataClasses lists every data class.
var DataClasses = []DataClass{ClassDecisions, ClassAlerts, ClassIncidents, ClassAudit, ClassContainment, ClassCoverage}

// Valid reports whether c is a data class.
func (c DataClass) Valid() bool {
	for _, k := range DataClasses {
		if c == k {
			return true
		}
	}
	return false
}

// Event is one evidence feed event (D2).
type Event = feed.Event

// stateOf is an alert's, incident's or case's state: the feed carries it
// as the outcome of reflex entries.
func stateOf(e Event) string {
	if s := e.Attrs[AttrState]; s != "" {
		return s
	}
	return e.Outcome
}

// findingUID is the finding's own id (stable across its updates), else the
// ledger entry id.
func findingUID(e Event) string {
	if id := e.Attrs[AttrID]; id != "" {
		return id
	}
	return e.ID.String()
}

// ClassOf returns the data class of a feed kind; ok is false for a kind
// no destination receives (unknown kinds are never exported: a new kind
// is not shared until it is mapped, F3).
func ClassOf(kind string) (DataClass, bool) {
	switch {
	case strings.HasPrefix(kind, "receipt."):
		return ClassDecisions, true
	case kind == "reflex.alert":
		return ClassAlerts, true
	case kind == "reflex.incident", kind == "reflex.case":
		return ClassIncidents, true
	case strings.HasPrefix(kind, "response."), strings.HasPrefix(kind, "audit.containment."):
		return ClassContainment, true
	case strings.HasPrefix(kind, "coverage."), kind == "sandbox.closure", kind == "posture.finding":
		return ClassCoverage, true
	case strings.HasPrefix(kind, "audit."):
		return ClassAudit, true
	}
	return "", false
}

// Selected reports whether a destination with classes receives e.
func Selected(e Event, classes []DataClass) bool {
	c, ok := ClassOf(e.Kind)
	if !ok {
		return false
	}
	for _, k := range classes {
		if k == c {
			return true
		}
	}
	return false
}

// OCSF identifiers.
const (
	classBase            = 0
	classDetection       = 2004
	classIncident        = 2005
	classAccountChange   = 3001
	classAuthentication  = 3002
	classEntityMgmt      = 3004
	classAPIActivity     = 6003
	categoryFindings     = 2
	categoryIAM          = 3
	categoryApplication  = 6
	activityCreate       = 1
	activityRead         = 2
	activityUpdate       = 3
	activityDelete       = 4
	activityOther        = 99
	accountEnable        = 2
	accountDisable       = 5
	accountDelete        = 6
	accountAttach        = 7
	accountDetach        = 8
	accountMFAEnable     = 10
	accountMFADisable    = 11
	authnLogon           = 1
	authnLogoff          = 2
	authnTicket          = 3
	entityCreate         = 1
	entityUpdate         = 3
	entityDelete         = 4
	entityDisable        = 9
	entityActivate       = 10
	entityDeactivate     = 11
	findingUpdate        = 2
	findingClose         = 3
	findingStatusNew     = 1
	findingStatusInProg  = 2
	findingStatusSupp    = 3
	findingStatusResolve = 4
	incidentStatusClosed = 5
	statusUnknown        = 0
	statusSuccess        = 1
	statusFailure        = 2
	statusOther          = 99
	severityUnknown      = 0
	severityInfo         = 1
	severityLow          = 2
	severityMedium       = 3
	severityHigh         = 4
	severityCritical     = 5
)

// OCSF objects, with only the members PantherClaw fills. Field order is
// the encoding order, so the output is deterministic.

// Record is one OCSF event.
type Record struct {
	ClassUID       int             `json:"class_uid"`
	ClassName      string          `json:"class_name"`
	CategoryUID    int             `json:"category_uid"`
	CategoryName   string          `json:"category_name"`
	ActivityID     int             `json:"activity_id"`
	ActivityName   string          `json:"activity_name,omitzero"`
	TypeUID        int             `json:"type_uid"`
	Time           int64           `json:"time"`
	SeverityID     int             `json:"severity_id"`
	Severity       string          `json:"severity,omitzero"`
	StatusID       int             `json:"status_id,omitzero"`
	Status         string          `json:"status,omitzero"`
	StatusDetail   string          `json:"status_detail,omitzero"`
	Message        string          `json:"message,omitzero"`
	Metadata       Metadata        `json:"metadata"`
	Actor          *Actor          `json:"actor,omitzero"`
	API            *API            `json:"api,omitzero"`
	SrcEndpoint    *Endpoint       `json:"src_endpoint,omitzero"`
	Authorizations []Authorization `json:"authorizations,omitzero"`
	User           *User           `json:"user,omitzero"`
	Entity         *Entity         `json:"entity,omitzero"`
	FindingInfo    *FindingInfo    `json:"finding_info,omitzero"`
	FindingList    []FindingInfo   `json:"finding_info_list,omitzero"`
	Resources      []Resource      `json:"resources,omitzero"`
	Unmapped       *Unmapped       `json:"unmapped,omitzero"`
}

// Metadata is the OCSF metadata object.
type Metadata struct {
	Version   string   `json:"version"`
	UID       string   `json:"uid"`
	Sequence  int64    `json:"sequence"`
	EventCode string   `json:"event_code"`
	TenantUID string   `json:"tenant_uid"`
	Labels    []string `json:"labels,omitzero"`
	Product   Prod     `json:"product"`
}

// Prod is the OCSF product object.
type Prod struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version,omitzero"`
}

// Actor is the OCSF actor object.
type Actor struct {
	User *User `json:"user,omitzero"`
}

// User is the OCSF user object.
type User struct {
	UID    string `json:"uid"`
	Type   string `json:"type,omitzero"`
	TypeID int    `json:"type_id"`
}

// Entity is the OCSF managed entity object of an Entity Management event.
type Entity struct {
	UID    string `json:"uid"`
	Type   string `json:"type"`
	TypeID int    `json:"type_id"`
}

// API is the OCSF api object.
type API struct {
	Operation string  `json:"operation"`
	Service   Service `json:"service"`
}

// Service is the OCSF service object.
type Service struct {
	Name string `json:"name"`
}

// Endpoint is the OCSF network endpoint object.
type Endpoint struct {
	Name string `json:"name,omitzero"`
	Zone string `json:"zone,omitzero"`
}

// Authorization is the OCSF authorization result object.
type Authorization struct {
	Decision string  `json:"decision"`
	Policy   *Policy `json:"policy,omitzero"`
}

// Policy is the OCSF policy object.
type Policy struct {
	UID     string `json:"uid,omitzero"`
	Version string `json:"version,omitzero"`
	Desc    string `json:"desc,omitzero"`
}

// FindingInfo is the OCSF finding information object.
type FindingInfo struct {
	UID      string    `json:"uid"`
	Title    string    `json:"title,omitzero"`
	Desc     string    `json:"desc,omitzero"`
	Types    []string  `json:"types,omitzero"`
	Analytic *Analytic `json:"analytic,omitzero"`
	Attacks  []Attack  `json:"attacks,omitzero"`
}

// Analytic is the OCSF analytic object (the detection rule).
type Analytic struct {
	UID     string `json:"uid"`
	Name    string `json:"name,omitzero"`
	Type    string `json:"type"`
	TypeID  int    `json:"type_id"`
	Version string `json:"version,omitzero"`
}

// Attack is the OCSF attack object: one per (technique, tactic) of the
// ATLAS and ATT&CK techniques an alert or incident carries, with names and
// tactics from the pinned catalog (G0 M28 D718). A sub-technique fills
// SubTechnique and its parent Technique. Version is the ATT&CK catalog
// version, or "ATLAS <version>" for an ATLAS id.
type Attack struct {
	Tactic       *Tactic    `json:"tactic,omitzero"`
	Technique    *Technique `json:"technique,omitzero"`
	SubTechnique *Technique `json:"sub_technique,omitzero"`
	Version      string     `json:"version,omitzero"`
}

// Tactic is the OCSF tactic object.
type Tactic struct {
	UID  string `json:"uid"`
	Name string `json:"name,omitzero"`
}

// Technique is the OCSF technique (and sub-technique) object.
type Technique struct {
	UID  string `json:"uid"`
	Name string `json:"name,omitzero"`
}

// Resource is the OCSF resource details object.
type Resource struct {
	UID  string `json:"uid"`
	Type string `json:"type"`
}

// Unmapped carries PantherClaw facts OCSF has no member for.
type Unmapped struct {
	Kind             string            `json:"pantherclaw_kind"`
	Mode             string            `json:"pantherclaw_mode,omitzero"`
	Outcome          string            `json:"pantherclaw_outcome,omitzero"`
	Environment      string            `json:"pantherclaw_environment,omitzero"`
	DestinationClass string            `json:"pantherclaw_destination_class,omitzero"`
	Effect           string            `json:"pantherclaw_effect,omitzero"`
	Coverage         string            `json:"pantherclaw_coverage,omitzero"`
	Uncertainty      string            `json:"pantherclaw_uncertainty,omitzero"`
	Attrs            map[string]string `json:"pantherclaw_attrs,omitzero"`
}

// Attribute names the mapper reads from Event.Attrs (D2 Normalize).
const (
	AttrPolicyVersion = "policy_version"
	AttrPolicyDigest  = "policy_digest"
	AttrRuleID        = "rule"
	AttrRuleVersion   = "rule_version"
	AttrRuleDigest    = "rule_digest"
	AttrTitle         = "title"
	AttrSummary       = "summary"
	AttrSeverity      = "severity"
	AttrID            = "id"
	AttrState         = "state"
	AttrBasis         = "basis"
	AttrEffect        = "effect"
	AttrCoverage      = "coverage"
	AttrATLAS         = "atlas"
	AttrATTACK        = "attack"
	AttrOWASP         = "owasp"
)

// mappedAttrs are attributes placed in OCSF members; the rest go to
// unmapped.pantherclaw_attrs.
var mappedAttrs = map[string]bool{
	AttrPolicyVersion: true, AttrRuleID: true, AttrRuleVersion: true, AttrTitle: true, AttrSummary: true,
	AttrSeverity: true, AttrState: true, AttrID: true, AttrBasis: true, AttrEffect: true, AttrCoverage: true, AttrATLAS: true,
	AttrOWASP: true, AttrATTACK: true,
}

// Map returns the OCSF record of e. productVersion is PantherClaw's
// version (may be empty).
func Map(e Event, productVersion string) Record {
	r := Record{
		Time:       e.OccurredAt.UTC().UnixMilli(),
		SeverityID: severityInfo,
		Severity:   "Informational",
		Metadata: Metadata{
			Version: Version, UID: e.ID.String(), Sequence: e.Seq, EventCode: e.Kind, TenantUID: e.Org.String(),
			Product: Prod{Name: Product, VendorName: Product, Version: productVersion},
		},
		Actor:     actorOf(e),
		Resources: resourcesOf(e.Subjects),
		Unmapped:  unmappedOf(e),
	}
	if e.Test {
		r.Metadata.Labels = []string{"test"}
	}
	class, _ := ClassOf(e.Kind)
	switch {
	case class == ClassDecisions:
		mapDecision(&r, e)
	case class == ClassAlerts:
		mapDetection(&r, e)
	case class == ClassIncidents:
		mapIncident(&r, e)
	case class == ClassAudit && isAgentIdentity(e.Kind):
		mapAgentIdentity(&r, e)
	case class == ClassAudit && hasAnyPrefix(e.Kind, accountKinds):
		mapAccountChange(&r, e)
	case class == ClassAudit && hasAnyPrefix(e.Kind, authnKinds):
		mapAuthentication(&r, e)
	case class == ClassAudit:
		mapAudit(&r, e)
	default:
		r.ClassUID, r.ClassName, r.CategoryUID, r.CategoryName = classBase, "Base Event", 0, "Uncategorized"
		r.ActivityID, r.ActivityName = activityOther, "Other"
		r.Message = e.Kind
	}
	r.TypeUID = r.ClassUID*100 + r.ActivityID
	return r
}

func mapDecision(r *Record, e Event) {
	r.ClassUID, r.ClassName, r.CategoryUID, r.CategoryName = classAPIActivity, "API Activity", categoryApplication, "Application Activity"
	r.ActivityID, r.ActivityName = apiActivity(e.Operation)
	r.API = &API{Operation: nonEmpty(e.Operation, e.Kind), Service: Service{Name: Product}}
	r.SrcEndpoint = &Endpoint{Name: e.ActorType, Zone: e.Environment}
	if e.Decision != "" {
		a := Authorization{Decision: e.Decision}
		if v := e.Attrs[AttrPolicyVersion]; v != "" || e.Reason != "" {
			a.Policy = &Policy{UID: v, Version: v, Desc: e.Reason}
		}
		r.Authorizations = []Authorization{a}
	}
	r.StatusID, r.Status = decisionStatus(e.Decision)
	r.StatusDetail = e.Reason
	r.Message = strings.TrimSpace(e.Kind + " " + e.Decision)
	if e.Decision == "DENY" || e.Decision == "CANNOT_AUTHORIZE" {
		r.SeverityID, r.Severity = severityLow, "Low"
	}
}

func mapDetection(r *Record, e Event) {
	r.ClassUID, r.ClassName, r.CategoryUID, r.CategoryName = classDetection, "Detection Finding", categoryFindings, "Findings"
	r.ActivityID, r.ActivityName, r.StatusID, r.Status = findingActivity(stateOf(e))
	r.SeverityID, r.Severity = severityOf(e.Attrs[AttrSeverity])
	r.FindingInfo = findingInfo(e)
	r.Message = e.Attrs[AttrTitle]
}

func mapIncident(r *Record, e Event) {
	r.ClassUID, r.ClassName, r.CategoryUID, r.CategoryName = classIncident, "Incident Finding", categoryFindings, "Findings"
	r.ActivityID, r.ActivityName, r.StatusID, r.Status = incidentActivity(stateOf(e))
	r.SeverityID, r.Severity = severityOf(e.Attrs[AttrSeverity])
	r.FindingList = []FindingInfo{*findingInfo(e)}
	r.Message = e.Attrs[AttrTitle]
}

func mapAccountChange(r *Record, e Event) {
	r.ClassUID, r.ClassName, r.CategoryUID, r.CategoryName = classAccountChange, "Account Change", categoryIAM, "Identity & Access Management"
	r.ActivityID, r.ActivityName = accountActivity(e.Kind)
	r.StatusID, r.Status = statusOf(e.Outcome)
	r.User = subjectUser(e)
	r.Message = e.Kind
}

func mapAuthentication(r *Record, e Event) {
	r.ClassUID, r.ClassName, r.CategoryUID, r.CategoryName = classAuthentication, "Authentication", categoryIAM, "Identity & Access Management"
	r.ActivityID, r.ActivityName = authnActivity(e.Kind)
	r.StatusID, r.Status = statusOf(e.Outcome)
	r.User = subjectUser(e)
	r.Message = e.Kind
}

// identityEvent is how one audit kind of agent identity protection maps
// to an Identity & Access Management class (D1205).
type identityEvent struct {
	class, activity int
	activityName    string
	// entity is the managed entity's type, for Entity Management.
	entity string
	// refused: the entry records a refused use (a reused code, refresh
	// token or enrolment token, a key no admitted instance holds), so its
	// status is Failure.
	refused bool
}

// agentIdentityKinds are the audit kinds of agent identity protection
// (Badge; D1205), keyed without the "audit." prefix: the lifecycle of an
// agent's and an instance's identity (Account Change), its tokens and
// refused reuse (Authentication), and the trusted issuers, identity
// providers and clients that vouch for who an agent is or acts for (Entity
// Management). Runtime firewall audit (grants, guardrails, policies,
// connections) is not here: it stays API Activity.
var agentIdentityKinds = map[string]identityEvent{
	auditkind.AgentsAgentCreated:             {class: classAccountChange, activity: activityCreate, activityName: "Create"},
	auditkind.AgentsAgentSuspended:           {class: classAccountChange, activity: accountDisable, activityName: "Disable"},
	auditkind.AgentsAgentRetired:             {class: classAccountChange, activity: accountDelete, activityName: "Delete"},
	auditkind.IdentityEnrollmentTokenCreated: {class: classAccountChange, activity: activityOther, activityName: "Other"},
	auditkind.IdentityInstanceEnrolled:       {class: classAccountChange, activity: activityCreate, activityName: "Create"},
	auditkind.IdentityInstanceAdmitted:       {class: classAccountChange, activity: accountEnable, activityName: "Enable"},
	auditkind.IdentityInstanceAutoAdmitted:   {class: classAccountChange, activity: accountEnable, activityName: "Enable"},
	auditkind.IdentityInstanceRejected:       {class: classAccountChange, activity: accountDisable, activityName: "Disable"},
	auditkind.IdentityInstanceRevoked:        {class: classAccountChange, activity: accountDelete, activityName: "Delete"},

	auditkind.IdaccessTokenIssued:            {class: classAuthentication, activity: authnTicket, activityName: "Authentication Ticket"},
	auditkind.IdaccessCodeReuse:              {class: classAuthentication, activity: activityOther, activityName: "Other", refused: true},
	auditkind.IdaccessRefreshReuse:           {class: classAuthentication, activity: activityOther, activityName: "Other", refused: true},
	auditkind.SecurityEnrollmentTokenReused:  {class: classAuthentication, activity: activityOther, activityName: "Other", refused: true},
	auditkind.IdentityWorkloadDiscovered:     {class: classAuthentication, activity: activityOther, activityName: "Other", refused: true},
	auditkind.SecurityWorkloadProofRefused:   {class: classAuthentication, activity: activityOther, activityName: "Other", refused: true},
	auditkind.SecurityInstanceNetworkChanged: {class: classAuthentication, activity: activityOther, activityName: "Other"},

	auditkind.IdentityIssuerProposed:        {class: classEntityMgmt, activity: entityCreate, activityName: "Create", entity: "trusted_issuer"},
	auditkind.IdentityIssuerActivated:       {class: classEntityMgmt, activity: entityActivate, activityName: "Activate", entity: "trusted_issuer"},
	auditkind.IdentityIssuerNarrowed:        {class: classEntityMgmt, activity: entityUpdate, activityName: "Update", entity: "trusted_issuer"},
	auditkind.IdentityIssuerDisabled:        {class: classEntityMgmt, activity: entityDisable, activityName: "Disable", entity: "trusted_issuer"},
	auditkind.IdentityIssuerWithdrawn:       {class: classEntityMgmt, activity: entityDelete, activityName: "Delete", entity: "trusted_issuer"},
	auditkind.IdentityProviderCreated:       {class: classEntityMgmt, activity: entityCreate, activityName: "Create", entity: "identity_provider"},
	auditkind.IdentityProviderActivated:     {class: classEntityMgmt, activity: entityActivate, activityName: "Activate", entity: "identity_provider"},
	auditkind.IdentityProviderDisabled:      {class: classEntityMgmt, activity: entityDisable, activityName: "Disable", entity: "identity_provider"},
	auditkind.IdentityProviderLapsed:        {class: classEntityMgmt, activity: entityDeactivate, activityName: "Deactivate", entity: "identity_provider"},
	auditkind.IdentityProviderOwnOnlySet:    {class: classEntityMgmt, activity: entityUpdate, activityName: "Update", entity: "identity_provider"},
	auditkind.IdaccessIssuerDisabled:        {class: classEntityMgmt, activity: entityDisable, activityName: "Disable", entity: "assertion_issuer"},
	auditkind.IdaccessClientDocumentChanged: {class: classEntityMgmt, activity: entityUpdate, activityName: "Update", entity: "oauth_client"},
	auditkind.IdaccessClientRemoved:         {class: classEntityMgmt, activity: entityDelete, activityName: "Delete", entity: "oauth_client"},
	auditkind.IdaccessMcpClientRemoved:      {class: classEntityMgmt, activity: entityDelete, activityName: "Delete", entity: "mcp_client"},
	auditkind.IdaccessMcpAccessDisabled:     {class: classEntityMgmt, activity: entityDisable, activityName: "Disable", entity: "mcp_access"},
	auditkind.IdaccessConsentGiven:          {class: classEntityMgmt, activity: entityCreate, activityName: "Create", entity: "consent"},
	auditkind.IdaccessLapsed:                {class: classEntityMgmt, activity: entityDeactivate, activityName: "Deactivate", entity: "idp_access"},
	// A gateway's kubernetes binding is the TokenReview trust its replicas
	// enrol by (G0 M32 D968; D1206 M32-1).
	auditkind.GatewayKubernetesBindingSet:     {class: classEntityMgmt, activity: entityCreate, activityName: "Create", entity: "kubernetes_binding"},
	auditkind.GatewayKubernetesBindingCleared: {class: classEntityMgmt, activity: entityDelete, activityName: "Delete", entity: "kubernetes_binding"},
}

func isAgentIdentity(kind string) bool {
	_, ok := agentIdentityKinds[strings.TrimPrefix(kind, "audit.")]
	return ok
}

// mapAgentIdentity maps an audit entry of agent identity protection.
func mapAgentIdentity(r *Record, e Event) {
	m := agentIdentityKinds[strings.TrimPrefix(e.Kind, "audit.")]
	r.ClassUID, r.CategoryUID, r.CategoryName = m.class, categoryIAM, "Identity & Access Management"
	r.ActivityID, r.ActivityName = m.activity, m.activityName
	r.StatusID, r.Status = statusOf(e.Outcome)
	if m.refused {
		r.StatusID, r.Status = statusFailure, "Failure"
	}
	switch m.class {
	case classAccountChange:
		r.ClassName, r.User = "Account Change", identityUser(e)
	case classAuthentication:
		r.ClassName, r.User = "Authentication", identityUser(e)
	default:
		r.ClassName = "Entity Management"
		r.Entity = &Entity{UID: nonEmpty(e.Attrs["object_id"], "unknown"), Type: m.entity, TypeID: 99}
	}
	r.Message = e.Kind
}

// identityUser is whose identity the entry is about: the agent instance,
// else the agent, else the person or service account.
func identityUser(e Event) *User {
	for _, t := range []reflexdomain.SubjectType{reflexdomain.SubjectInstance, reflexdomain.SubjectAgent} {
		if id, ok := e.Subject(t); ok {
			return userOf(string(t), id)
		}
	}
	return subjectUser(e)
}

// subjectUser is the person or service account the entry is about.
func subjectUser(e Event) *User {
	for _, s := range e.Subjects {
		if s.Type == reflexdomain.SubjectUser || s.Type == reflexdomain.SubjectServiceAccount {
			return userOf(string(s.Type), s.ID)
		}
	}
	return &User{UID: "unknown", TypeID: 0}
}

func mapAudit(r *Record, e Event) {
	r.ClassUID, r.ClassName, r.CategoryUID, r.CategoryName = classAPIActivity, "API Activity", categoryApplication, "Application Activity"
	r.ActivityID, r.ActivityName = auditActivity(e.Kind)
	r.API = &API{Operation: e.Kind, Service: Service{Name: Product}}
	r.SrcEndpoint = &Endpoint{Name: e.ActorType, Zone: e.Environment}
	r.StatusID, r.Status = statusOf(e.Outcome)
	r.Message = e.Kind
}

// accountKinds are the audit kinds about a person's or service account's
// account, its keys, roles or second factors (Account Change).
var accountKinds = []string{
	"audit.access.user_", "audit.access.service_account_", "audit.access.role_", "audit.access.api_key_", "audit.authn.webauthn_",
}

// authnKinds are the audit kinds about signing in, sessions and tokens
// (Authentication).
var authnKinds = []string{"audit.authn.login", "audit.authn.session", "audit.authn.step_up", "audit.authn.token_issued"}

func hasAnyPrefix(kind string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(kind, p) {
			return true
		}
	}
	return false
}

// accountActivity reads the verb ending an account kind
// ("audit.access.user_disabled"). A key is not the account: adding or
// revoking one is Other.
func accountActivity(kind string) (int, string) {
	verb := kind[strings.LastIndexByte(kind, '_')+1:]
	switch {
	case strings.HasPrefix(kind, "audit.authn.webauthn_"):
		switch verb {
		case "registered":
			return accountMFAEnable, "MFA Factor Enable"
		case "removed", "suspended":
			return accountMFADisable, "MFA Factor Disable"
		}
		return activityOther, "Other"
	case strings.Contains(kind, "key_"):
		return activityOther, "Other"
	}
	switch verb {
	case "created":
		return activityCreate, "Create"
	case "enabled":
		return accountEnable, "Enable"
	case "disabled":
		return accountDisable, "Disable"
	case "bound":
		return accountAttach, "Attach Policy"
	case "unbound":
		return accountDetach, "Detach Policy"
	}
	return activityOther, "Other"
}

func authnActivity(kind string) (int, string) {
	switch strings.TrimPrefix(kind, "audit.") {
	case auditkind.AuthnLogin, auditkind.AuthnSessionCreated, auditkind.AuthnStepUp:
		return authnLogon, "Logon"
	case auditkind.AuthnSessionEnded, auditkind.AuthnSessionRevoked, auditkind.AuthnSessionsRevoked:
		return authnLogoff, "Logoff"
	case auditkind.AuthnTokenIssued:
		return authnTicket, "Authentication Ticket"
	}
	return activityOther, "Other"
}

func auditActivity(kind string) (int, string) {
	verb := kind[strings.LastIndexByte(kind, '.')+1:]
	switch {
	case strings.HasSuffix(verb, "created"), strings.HasSuffix(verb, "added"), strings.HasSuffix(verb, "published"):
		return activityCreate, "Create"
	case strings.HasSuffix(verb, "deleted"), strings.HasSuffix(verb, "removed"), strings.HasSuffix(verb, "revoked"):
		return activityDelete, "Delete"
	case strings.HasSuffix(verb, "read"), strings.HasSuffix(verb, "exported"), strings.HasSuffix(verb, "viewed"):
		return activityRead, "Read"
	case strings.HasSuffix(verb, "updated"), strings.HasSuffix(verb, "changed"), strings.HasSuffix(verb, "activated"),
		strings.HasSuffix(verb, "rotated"), strings.HasSuffix(verb, "paused"), strings.HasSuffix(verb, "resumed"):
		return activityUpdate, "Update"
	}
	return activityOther, "Other"
}

// apiActivity reads the verb of a PantherClaw operation ("github.repo.read",
// "files.delete"). An operation with no known verb is Other.
func apiActivity(op string) (int, string) {
	verb := op[strings.LastIndexByte(op, '.')+1:]
	switch verb {
	case "create", "add", "open", "push", "write", "post", "send", "upload":
		return activityCreate, "Create"
	case "read", "get", "list", "search", "fetch", "download", "view":
		return activityRead, "Read"
	case "update", "edit", "patch", "merge", "set", "move", "rename":
		return activityUpdate, "Update"
	case "delete", "remove", "close", "destroy", "purge":
		return activityDelete, "Delete"
	}
	return activityOther, "Other"
}

func decisionStatus(d string) (int, string) {
	switch d {
	case "ALLOW":
		return statusSuccess, "Success"
	case "DENY", "CANNOT_AUTHORIZE":
		return statusFailure, "Failure"
	case "":
		return statusUnknown, "Unknown"
	}
	return statusOther, d
}

func statusOf(outcome string) (int, string) {
	switch strings.ToUpper(outcome) {
	case "":
		return statusUnknown, "Unknown"
	case "SUCCESS", "OK", "SUCCEEDED", "CONFIRMED":
		return statusSuccess, "Success"
	case "FAILURE", "FAILED", "ERROR", "REFUSED":
		return statusFailure, "Failure"
	}
	return statusOther, outcome
}

func severityOf(s string) (int, string) {
	switch strings.ToUpper(s) {
	case "LOW":
		return severityLow, "Low"
	case "MEDIUM":
		return severityMedium, "Medium"
	case "HIGH":
		return severityHigh, "High"
	case "CRITICAL":
		return severityCritical, "Critical"
	}
	return severityUnknown, "Unknown"
}

func findingActivity(state string) (activity int, activityName string, status int, statusName string) {
	switch state {
	case "ACKNOWLEDGED":
		return findingUpdate, "Update", findingStatusInProg, "In Progress"
	case "SUPPRESSED":
		return findingUpdate, "Update", findingStatusSupp, "Suppressed"
	case "RESOLVED":
		return findingClose, "Close", findingStatusResolve, "Resolved"
	}
	return activityCreate, "Create", findingStatusNew, "New"
}

func incidentActivity(state string) (activity int, activityName string, status int, statusName string) {
	switch state {
	case "CONTAINED":
		return findingUpdate, "Update", findingStatusInProg, "In Progress"
	case "RESOLVED":
		return findingClose, "Close", findingStatusResolve, "Resolved"
	case "CLOSED":
		return findingClose, "Close", incidentStatusClosed, "Closed"
	}
	return activityCreate, "Create", findingStatusNew, "New"
}

func findingInfo(e Event) *FindingInfo {
	f := &FindingInfo{UID: findingUID(e), Title: e.Attrs[AttrTitle], Desc: e.Attrs[AttrSummary], Types: splitList(e.Attrs[AttrOWASP])}
	if id := e.Attrs[AttrRuleID]; id != "" {
		f.Analytic = &Analytic{UID: id, Name: id, Type: "Rule", TypeID: 1, Version: e.Attrs[AttrRuleVersion]}
	}
	// The full technique lists, never the atlas/attack attributes, which
	// may be cut to fit (G0 M28 D718b, HR-684).
	for _, t := range e.ATLAS {
		f.Attacks = append(f.Attacks, attacksOf(t)...)
	}
	for _, t := range e.ATTACK {
		f.Attacks = append(f.Attacks, attacksOf(t)...)
	}
	return f
}

// attacksOf returns the OCSF attack objects of one technique id: one per
// tactic the catalog gives it (G0 M28 D718). An id the catalog does not
// know keeps its uid alone, so a label is never dropped.
func attacksOf(id string) []Attack {
	fw, ok := catalog.FrameworkOf(id)
	if !ok {
		return []Attack{{Technique: &Technique{UID: id}}}
	}
	c := catalog.Load(fw)
	version := c.Version
	if fw == catalog.FrameworkATLAS {
		version = "ATLAS " + c.Version
	}
	t, ok := c.Technique(id)
	if !ok {
		return []Attack{{Technique: &Technique{UID: id}, Version: version}}
	}
	a := Attack{Technique: &Technique{UID: t.ID, Name: t.Name}, Version: version}
	tactics := t.Tactics
	if t.Parent != "" {
		a.SubTechnique = a.Technique
		a.Technique = &Technique{UID: t.Parent}
		if p, ok := c.Technique(t.Parent); ok {
			a.Technique.Name = p.Name
			if len(tactics) == 0 {
				tactics = p.Tactics
			}
		}
	}
	if len(tactics) == 0 {
		return []Attack{a}
	}
	out := make([]Attack, 0, len(tactics))
	for _, short := range tactics {
		x := a
		if tc, ok := c.Tactic(short); ok {
			x.Tactic = &Tactic{UID: tc.ID, Name: tc.Name}
		} else {
			x.Tactic = &Tactic{UID: short}
		}
		out = append(out, x)
	}
	return out
}

// splitList reads a comma-separated attribute.
func splitList(s string) []string {
	var out []string
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func actorOf(e Event) *Actor {
	if e.ActorType == "" && e.ActorID == "" {
		return nil
	}
	return &Actor{User: userOf(e.ActorType, e.ActorID)}
}

// userOf: OCSF user type_id 1 User, 3 System, 99 Other (agents).
func userOf(typ, id string) *User {
	u := &User{UID: nonEmpty(id, "unknown"), Type: typ}
	switch typ {
	case "user":
		u.TypeID, u.Type = 1, "User"
	case "service_account", "system":
		u.TypeID, u.Type = 3, "System"
	default:
		u.TypeID = 99
	}
	return u
}

func resourcesOf(subjects []reflexdomain.Subject) []Resource {
	out := make([]Resource, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, Resource{UID: s.ID, Type: string(s.Type)})
	}
	return out
}

func unmappedOf(e Event) *Unmapped {
	u := &Unmapped{
		Kind: e.Kind, Mode: e.Mode, Outcome: e.Outcome, Environment: e.Environment, DestinationClass: e.DestinationClass,
		Effect: e.Attrs[AttrEffect], Coverage: e.Attrs[AttrCoverage], Uncertainty: uncertainty(e),
	}
	for k, v := range e.Attrs {
		if mappedAttrs[k] {
			continue
		}
		if u.Attrs == nil {
			u.Attrs = map[string]string{}
		}
		u.Attrs[k] = v
	}
	return u
}

// uncertainty states how much of the event is known (F648): the basis
// of a finding, or a decision's mode when it is not enforced.
func uncertainty(e Event) string {
	if b := e.Attrs[AttrBasis]; b != "" {
		return b
	}
	switch e.Mode {
	case "", "ENFORCED", "ENFORCE":
		return ""
	}
	return "mode:" + e.Mode
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
