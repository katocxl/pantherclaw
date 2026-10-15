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
// other audit → API Activity (6003); everything else → Base Event (0).
// Each event carries its actor, the decision and reason, the policy
// version, effects, coverage and uncertainty when the feed has them, and
// never a payload or a secret: the feed carries none (D2).
package ocsf

import (
	"strings"
	"time"
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

// Subject is a feed subject (reflexdomain.Subject, D1).
type Subject struct {
	Type string
	ID   string
}

// Event is one evidence feed event with the fields of the D2 contract
// (reflex/feed.Event).
type Event struct {
	Seq              int64
	ID               string
	Org              string
	Kind             string
	OccurredAt       time.Time
	ActorType        string
	ActorID          string
	Subjects         []Subject
	Decision         string
	Reason           string
	Operation        string
	Mode             string
	Outcome          string
	Environment      string
	DestinationClass string
	Test             bool
	Attrs            map[string]string
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

// Attack is the OCSF attack object; PantherClaw puts MITRE ATLAS
// techniques in it.
type Attack struct {
	Technique Technique `json:"technique"`
	Version   string    `json:"version,omitzero"`
}

// Technique is the OCSF technique object.
type Technique struct {
	UID string `json:"uid"`
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
	AttrRuleID        = "rule_id"
	AttrRuleVersion   = "rule_version"
	AttrRuleDigest    = "rule_digest"
	AttrTitle         = "title"
	AttrSummary       = "summary"
	AttrSeverity      = "severity"
	AttrState         = "state"
	AttrBasis         = "basis"
	AttrEffect        = "effect"
	AttrCoverage      = "coverage"
	AttrATLAS         = "atlas"
	AttrOWASP         = "owasp"
)

// mappedAttrs are attributes placed in OCSF members; the rest go to
// unmapped.pantherclaw_attrs.
var mappedAttrs = map[string]bool{
	AttrPolicyVersion: true, AttrRuleID: true, AttrRuleVersion: true, AttrTitle: true, AttrSummary: true,
	AttrSeverity: true, AttrState: true, AttrBasis: true, AttrEffect: true, AttrCoverage: true, AttrATLAS: true,
	AttrOWASP: true,
}

// Map returns the OCSF record of e. productVersion is PantherClaw's
// version (may be empty).
func Map(e Event, productVersion string) Record {
	r := Record{
		Time:       e.OccurredAt.UTC().UnixMilli(),
		SeverityID: severityInfo,
		Severity:   "Informational",
		Metadata: Metadata{
			Version: Version, UID: e.ID, Sequence: e.Seq, EventCode: e.Kind, TenantUID: e.Org,
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
	case class == ClassAudit && accountChange(e.Kind):
		mapAccountChange(&r, e)
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
	r.ActivityID, r.ActivityName, r.StatusID, r.Status = findingActivity(e.Attrs[AttrState])
	r.SeverityID, r.Severity = severityOf(e.Attrs[AttrSeverity])
	r.FindingInfo = findingInfo(e)
	r.Message = e.Attrs[AttrTitle]
}

func mapIncident(r *Record, e Event) {
	r.ClassUID, r.ClassName, r.CategoryUID, r.CategoryName = classIncident, "Incident Finding", categoryFindings, "Findings"
	r.ActivityID, r.ActivityName, r.StatusID, r.Status = incidentActivity(e.Attrs[AttrState])
	r.SeverityID, r.Severity = severityOf(e.Attrs[AttrSeverity])
	r.FindingList = []FindingInfo{*findingInfo(e)}
	r.Message = e.Attrs[AttrTitle]
}

func mapAccountChange(r *Record, e Event) {
	r.ClassUID, r.ClassName, r.CategoryUID, r.CategoryName = classAccountChange, "Account Change", categoryIAM, "Identity & Access Management"
	r.ActivityID, r.ActivityName = accountActivity(e.Kind)
	r.StatusID, r.Status = statusOf(e.Outcome)
	for _, s := range e.Subjects {
		if s.Type == "user" || s.Type == "service_account" {
			r.User = userOf(s.Type, s.ID)
			break
		}
	}
	if r.User == nil {
		r.User = &User{UID: "unknown", TypeID: 0}
	}
	r.Message = e.Kind
}

func mapAudit(r *Record, e Event) {
	r.ClassUID, r.ClassName, r.CategoryUID, r.CategoryName = classAPIActivity, "API Activity", categoryApplication, "Application Activity"
	r.ActivityID, r.ActivityName = auditActivity(e.Kind)
	r.API = &API{Operation: e.Kind, Service: Service{Name: Product}}
	r.SrcEndpoint = &Endpoint{Name: e.ActorType, Zone: e.Environment}
	r.StatusID, r.Status = statusOf(e.Outcome)
	r.Message = e.Kind
}

// accountChange: audit kinds about a person's or service account's
// account, its keys, roles or sessions.
func accountChange(kind string) bool {
	for _, p := range []string{"audit.user.", "audit.service_account.", "audit.role.", "audit.webauthn.", "audit.session."} {
		if strings.HasPrefix(kind, p) {
			return true
		}
	}
	return false
}

func accountActivity(kind string) (int, string) {
	verb := kind[strings.LastIndexByte(kind, '.')+1:]
	switch verb {
	case "created", "invited", "added", "registered":
		return activityCreate, "Create"
	case "enabled", "restored", "reactivated":
		return accountEnable, "Enable"
	case "disabled", "suspended", "revoked":
		return accountDisable, "Disable"
	case "deleted", "removed":
		return accountDelete, "Delete"
	case "bound", "granted":
		return accountAttach, "Attach Policy"
	case "unbound":
		return accountDetach, "Detach Policy"
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
	f := &FindingInfo{UID: e.ID, Title: e.Attrs[AttrTitle], Desc: e.Attrs[AttrSummary], Types: splitList(e.Attrs[AttrOWASP])}
	if id := e.Attrs[AttrRuleID]; id != "" {
		f.Analytic = &Analytic{UID: id, Name: id, Type: "Rule", TypeID: 1, Version: e.Attrs[AttrRuleVersion]}
	}
	for _, t := range splitList(e.Attrs[AttrATLAS]) {
		f.Attacks = append(f.Attacks, Attack{Technique: Technique{UID: t}, Version: "ATLAS"})
	}
	return f
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

func resourcesOf(subjects []Subject) []Resource {
	out := make([]Resource, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, Resource{UID: s.ID, Type: s.Type})
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
