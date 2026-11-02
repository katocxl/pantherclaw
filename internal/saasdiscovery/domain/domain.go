// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain is SaaS agent discovery (N6, G0 M26 D407): which vendors it
// reads, the closed kinds of finding, and the only attributes each may carry.
// A finding is metadata about an agent someone built in a SaaS tenant. It is
// never a conversation, a prompt or an instruction (H3, F789, HR-635).
package domain

import (
	"crypto/sha256"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Sources are the SaaS vendors discovery reads (H4). Each is also a
// discovery's source.
const (
	SourceCopilotStudio     = "copilot_studio"
	SourceChatGPTEnterprise = "chatgpt_enterprise"
)

// Sources lists them.
var Sources = []string{SourceChatGPTEnterprise, SourceCopilotStudio}

// Kinds of finding, one to a source.
const (
	KindCopilotAgent = "copilot_studio_agent"
	KindCustomGPT    = "chatgpt_gpt"
)

// KindOf is the kind a source's findings are, "" for no source.
func KindOf(source string) string {
	switch source {
	case SourceCopilotStudio:
		return KindCopilotAgent
	case SourceChatGPTEnterprise:
		return KindCustomGPT
	}
	return ""
}

// OperationScan is the operation of a saas_scan lease.
const OperationScan = "saas.scan"

// Collector is what a connection needs to scan a source.
type Collector struct {
	Package, CredentialKind string
}

// CollectorOf is the source's collector. Copilot Studio reads Dataverse with
// an Entra application's client credentials, ChatGPT Enterprise with an
// admin key.
func CollectorOf(source string) (Collector, bool) {
	switch source {
	case SourceCopilotStudio:
		return Collector{Package: "pc.copilot-studio", CredentialKind: "oauth_client"}, true //nolint:gosec // G101: a credential kind's name, not a credential
	case SourceChatGPTEnterprise:
		return Collector{Package: "pc.chatgpt-enterprise", CredentialKind: "static"}, true
	}
	return Collector{}, false
}

// What a scan of each source reads. A report accounts for every one of them,
// read or not read: one it leaves out is "not reported", never "none found".
const (
	ReadBots          = "bots"
	ReadBotComponents = "bot_components"
	ReadGPTs          = "gpts"
	ReadGPTConfigs    = "gpt_configs"
)

// Reads are what a scan of source reads.
func Reads(source string) []string {
	switch source {
	case SourceCopilotStudio:
		return []string{ReadBotComponents, ReadBots}
	case SourceChatGPTEnterprise:
		return []string{ReadGPTConfigs, ReadGPTs}
	}
	return nil
}

// Notes are further reasons a report may give: the tenant could not be
// reached, a record was refused, or findings were not recorded.
const (
	NoteTenant   = "tenant"
	NoteRecords  = "records"
	NoteFindings = "findings"
)

// Notes lists them.
var Notes = []string{NoteFindings, NoteRecords, NoteTenant}

// Counts a report may give: how many agents it found, and how many records it
// kept whose side read it could not finish (each marked on its own,
// AttrUnread). Any other name is refused.
const (
	CountAgents        = "agents"
	CountRecordsUnread = "records_unread"
)

// CountNames lists them.
var CountNames = []string{CountAgents, CountRecordsUnread}

// CountsOK reports whether every count is one CountNames names, and none is
// negative.
func CountsOK(counts map[string]int64) bool {
	for k, v := range counts {
		if !slices.Contains(CountNames, k) || v < 0 {
			return false
		}
	}
	return true
}

// attributes are the only attributes each kind carries (HR-636). A value not
// listed here never leaves the parser, and the server drops it if it comes.
var attributes = map[string][]string{
	KindCopilotAgent: {
		"tenant", "agent_id", "name", "schema_name", "state", "status", "auth_mode", "auth_trigger", "access_policy",
		"published_at", "created_at", "modified_at", "owner_ref", "skills", "skill_count", "knowledge_count",
	},
	KindCustomGPT: {
		"tenant", "agent_id", "name", "visibility", "created_at", "owner_ref", "tool_kinds", "action_domains",
		"tools_incomplete",
	},
}

// AttrUnread is how a gateway's finding, which reaches the server ahead of
// its report, says which read it could not finish. It is no attribute: its
// value is one of the kind's side reads, and the server takes it off and
// records nothing of it.
const AttrUnread = "unread"

// sideReads are the reads behind a kind's material attributes other than the
// record itself.
var sideReads = map[string][]string{KindCopilotAgent: {ReadBotComponents}, KindCustomGPT: {ReadGPTConfigs}}

// materialKeys are the attributes that say what a discovered agent may do or
// who may reach it. A change of one is recorded and announced, and reopens a
// dismissed finding (HR-460).
var materialKeys = map[string][]string{
	KindCopilotAgent: {"state", "auth_mode", "auth_trigger", "access_policy", "skills", "skill_count", "knowledge_count"},
	KindCustomGPT:    {"visibility", "tool_kinds", "action_domains", "tools_incomplete"},
}

// MaterialKeys are the material attributes of kind.
func MaterialKeys(kind string) []string { return materialKeys[kind] }

// readOf names the read a material attribute comes from, where that is not
// the record itself: a report that did not finish it says nothing of them.
var readOf = map[string]string{
	"skills": ReadBotComponents, "skill_count": ReadBotComponents, "knowledge_count": ReadBotComponents,
	"tool_kinds": ReadGPTConfigs, "action_domains": ReadGPTConfigs, "tools_incomplete": ReadGPTConfigs,
}

// KeepsPrior reports whether a report that did not finish notScanned says
// nothing of key: what was recorded stands, so an unread read never reads as
// a change (HR-637).
func KeepsPrior(key string, notScanned map[string]string) bool {
	read, ok := readOf[key]
	if !ok {
		return false
	}
	_, unread := notScanned[read]
	return unread
}

// Attributes are the attributes kind may carry, ok false for no kind.
func Attributes(kind string) ([]string, bool) {
	a, ok := attributes[kind]
	return a, ok
}

// MaxValue is the longest attribute value, in bytes (the API's limit).
const MaxValue = 256

// Plain reports whether v is text a person can be shown as it is: valid
// UTF-8 of at most MaxValue bytes, with no control or format characters.
func Plain(v string) bool {
	if len(v) > MaxValue || !utf8.ValidString(v) {
		return false
	}
	return !strings.ContainsFunc(v, unsafeRune)
}

func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029
}

// Clean is what the server keeps of a finding's attributes: those its kind
// names, with plain values. It returns how many it dropped. An unknown kind
// keeps nothing.
func Clean(kind string, attrs map[string]string) (map[string]string, int) {
	names := attributes[kind]
	kept, dropped := make(map[string]string, len(attrs)), 0
	for k, v := range attrs {
		if k == AttrUnread && slices.Contains(sideReads[kind], v) {
			kept[k] = v // a mark of the server's, never recorded
			continue
		}
		if slices.Contains(names, k) && Plain(v) {
			kept[k] = v
		} else {
			dropped++
		}
	}
	return kept, dropped
}

// Text is untrusted vendor text made fit to keep: its control and format
// characters go, and it is cut to MaxValue bytes on a character boundary.
func Text(s string) string {
	s = strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	s = strings.TrimSpace(s)
	if len(s) <= MaxValue {
		return s
	}
	cut := MaxValue
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut])
}

var tenantRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// TenantOK reports whether t can name a tenant: the Dataverse organization or
// the ChatGPT workspace a report covers.
func TenantOK(t string) bool { return tenantRe.MatchString(t) }

// Finding is one agent found: a kind, a key stable across imports and scans,
// and untrusted attributes.
type Finding struct {
	Kind       string
	Key        [32]byte
	Attributes map[string]string
}

// Key is a finding's key: one vendor record of one tenant, however it was
// read, so an import and a scan of it are one discovery.
func Key(source, tenant, id string) [32]byte {
	h := sha256.New()
	h.Write([]byte("pantherclaw saas key v1\x00"))
	for _, s := range []string{source, tenant, id} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return [32]byte(h.Sum(nil))
}

// Report is what one import or scan found and how far it got.
type Report struct {
	Source, Tenant string
	Findings       []Finding
	Counts         map[string]int64
	Scanned        []string
	NotScanned     map[string]string
}

// notRead is what a read says until it is read.
const notRead = "not read"

// NewReport starts a report that has read nothing: every read is not
// scanned until Read marks it, so what a parser never reaches stays
// "not scanned".
func NewReport(source, tenant string) *Report {
	r := &Report{Source: source, Tenant: tenant, Counts: map[string]int64{}, NotScanned: map[string]string{}}
	for _, s := range Reads(source) {
		r.NotScanned[s] = notRead
	}
	return r
}

// Read marks read as read in full.
func (r *Report) Read(read string) {
	delete(r.NotScanned, read)
	if !slices.Contains(r.Scanned, read) {
		r.Scanned = append(r.Scanned, read)
		slices.Sort(r.Scanned)
	}
}

// Note says why a read or note is not complete; a read loses its scanned
// mark. Notes on one name add up.
func (r *Report) Note(name, why string) {
	r.Scanned = slices.DeleteFunc(r.Scanned, func(s string) bool { return s == name })
	if had := r.NotScanned[name]; had != "" && had != notRead && had != why {
		why = had + "; " + why
	}
	r.NotScanned[name] = why
}

// MarkUnread marks each finding with the read behind its material attributes
// when the report did not finish that read for every record (AttrUnread).
// A record a parser could not read is already marked on its own, and only it:
// one bad record never hides another's change (HR-637).
func (r *Report) MarkUnread() {
	for i := range r.Findings {
		f := &r.Findings[i]
		for _, read := range sideReads[f.Kind] {
			if _, unread := r.NotScanned[read]; unread {
				f.Attributes[AttrUnread] = read
			}
		}
	}
}

// Complete reports whether nothing was left unread.
func (r *Report) Complete() bool { return len(r.NotScanned) == 0 }

// Fields is the report as a gateway reports it: /counts/<name>,
// /scanned/<read> and /not_scanned/<name>.
func (r *Report) Fields() map[string]string {
	out := make(map[string]string, len(r.Counts)+len(r.Scanned)+len(r.NotScanned))
	for k, v := range r.Counts {
		out["/counts/"+k] = strconv.FormatInt(v, 10)
	}
	for _, s := range r.Scanned {
		out["/scanned/"+s] = "true"
	}
	for k, v := range r.NotScanned {
		out["/not_scanned/"+k] = v
	}
	return out
}
