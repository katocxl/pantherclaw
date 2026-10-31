// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the PantherClaw Hub format (G0 M23 D100, HR-563) and
// its verification (D101, HR-560).
//
// Hub is a static directory: index.jws plus items/<sha256>.json. There are no
// archives. The index is a compact JWS listing, for each item, its name,
// version, kind, and the SHA-256 and size of its exact bytes. An item holds a
// closed kind of data under strict decoding: no kind runs code, and a member
// no kind defines is refused.
package domain

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

const (
	// IndexSpec names the index format.
	IndexSpec = "pantherclaw.hub.index/1"
	// ItemSpec names the item format.
	ItemSpec = "pantherclaw.hub.item/1"
	// MaxItemBytes bounds one item file.
	MaxItemBytes = 1 << 20
	// MaxItems bounds one index.
	MaxItems = 1000
	// MaxIndexBytes bounds the signed index file.
	MaxIndexBytes = 2 << 20
	// MaxValidity bounds how long an index stays valid.
	MaxValidity = 180 * 24 * time.Hour
	// MaxNameBytes bounds an item name.
	MaxNameBytes = 128
	// MaxTitleBytes bounds an entry's title.
	MaxTitleBytes = 120
	// MaxSummaryBytes bounds an entry's summary.
	MaxSummaryBytes = 500
)

// Kind is a closed list of what an item can be (HR-563).
type Kind string

// The kinds.
const (
	KindPolicyTemplate Kind = "policy_template"
	KindDetectionRule  Kind = "detection_rule"
	KindRangeScenario  Kind = "range_scenario"
	KindToolPackage    Kind = "tool_package"
	KindAutomation     Kind = "automation"
)

// Kinds lists every kind.
func Kinds() []Kind {
	return []Kind{KindPolicyTemplate, KindDetectionRule, KindRangeScenario, KindToolPackage, KindAutomation}
}

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { return slices.Contains(Kinds(), k) }

var (
	namePattern = regexp.MustCompile(`^pc\.[a-z0-9-]+(\.[a-z0-9-]+)*$`)
	hexDigest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// A scenario file is one plain name, so a signed item cannot write
	// outside the directory it is installed into.
	scenarioFile = regexp.MustCompile(`^CX-[0-9]+(-[a-z0-9-]+)?\.yaml$`)
)

// ValidName reports whether s is an item name.
func ValidName(s string) bool { return len(s) <= MaxNameBytes && namePattern.MatchString(s) }

// ValidScenarioFile reports whether s is a customer-authored scenario file
// name.
func ValidScenarioFile(s string) bool { return scenarioFile.MatchString(s) }

// Entry lists one item in the index.
type Entry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kind    Kind   `json:"kind"`
	// SHA256 and Size describe the exact bytes of items/<sha256>.json.
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

// Index is the payload of index.jws.
type Index struct {
	Spec string `json:"spec"`
	// Version rises with every index published.
	Version   uint64  `json:"version"`
	IssuedAt  string  `json:"issued_at"`
	ExpiresAt string  `json:"expires_at"`
	Items     []Entry `json:"items"`
}

// Item is one items/<sha256>.json file.
type Item struct {
	Spec    string `json:"spec"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Kind    Kind   `json:"kind"`
	// Body is the kind's own document: PolicyTemplateBody, DetectionRuleBody,
	// RangeScenarioBody, ToolPackageBody or AutomationBody.
	Body jsontext.Value `json:"body"`
}

// PlaceholderSpec declares one policy template placeholder: the same
// declaration a template's template.json makes (G0 M8 C4).
type PlaceholderSpec struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
}

// PolicyTemplateBody is a policy_template's body: rules and scenario tests
// in the form of a template's policy.json and tests.json, with "per" and
// {{placeholders}}, rendered with the template renderer.
type PolicyTemplateBody struct {
	Placeholders map[string]PlaceholderSpec `json:"placeholders,omitzero"`
	Rules        []map[string]any           `json:"rules"`
	Tests        []map[string]any           `json:"tests,omitzero"`
}

// DetectionRuleBody is a detection_rule's body. Content is the custom rule
// document CreateCustomRule takes, whose id starts with "org.".
type DetectionRuleBody struct {
	Content string `json:"content"`
}

// RangeScenarioBody is a range_scenario's body. FileName and Scenario are a
// customer-authored scenario file (CX-…-….yaml) and its exact YAML; pclaw
// writes it locally, and no server installs it.
type RangeScenarioBody struct {
	FileName string `json:"file_name"`
	Scenario string `json:"scenario"`
}

// ToolPackageBody is a tool_package's body. PackageYAML is the exact package
// file and TargetsJWS the targets document signed for it, as ImportPackage
// takes them. The package root's signature is checked as for any import.
type ToolPackageBody struct {
	PackageYAML string `json:"package_yaml"`
	TargetsJWS  string `json:"targets_jws"`
}

// AutomationBody is an automation's body: the name and purpose of a DRAFT
// automation and its first definition, as CreateAutomation and
// CreateDraftVersion take them.
type AutomationBody struct {
	AutomationName string `json:"automation_name"`
	Purpose        string `json:"purpose"`
	// WorkKind is AGENT_WORK or SECURITY_WORK.
	WorkKind string `json:"work_kind"`
	// Definition is the automation definition, YAML.
	Definition string `json:"definition"`
}

// ErrItem reports an item that does not meet the format.
var ErrItem = errors.New("hub: invalid item")

func itemErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrItem}, args...)...)
}

// plainText reports whether s is valid UTF-8 without control, format or bidi
// characters: titles and summaries reach terminals and the console as they
// are, so an index cannot restyle or reorder what a person reads (T-242).
func plainText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r) {
			return false
		}
	}
	return true
}

func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil && strings.HasSuffix(s, "Z")
}

// checkEntry checks one index entry.
func (e Entry) check() error {
	key := e.Name + "@" + e.Version
	switch {
	case !ValidName(e.Name) || !actionir.ValidVersion(e.Version):
		return fmt.Errorf("entry %q is not name@version", key)
	case !e.Kind.Valid():
		return fmt.Errorf("entry %s has unknown kind %q", key, e.Kind)
	case !hexDigest.MatchString(e.SHA256):
		return fmt.Errorf("entry %s has no sha256", key)
	case e.Size < 1 || e.Size > MaxItemBytes:
		return fmt.Errorf("entry %s has size %d, want 1..%d", key, e.Size, MaxItemBytes)
	case e.Title == "" || len(e.Title) > MaxTitleBytes || !plainText(e.Title):
		return fmt.Errorf("entry %s needs a plain title of at most %d bytes", key, MaxTitleBytes)
	case len(e.Summary) > MaxSummaryBytes || !plainText(e.Summary):
		return fmt.Errorf("entry %s needs a plain summary of at most %d bytes", key, MaxSummaryBytes)
	}
	return nil
}

// Validate checks an index's shape and returns its expiry.
func (x Index) Validate() (time.Time, error) {
	if x.Spec != IndexSpec || x.Version < 1 || x.Version > 1<<63-1 {
		return time.Time{}, fmt.Errorf("not a %s index with a version from 1 to 2^63-1", IndexSpec)
	}
	issued, ok := parseTime(x.IssuedAt)
	if !ok {
		return time.Time{}, errors.New("issued_at must be an RFC 3339 UTC time")
	}
	expires, ok := parseTime(x.ExpiresAt)
	if !ok {
		return time.Time{}, errors.New("expires_at must be an RFC 3339 UTC time")
	}
	if !expires.After(issued) || expires.Sub(issued) > MaxValidity {
		return time.Time{}, errors.New("expires_at must be after issued_at, by at most 180 days")
	}
	if len(x.Items) > MaxItems {
		return time.Time{}, fmt.Errorf("at most %d items", MaxItems)
	}
	seen := make(map[string]bool, len(x.Items))
	for _, e := range x.Items {
		if err := e.check(); err != nil {
			return time.Time{}, err
		}
		key := e.Name + "@" + e.Version
		if seen[key] {
			return time.Time{}, fmt.Errorf("entry %s is listed twice", key)
		}
		seen[key] = true
	}
	return expires, nil
}

// DecodeItem strictly decodes an item file and checks its body against its
// kind: unknown members, unknown kinds and oversized files are refused.
func DecodeItem(raw []byte) (Item, error) {
	var it Item
	if len(raw) == 0 || len(raw) > MaxItemBytes {
		return it, itemErr("an item is 1..%d bytes", MaxItemBytes)
	}
	if err := json.Unmarshal(raw, &it, json.RejectUnknownMembers(true)); err != nil {
		return Item{}, itemErr("%v", err)
	}
	switch {
	case it.Spec != ItemSpec:
		return Item{}, itemErr("spec %q, want %s", it.Spec, ItemSpec)
	case !ValidName(it.Name) || !actionir.ValidVersion(it.Version):
		return Item{}, itemErr("%q is not name@version", it.Name+"@"+it.Version)
	case !it.Kind.Valid():
		return Item{}, itemErr("unknown kind %q", it.Kind)
	}
	if _, err := it.DecodeBody(); err != nil {
		return Item{}, err
	}
	return it, nil
}

func body[T any](raw jsontext.Value) (T, error) {
	var out T
	if err := json.Unmarshal(raw, &out, json.RejectUnknownMembers(true)); err != nil {
		return out, itemErr("body: %v", err)
	}
	return out, nil
}

// DecodeBody strictly decodes the item's body to its kind's type and checks
// that the fields the kind needs are there.
func (it Item) DecodeBody() (any, error) {
	switch it.Kind {
	case KindPolicyTemplate:
		b, err := body[PolicyTemplateBody](it.Body)
		if err != nil {
			return nil, err
		}
		if len(b.Rules) == 0 {
			return nil, itemErr("a policy template needs a rule")
		}
		return b, nil
	case KindDetectionRule:
		b, err := body[DetectionRuleBody](it.Body)
		if err != nil {
			return nil, err
		}
		if b.Content == "" {
			return nil, itemErr("a detection rule needs its content")
		}
		return b, nil
	case KindRangeScenario:
		b, err := body[RangeScenarioBody](it.Body)
		if err != nil {
			return nil, err
		}
		if !ValidScenarioFile(b.FileName) {
			return nil, itemErr("%q is not a CX-….yaml scenario file name", b.FileName)
		}
		if b.Scenario == "" {
			return nil, itemErr("a range scenario needs its scenario")
		}
		return b, nil
	case KindToolPackage:
		b, err := body[ToolPackageBody](it.Body)
		if err != nil {
			return nil, err
		}
		if b.PackageYAML == "" || b.TargetsJWS == "" {
			return nil, itemErr("a tool package needs package_yaml and targets_jws")
		}
		return b, nil
	case KindAutomation:
		b, err := body[AutomationBody](it.Body)
		if err != nil {
			return nil, err
		}
		if b.AutomationName == "" || b.Purpose == "" || b.WorkKind == "" || b.Definition == "" {
			return nil, itemErr("an automation needs automation_name, purpose, work_kind and definition")
		}
		return b, nil
	}
	return nil, itemErr("unknown kind %q", it.Kind)
}
