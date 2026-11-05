// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package format

import (
	"encoding/json/v2"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/openapi"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	factsdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// decodeItem decodes it.Data strictly as its kind (D1080) and checks the
// item's name against what the data declares.
func decodeItem(it *Item, publisher string) error {
	switch it.Kind {
	case KindToolPackage:
		p, err := manifest.Decode(it.Data)
		if err != nil {
			return fail(ErrItem, "%s: %v", it.Name, err)
		}
		if p.Name != it.Name {
			return fail(ErrNamespace, "%s: the package declares the name %q", it.Name, p.Name)
		}
		it.Package = p
	case KindOpenAPISpec:
		s, err := openapi.Parse(it.Data)
		if err != nil {
			return fail(ErrItem, "%s: %v", it.Name, err)
		}
		it.OpenAPI = s
	case KindDetectionRule:
		r, err := rules.Parse(it.Data)
		if err != nil {
			return fail(ErrItem, "%s: %v", it.Name, err)
		}
		if pub, ok := rules.ExtensionPublisher(r.ID); !ok || pub != publisher || r.ID != it.Name {
			return fail(ErrNamespace, "%s: the rule's id %q must be the item name", it.Name, r.ID)
		}
		if r.Basis.Confirmed() {
			return fail(ErrItem, "%s: a bundle rule's basis is at most INFERRED", it.Name)
		}
		it.Rule = r
	case KindPlaybook:
		if _, err := PlaybookAutomationName(it.Name); err != nil {
			return err
		}
		d, err := autodomain.Parse(it.Data)
		if err != nil {
			return fail(ErrItem, "%s: %v", it.Name, err)
		}
		it.Playbook = d
	case KindFactsDeclaration:
		f, err := DecodeFactsDeclaration(it.Data)
		if err != nil {
			return fail(ErrItem, "%s: %v", it.Name, err)
		}
		it.Facts = f
	case KindChannelTemplate:
		c, err := DecodeChannelTemplate(it.Data)
		if err != nil {
			return err
		}
		it.Channel = c
	default:
		return fail(ErrKind, "%q", it.Kind)
	}
	return nil
}

// PlaybookAutomationName is the automation name a playbook item drafts:
// its item name with dots and underscores as dashes, which must be a valid
// automation name (at most 52 characters).
func PlaybookAutomationName(item string) (string, error) {
	n := strings.NewReplacer(".", "-", "_", "-").Replace(item)
	if !autodomain.NamePattern.MatchString(n) || strings.Contains(n, "--") {
		return "", fail(ErrNamespace, "%s: a playbook's name, with dots as dashes, is an automation name of at most 52 characters", item)
	}
	return n, nil
}

// FactsDeclaration is a fact provider declaration (data only, no reader):
// what facts a provider of this publisher would write. Installing one
// records it as a template; a person registers a provider through the
// existing flow.
type FactsDeclaration struct {
	// Provider is the provider name, a lowercase dotted name.
	Provider string     `json:"provider"`
	Facts    []FactSpec `json:"facts"`
}

// FactSpec is one declared fact.
type FactSpec struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	SubjectType string `json:"subject_type"`
	// MaxLag is a Go duration, 1s..24h.
	MaxLag string `json:"max_lag"`
	// Kind is "value" (default) or "classification".
	Kind string `json:"kind,omitzero"`
}

// DecodeFactsDeclaration decodes a facts_declaration strictly and checks
// it with the fact provider rules.
func DecodeFactsDeclaration(raw []byte) (*FactsDeclaration, error) {
	doc, err := manifest.ToJSON(raw)
	if err != nil {
		return nil, err
	}
	var f FactsDeclaration
	if err := json.Unmarshal(doc, &f, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	p := factsdomain.Provider{
		ID: ids.NewV7(), Org: ids.New[ids.Org](), Name: f.Provider, ServiceAccountID: ids.NewV7(),
		State: factsdomain.ProviderActive,
	}
	for _, s := range f.Facts {
		lag, err := time.ParseDuration(s.MaxLag)
		if err != nil {
			return nil, fail(ErrItem, "fact %q: max_lag %q", s.Name, s.MaxLag)
		}
		p.Facts = append(p.Facts, factsdomain.Declaration{
			Name: s.Name, Type: factsdomain.Type(s.Type), SubjectType: s.SubjectType, MaxLag: lag, Kind: factsdomain.Kind(s.Kind),
		})
	}
	if err := p.Validate(nil); err != nil {
		return nil, err
	}
	return &f, nil
}

// ChannelTemplate is a notification channel template (D1080, HR-801): the
// channel kind, the events it subscribes to and non-secret settings. It
// never carries a secret: an admin creates the channel and its secrets
// through the existing flow.
type ChannelTemplate struct {
	Kind        string   `json:"kind"`
	Description string   `json:"description,omitzero"`
	EventTypes  []string `json:"event_types"`
	MinSeverity string   `json:"min_severity,omitzero"`
	// Settings are non-secret settings, shown to the admin as hints.
	Settings map[string]string `json:"settings,omitzero"`
}

// Template limits.
const (
	maxSettings     = 16
	maxSettingValue = 512
)

var (
	settingKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	// secretWords make a setting name secret-shaped.
	secretWords = []string{"token", "secret", "password", "passwd", "key", "credential", "auth", "cookie", "session",
		"signing", "private", "bearer", "webhook", "url", "dsn"}
	// secretValue matches values shaped like credentials: well-known token
	// prefixes, PEM blocks, JWTs and long base64 or hex runs.
	secretValue = regexp.MustCompile(`(?i)(xox[abposr]-|xapp-|ghp_|gho_|ghs_|github_pat_|glpat-|sk_live_|sk_test_|rk_live_|` +
		`AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|-----BEGIN|eyJ[A-Za-z0-9_-]{8,}\.|[A-Za-z0-9+/_-]{32,}|[0-9a-f]{32,})`)
)

// DecodeChannelTemplate decodes a channel_template strictly and refuses
// anything named or shaped like a secret.
func DecodeChannelTemplate(raw []byte) (*ChannelTemplate, error) {
	doc, err := manifest.ToJSON(raw)
	if err != nil {
		return nil, fail(ErrItem, "channel template: %v", err)
	}
	var c ChannelTemplate
	if err := json.Unmarshal(doc, &c, json.RejectUnknownMembers(true)); err != nil {
		return nil, fail(ErrItem, "channel template: %v", err)
	}
	switch {
	case !ndomain.Kind(c.Kind).Valid():
		return nil, fail(ErrItem, "channel template: unknown channel kind %q", c.Kind)
	case !plainText(c.Description, 500):
		return nil, fail(ErrItem, "channel template: description is at most 500 bytes of plain text")
	case ndomain.ValidEventTypes(c.EventTypes) != nil:
		return nil, fail(ErrItem, "channel template: event_types are 1..%d types or prefixes", ndomain.MaxEventTypes)
	case c.MinSeverity != "" && !ndomain.Severity(c.MinSeverity).Valid():
		return nil, fail(ErrItem, "channel template: min_severity %q", c.MinSeverity)
	case len(c.Settings) > maxSettings:
		return nil, fail(ErrItem, "channel template: at most %d settings", maxSettings)
	}
	if secretShaped(c.Description) {
		return nil, fail(ErrSecret, "the description looks like a secret")
	}
	for k, v := range c.Settings {
		if !settingKeyRe.MatchString(k) || !plainText(v, maxSettingValue) {
			return nil, fail(ErrItem, "channel template: setting %q", k)
		}
		if slices.ContainsFunc(secretWords, func(w string) bool { return strings.Contains(k, w) }) {
			return nil, fail(ErrSecret, "setting %q is named like a secret", k)
		}
		if secretShaped(v) {
			return nil, fail(ErrSecret, "setting %q looks like a secret or a URL", k)
		}
	}
	return &c, nil
}

// secretShaped reports a value that looks like a credential or carries a
// URL (a webhook URL is itself the secret of a Slack or Teams channel, and
// any URL may carry credentials in its user info or query).
func secretShaped(v string) bool {
	if secretValue.MatchString(v) {
		return true
	}
	for f := range strings.FieldsSeq(v) {
		if u, err := url.Parse(f); err == nil && (u.Scheme != "" || u.User != nil || u.RawQuery != "") && strings.Contains(f, ":") {
			return true
		}
	}
	return strings.Contains(v, "://")
}
