// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package manifest

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	pcjira "github.com/katocxl/pantherclaw/packages/pc-jira"
	pcslack "github.com/katocxl/pantherclaw/packages/pc-slack"
)

// slackCoverage is a valid coverage declaration for pc.slack.
const slackCoverage = `
coverage:
  environment:
    source: none
  record_scope: [slack_channel]
  recipient_fact: slack.channel.external
  channels: [http, mcp]
`

// TestHR523_ACoverageBlockIsValidatedAgainstThePackage: a coverage
// declaration may name only what the package declares: an environment param
// or fact it has, target types its definitions touch, a fact it reads, and
// channels its mappings use. Anything else refuses the whole package, and a
// package without the block is valid as before (G0 M20 D254, F756).
//
// Covers: F756
func TestHR523_ACoverageBlockIsValidatedAgainstThePackage(t *testing.T) {
	plain, err := Decode(pcslack.Package)
	if err != nil || plain.Coverage != nil {
		t.Fatalf("without coverage: %v %+v", err, plain.Coverage)
	}
	p, err := Decode(append(append([]byte(nil), pcslack.Package...), slackCoverage...))
	if err != nil {
		t.Fatal(err)
	}
	if c := p.Coverage; c == nil || c.Environment.Source != domain.EnvironmentNone || c.RecipientFact != "slack.channel.external" ||
		len(c.RecordScope) != 1 || len(c.Channels) != 2 {
		t.Fatalf("coverage: %+v", p.Coverage)
	}
	for name, block := range map[string]string{
		"unknown source":           strings.Replace(slackCoverage, "source: none", "source: guess", 1),
		"none with a param":        strings.Replace(slackCoverage, "source: none", "source: none\n    param: text", 1),
		"undeclared param":         strings.Replace(slackCoverage, "source: none", "source: param\n    param: environment", 1),
		"content param":            strings.Replace(slackCoverage, "source: none", "source: param\n    param: text", 1),
		"unread fact":              strings.Replace(slackCoverage, "source: none", "source: fact\n    fact: slack.channel.region", 1),
		"undeclared target type":   strings.Replace(slackCoverage, "[slack_channel]", "[slack_channel, slack_user]", 1),
		"connection target":        strings.Replace(slackCoverage, "[slack_channel]", "[pc.connection]", 1),
		"duplicate target type":    strings.Replace(slackCoverage, "[slack_channel]", "[slack_channel, slack_channel]", 1),
		"no record scope":          strings.Replace(slackCoverage, "[slack_channel]", "[]", 1),
		"unread recipient fact":    strings.Replace(slackCoverage, "slack.channel.external", "slack.channel.members", 1),
		"unmapped channel":         strings.Replace(slackCoverage, "[http, mcp]", "[http, mcp, hook]", 1),
		"unknown channel":          strings.Replace(slackCoverage, "[http, mcp]", "[http, email]", 1),
		"duplicate channel":        strings.Replace(slackCoverage, "[http, mcp]", "[http, http]", 1),
		"no channels":              strings.Replace(slackCoverage, "[http, mcp]", "[]", 1),
		"unknown field":            slackCoverage + "  grants: [slack.message.post]\n",
		"authority-shaped field":   slackCoverage + "  allow: true\n",
		"environment unknown name": strings.Replace(slackCoverage, "source: none", "source: none\n    default: production", 1),
	} {
		_, err := Decode(append(append([]byte(nil), pcslack.Package...), block...))
		if !errors.Is(err, domain.ErrInvalid) && !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR523_ACoverageDeclarationWidensNothing: the same package with and
// without a declaration has the same definitions, digest for digest, the
// same consequence rules and the same mappings, so every action maps and is
// decided exactly as before: the declaration describes, it never grants
// (G0 M20 D254).
//
// Covers: F756
func TestHR523_ACoverageDeclarationWidensNothing(t *testing.T) {
	plain, err := Decode(pcslack.Package)
	if err != nil {
		t.Fatal(err)
	}
	declared, err := Decode(append(append([]byte(nil), pcslack.Package...), slackCoverage...))
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.Definitions) != len(declared.Definitions) || len(plain.Consequences) != len(declared.Consequences) {
		t.Fatalf("definitions %d/%d consequences %d/%d", len(plain.Definitions), len(declared.Definitions),
			len(plain.Consequences), len(declared.Consequences))
	}
	for i := range plain.Definitions {
		a, b := plain.Definitions[i], declared.Definitions[i]
		if a.Operation != b.Operation || a.Digest != b.Digest || a.Digest == "" {
			t.Fatalf("%s: %s != %s", a.Operation, a.Digest, b.Digest)
		}
	}
	for i := range plain.Consequences {
		if plain.Consequences[i].ID != declared.Consequences[i].ID || plain.Consequences[i].When != declared.Consequences[i].When {
			t.Fatalf("consequence %d differs", i)
		}
	}
}

// TestHR526_JSONBodyKeysFollowTheBracketGrammar: a JSON body's bracket keys
// nest objects only: a [] list, a digit-only name, more than three levels,
// an unpaired bracket or a key that is both a value and a parent refuses
// the package; MCP arguments stay flat (G0 M20 D260).
//
// Covers: F756
func TestHR526_JSONBodyKeysFollowTheBracketGrammar(t *testing.T) {
	const at = "          fields[issuetype][name]: params.issue_type\n"
	raw := string(pcjira.Package)
	if !strings.Contains(raw, at) {
		t.Fatal("fixture moved")
	}
	if _, err := Decode(pcjira.Package); err != nil {
		t.Fatal(err)
	}
	for name, extra := range map[string]string{
		"list":             "          fields[labels][]: params.issue_type\n",
		"digits":           "          fields[0]: params.issue_type\n",
		"too deep":         "          fields[a][b][c]: params.issue_type\n",
		"unpaired":         "          fields[a: params.issue_type\n",
		"value and parent": "          fields: params.issue_type\n",
		"bad name":         "          fields[a b]: params.issue_type\n",
	} {
		_, err := Decode([]byte(strings.Replace(raw, at, at+extra, 1)))
		if !errors.Is(err, domain.ErrInvalid) && !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR526_AValidatorWithoutNestingRefusesBracketKeys: a JSON body key
// that nests is never a flat field name, so a validator that predates
// nesting refuses the package instead of sending "fields[project][key]"
// as one key: it fails closed (G0 M20 D260).
//
// Covers: F756
func TestHR526_AValidatorWithoutNestingRefusesBracketKeys(t *testing.T) {
	flat := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`) // the field rule before D260
	p, err := Decode(pcjira.Package)
	if err != nil {
		t.Fatal(err)
	}
	var nested int
	for _, d := range p.Definitions {
		if d.Dispatch == nil || d.Dispatch.HTTP == nil {
			continue
		}
		for k := range d.Dispatch.HTTP.Body {
			if strings.Contains(k, "[") {
				nested++
				if flat.MatchString(k) {
					t.Fatalf("%s: %q passes the old rule", d.Operation, k)
				}
			}
		}
	}
	if nested == 0 {
		t.Fatal("no nested keys")
	}
}

// TestHR526_AValidatorWithoutBooleansRefusesThem: bool.true and bool.false
// are none of the references a validator before D263 accepts (target.id,
// target.account, params.*, transaction.key, literal.*), so an older server
// refuses a package that uses them instead of sending something else
// (G0 M20 D272).
//
// Covers: F756
func TestHR526_AValidatorWithoutBooleansRefusesThem(t *testing.T) {
	old := regexp.MustCompile(`^(target\.id(\.[a-z_]+)?|target\.account|params\..+|transaction\.key|literal\..+)$`)
	for _, ref := range []string{domain.BoolTrue, domain.BoolFalse} {
		if old.MatchString(ref) {
			t.Fatalf("%s passes the old reference rule", ref)
		}
	}
}
