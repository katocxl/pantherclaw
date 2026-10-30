// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// GitLabDefaultIssuer is the issuer accepted when the operator configures
// none (D119).
const GitLabDefaultIssuer = "https://gitlab.com"

// GitLabAlgorithms are the only signature algorithms GitLab ID tokens may
// use.
var GitLabAlgorithms = []string{"RS256"}

// ciConfigRefURI is host/full/project/path//config/path@refs/heads|tags/…
var ciConfigRefURI = regexp.MustCompile(`^([a-z0-9.-]+(?::[0-9]+)?)/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*//[^@\s]+@refs/(heads|tags)/[^\s]+$`)

// GitLabBinding pins GitLab CI ID tokens to one agent (HR-461, HR-140).
type GitLabBinding struct {
	// Issuer is one of the GitLab instances the operator configured
	// (identity.gitlab_issuers); never a tenant-chosen address.
	Issuer      string `json:"issuer"`
	ProjectID   string `json:"project_id"`
	NamespaceID string `json:"namespace_id"`
	// CIConfigRefURIs are accepted values of ci_config_ref_uri: the
	// pipeline definition's path on a branch or tag.
	CIConfigRefURIs []string `json:"ci_config_ref_uris"`
	// CIConfigSHAs optionally pin exact revisions of the definition.
	CIConfigSHAs      []string `json:"ci_config_shas,omitzero"`
	Environment       string   `json:"environment,omitzero"`
	RunnerEnvironment string   `json:"runner_environment,omitzero"`
}

// Validate checks that the binding pins numeric ids and branch or tag
// definitions on the issuer's own host (HR-140, HR-461). Project and
// group paths are never enough: they can be renamed and reused.
func (b GitLabBinding) Validate() error {
	var errs []string
	iu, err := url.Parse(b.Issuer)
	if err != nil || iu.Scheme != "https" || iu.Host == "" || iu.User != nil || iu.RawQuery != "" || iu.Fragment != "" ||
		(iu.Path != "" && iu.Path != "/") || len(b.Issuer) > 255 {
		errs = append(errs, "issuer must be an https URL without path")
	}
	if !numericID.MatchString(b.ProjectID) || !numericID.MatchString(b.NamespaceID) {
		errs = append(errs, "project_id and namespace_id must be numeric ids")
	}
	if len(b.CIConfigRefURIs) == 0 || len(b.CIConfigRefURIs) > 20 {
		errs = append(errs, "1 to 20 ci_config_ref_uri values are required")
	}
	for _, r := range b.CIConfigRefURIs {
		m := ciConfigRefURI.FindStringSubmatch(r)
		if m == nil || strings.Contains(r, "*") || iu == nil || !strings.EqualFold(m[1], iu.Host) {
			errs = append(errs, fmt.Sprintf("ci_config_ref_uri %q must be <issuer host>/<project path>//<file>@refs/heads/… or @refs/tags/… with no wildcard", r))
		}
	}
	for _, s := range b.CIConfigSHAs {
		if !gitSHA.MatchString(s) {
			errs = append(errs, fmt.Sprintf("ci_config_sha %q must be 40 hex digits", s))
		}
	}
	if len(b.CIConfigSHAs) > 20 || len(b.Environment) > 255 ||
		(b.RunnerEnvironment != "" && b.RunnerEnvironment != "gitlab-hosted" && b.RunnerEnvironment != "self-hosted") {
		errs = append(errs, "sha, environment or runner environment pin")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidEntry, strings.Join(errs, "; "))
	}
	return nil
}

// Widening lists what b accepts that prev did not (HR-141).
func (b GitLabBinding) Widening(prev *GitLabBinding) []string {
	if prev == nil {
		return []string{"new trusted issuer entry"}
	}
	var out []string
	if prev.Issuer != b.Issuer || prev.ProjectID != b.ProjectID || prev.NamespaceID != b.NamespaceID {
		out = append(out, "issuer, project or namespace changed")
	}
	out = append(out, widenedList("ci_config_ref_uris", prev.CIConfigRefURIs, b.CIConfigRefURIs)...)
	out = append(out, widenedList("ci_config_shas", prev.CIConfigSHAs, b.CIConfigSHAs)...)
	out = append(out, widenedPin("environment", prev.Environment, b.Environment)...)
	out = append(out, widenedPin("runner_environment", prev.RunnerEnvironment, b.RunnerEnvironment)...)
	return out
}

// GitLabClaims are the claims of a GitLab CI ID token whose signature was
// already verified with its issuer's keys.
type GitLabClaims struct {
	Issuer            string         `json:"iss"`
	Audience          jsontext.Value `json:"aud"`
	JTI               string         `json:"jti"`
	ProjectID         jsontext.Value `json:"project_id"`
	NamespaceID       jsontext.Value `json:"namespace_id"`
	Ref               string         `json:"ref"`
	RefType           string         `json:"ref_type"`
	RefProtected      jsontext.Value `json:"ref_protected"`
	PipelineSource    string         `json:"pipeline_source"`
	Environment       string         `json:"environment"`
	RunnerEnvironment string         `json:"runner_environment"`
	CIConfigRefURI    string         `json:"ci_config_ref_uri"`
	CIConfigSHA       string         `json:"ci_config_sha"`
	SHA               string         `json:"sha"`
}

// ParseGitLabClaims decodes a verified payload; unknown claims are ignored,
// duplicate members are rejected.
func ParseGitLabClaims(payload []byte) (GitLabClaims, error) {
	var c GitLabClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, rejected("gitlab claims: %v", err)
	}
	return c, nil
}

// idValue reads a numeric id GitLab sends as a string (or, defensively, as
// a JSON integer).
func idValue(v jsontext.Value) string {
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s
	}
	if t := strings.TrimSpace(string(v)); numericID.MatchString(t) {
		return t
	}
	return ""
}

// MatchGitLab applies the GitLab preset to verified claims. The rules that
// no configuration can disable (HR-461):
//   - iss is the entry's issuer and aud is exactly pantherclaw:<org>;
//   - project_id and namespace_id equal the pinned numeric ids;
//   - ref_protected is true and ref_type is branch or tag;
//   - pipeline_source is not merge_request_event or
//     external_pull_request_event (those pipelines run code not yet
//     reviewed into a protected ref);
//   - ci_config_ref_uri is one of the pinned definitions (and its sha one
//     of the pinned shas, when pinned).
func MatchGitLab(b GitLabBinding, org ids.OrgID, c GitLabClaims) (Match, error) {
	if err := b.Validate(); err != nil {
		return Match{}, err
	}
	project, namespace := idValue(c.ProjectID), idValue(c.NamespaceID)
	switch {
	case c.Issuer != strings.TrimSuffix(b.Issuer, "/"):
		return Match{}, rejected("issuer %q", c.Issuer)
	case !audienceIs(c.Audience, Audience(org)):
		return Match{}, rejected("audience")
	case project == "" || project != b.ProjectID || namespace != b.NamespaceID:
		return Match{}, rejected("project or namespace id")
	case c.PipelineSource == "merge_request_event" || c.PipelineSource == "external_pull_request_event":
		return Match{}, rejected("pipeline source %s runs code not reviewed into a protected ref", c.PipelineSource)
	case c.RefType != "branch" && c.RefType != "tag":
		return Match{}, rejected("ref type %q", c.RefType)
	case !refProtected(c.RefProtected):
		return Match{}, rejected("ref %s is not protected", c.Ref)
	case b.Environment != "" && c.Environment != b.Environment:
		return Match{}, rejected("environment")
	case b.RunnerEnvironment != "" && c.RunnerEnvironment != b.RunnerEnvironment:
		return Match{}, rejected("runner environment")
	case !slices.Contains(b.CIConfigRefURIs, c.CIConfigRefURI):
		return Match{}, rejected("ci_config_ref_uri %q not pinned", c.CIConfigRefURI)
	case len(b.CIConfigSHAs) > 0 && !slices.Contains(b.CIConfigSHAs, c.CIConfigSHA):
		return Match{}, rejected("ci_config_sha not pinned")
	}
	return Match{Binding: Binding{
		"project_id":        project,
		"namespace_id":      namespace,
		"ci_config_ref_uri": c.CIConfigRefURI,
	}}, nil
}
