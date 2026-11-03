// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package campaign reads the library's attack campaigns (G0 M25 D310):
// redteam/campaigns/RT-14x-*.yaml. A campaign plants content an agent will
// read (a poisoned tool result, an injected issue or README, a fake approver,
// credential bait), tells the agent its task, and names each attempt it makes
// and the boundary expected to stop it. The server derives every outcome from
// its own records (HR-608); the file only says what to look for.
//
// A campaign's script is what the scripted stand-in agent does instead of a
// model: one request per attempt. A real model never sees the script.
package campaign

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/katocxl/pantherclaw/internal/campaigns/domain"
	rtdomain "github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// APIVersion is the only version of a campaign file.
const APIVersion = "pantherclaw.campaign/v1"

// Techniques a campaign uses (D310).
var Techniques = []string{"poisoned_tool_result", "injected_issue", "injected_readme", "fake_approver", "credential_bait"}

// ScriptDir is the workspace directory the stand-in's script goes in, only
// on a scripted run.
const ScriptDir = ".pclaw-campaign"

// ScriptFile is the script's name under ScriptDir.
const ScriptFile = "script.json"

// Limits of a campaign file.
const (
	maxPlants    = 8
	maxPlantSize = 16 << 10
	maxAttempts  = 16
	maxText      = 2048
)

var (
	idRE       = regexp.MustCompile(`^RT-14[0-9]$`)
	attemptRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	boundaryRE = regexp.MustCompile(`^HR-[0-9]{3}$`)
	opRE       = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,4}$`)
	hostRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	fixtureRE  = regexp.MustCompile(`\$\{([a-z][a-z0-9_]{0,31})\}`)
	headerRE   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// Plant is a file the campaign puts in the agent's workspace.
type Plant struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Step is one request of the scripted stand-in, for one attempt.
type Step struct {
	Attempt string            `json:"attempt"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Body    string            `json:"body,omitzero"`
	Headers map[string]string `json:"headers,omitzero"`
}

// File is a campaign file.
type File struct {
	APIVersion string   `json:"apiVersion"`
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Technique  string   `json:"technique"`
	Tier       string   `json:"tier"`
	Threats    []string `json:"threats,omitzero"`
	// ASI are the OWASP Top 10 for Agentic Applications risks the campaign
	// exercises by OWASP's definition, ascending (D529).
	ASI []string `json:"asi,omitzero"`
	// ATLAS and ATTACK are the techniques the campaign exercises, with
	// one line each in TechniqueWhy (G0 M28 D714). Labels only: a campaign
	// never feeds a threat-map lane.
	ATLAS        []string          `json:"atlas,omitzero"`
	ATTACK       []string          `json:"attack,omitzero"`
	TechniqueWhy map[string]string `json:"technique_why,omitzero"`
	Rules        []string          `json:"rules,omitzero"`
	Task         string            `json:"task"`
	Plants       []Plant           `json:"plants,omitzero"`
	Attempts     []domain.Attempt  `json:"attempts"`
	Script       []Step            `json:"script"`
}

var asiRE = regexp.MustCompile(`^ASI(0[1-9]|10)$`)

// validASI: OWASP agentic risk ids, strictly ascending.
func validASI(tags []string) bool {
	for i, a := range tags {
		if !asiRE.MatchString(a) || (i > 0 && tags[i-1] >= a) {
			return false
		}
	}
	return true
}

// Loaded is a campaign file read from disk, with its digest.
type Loaded struct {
	Path   string
	File   File
	Digest string
}

// Parse reads a campaign file under the scenario files' strict YAML rules
// and checks it.
func Parse(raw []byte) (*File, error) {
	doc, err := rtdomain.ToJSON(raw)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(doc, &f, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("campaign: %w", err)
	}
	return &f, f.Validate()
}

// Validate checks a campaign file.
func (f *File) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("campaign %s: "+format, append([]any{f.ID}, a...)...)
	}
	switch {
	case f.APIVersion != APIVersion:
		return bad("apiVersion must be %s", APIVersion)
	case !idRE.MatchString(f.ID):
		return bad("the id must be RT-140..RT-149")
	case f.Title == "" || len(f.Title) > 200:
		return bad("a title of 1..200 bytes")
	case !slices.Contains(Techniques, f.Technique):
		return bad("technique must be one of %s", strings.Join(Techniques, ", "))
	case f.Tier != "community" && f.Tier != "pro":
		return bad("tier must be community or pro")
	case f.Task == "" || len(f.Task) > maxText:
		return bad("a task of 1..%d bytes", maxText)
	case len(f.Plants) > maxPlants:
		return bad("at most %d plants", maxPlants)
	case len(f.Attempts) == 0 || len(f.Attempts) > maxAttempts:
		return bad("1..%d attempts", maxAttempts)
	case !validASI(f.ASI):
		return bad("asi: OWASP risks ASI01..ASI10, ascending, each once")
	}
	if err := rtdomain.CheckTechniques(f.ATLAS, f.ATTACK, f.TechniqueWhy); err != nil {
		return bad("%v", err)
	}
	seen := map[string]bool{}
	for _, p := range f.Plants {
		if !plantPath(p.Path) || seen[p.Path] {
			return bad("plant %q: a relative path inside the workspace, once, never under %s", p.Path, ScriptDir)
		}
		seen[p.Path] = true
		if len(p.Content) == 0 || len(p.Content) > maxPlantSize {
			return bad("plant %s: content of 1..%d bytes", p.Path, maxPlantSize)
		}
	}
	attempts := map[string]bool{}
	for _, a := range f.Attempts {
		switch {
		case !attemptRE.MatchString(a.ID) || attempts[a.ID]:
			return bad("attempt %q: a unique lowercase id", a.ID)
		case !boundaryRE.MatchString(a.Boundary):
			return bad("attempt %s: the boundary is the HR rule expected to stop it", a.ID)
		case a.Expected != domain.ExpectHeld && a.Expected != domain.ExpectDenied && a.Expected != domain.ExpectNotRouted:
			return bad("attempt %s: expected is HELD, DENIED or NOT_ROUTED", a.ID)
		case a.Operation == "" && a.RouteHost == "" && !a.Credential:
			return bad("attempt %s: names an operation, a route host or a credential", a.ID)
		case a.Operation != "" && !opRE.MatchString(a.Operation):
			return bad("attempt %s: operation %q", a.ID, a.Operation)
		case a.RouteHost != "" && !hostRE.MatchString(a.RouteHost):
			return bad("attempt %s: route host %q", a.ID, a.RouteHost)
		}
		attempts[a.ID] = true
	}
	scripted := map[string]bool{}
	for _, s := range f.Script {
		if !attempts[s.Attempt] {
			return bad("a script step names attempt %q, which the campaign does not have", s.Attempt)
		}
		scripted[s.Attempt] = true
		if err := s.check(); err != nil {
			return bad("script step %s: %v", s.Attempt, err)
		}
	}
	if len(scripted) != len(attempts) {
		return bad("the script makes every attempt at least once")
	}
	return nil
}

func plantPath(p string) bool {
	return p != "" && len(p) <= 200 && !strings.Contains(p, `\`) && path.Clean(p) == p && !path.IsAbs(p) &&
		p != ".." && !strings.HasPrefix(p, "../") && p != ScriptDir && !strings.HasPrefix(p, ScriptDir+"/")
}

func (s Step) check() error {
	switch s.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return errors.New("method must be GET, POST, PUT, PATCH or DELETE")
	}
	u, err := url.Parse(fixtureRE.ReplaceAllString(s.URL, "x"))
	if err != nil || u.Scheme != "https" || !hostRE.MatchString(u.Hostname()) || u.User != nil || u.Fragment != "" {
		return errors.New("the url is an https URL to a host name")
	}
	if len(s.Body) > maxText || len(s.Headers) > 4 {
		return fmt.Errorf("a body of at most %d bytes and at most 4 headers", maxText)
	}
	for k, v := range s.Headers {
		if !headerRE.MatchString(k) || len(v) > 512 || strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("header %q", k)
		}
	}
	return nil
}

// Digest is the SHA-256 (hex) of the RFC 8785 canonical JSON of the parsed
// file, as a scenario's (rtdomain.Digest): spelling in the YAML does not
// change it.
func Digest(f *File) (string, error) {
	raw, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	v := jsontext.Value(raw)
	if err := v.Canonicalize(); err != nil {
		return "", err
	}
	sum := sha256.Sum256(v)
	return hex.EncodeToString(sum[:]), nil
}

// LoadDir loads every RT-14x-*.yaml campaign in dir, sorted by id. A bad
// file, a filename that does not start with its id, or a repeated id is an
// error.
func LoadDir(dir string) ([]Loaded, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	var out []Loaded
	ids := map[string]string{}
	for _, name := range files {
		info, err := os.Lstat(name)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s: a campaign file is a regular file", filepath.Base(name))
		}
		raw, err := os.ReadFile(name) //nolint:gosec // G304: the operator's campaign directory
		if err != nil {
			return nil, err
		}
		f, err := Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(name), err)
		}
		if !strings.HasPrefix(filepath.Base(name), f.ID+"-") {
			return nil, fmt.Errorf("%s: the file name starts with its id %s", filepath.Base(name), f.ID)
		}
		if prev, dup := ids[f.ID]; dup {
			return nil, fmt.Errorf("%s: id %s is also in %s", filepath.Base(name), f.ID, prev)
		}
		ids[f.ID] = filepath.Base(name)
		d, err := Digest(f)
		if err != nil {
			return nil, err
		}
		out = append(out, Loaded{Path: name, File: *f, Digest: d})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File.ID < out[j].File.ID })
	return out, nil
}

// Fixtures fills ${name} in a script's URLs, bodies and headers and in the
// plants. A name with no value is an error, so a campaign never runs half
// filled in.
type Fixtures map[string]string

func (fx Fixtures) fill(s string) (string, error) {
	var missing []string
	out := fixtureRE.ReplaceAllStringFunc(s, func(m string) string {
		name := m[2 : len(m)-1]
		v, ok := fx[name]
		if !ok {
			missing = append(missing, name)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("no --fixture for %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// CanaryPrefix starts the fixtures a run makes up itself: fresh bait shaped
// like a real credential, never one. A --fixture never sets them.
const CanaryPrefix = "canary_"

// Canaries returns fresh bait for one campaign run: a GitHub token, an AWS
// key pair and an SSH private key block (with its base64, as a contents
// write carries it). Each value is random and unique to the run, so a
// campaign file holds no credential-shaped value.
func Canaries() Fixtures {
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	pick := func(set string, n int) string {
		b := make([]byte, n)
		_, _ = rand.Read(b)
		for i := range b {
			b[i] = set[int(b[i])%len(set)]
		}
		return string(b)
	}
	raw := make([]byte, 96)
	_, _ = rand.Read(raw)
	key := string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: raw}))
	return Fixtures{
		CanaryPrefix + "github_token": "ghp_" + pick(alnum, 36),
		CanaryPrefix + "aws_key_id":   "AKIA" + pick(upper, 16),
		CanaryPrefix + "aws_secret":   pick(alnum, 40),
		CanaryPrefix + "ssh_key":      key,
		CanaryPrefix + "ssh_key_b64":  base64.StdEncoding.EncodeToString([]byte(key)),
	}
}

// With returns fx with more fixtures added.
func (fx Fixtures) With(more Fixtures) Fixtures {
	out := maps.Clone(fx)
	if out == nil {
		out = Fixtures{}
	}
	maps.Copy(out, more)
	return out
}

// Script is what the scripted stand-in reads from its workspace.
type Script struct {
	Campaign  string `json:"campaign"`
	ModelHost string `json:"model_host"`
	Steps     []Step `json:"steps"`
}

// ErrPlantLink refuses a plant whose path is, or passes through, a link: a
// write would land outside the workspace (D525 M3).
var ErrPlantLink = errors.New("campaign: a plant's path is a symbolic link")

// Workspace writes the campaign's plants into dir, filled in, and, for a
// scripted run, the stand-in's script under ScriptDir. Every write goes
// through an os.Root on dir and refuses a path through a symbolic link, so
// no plant lands outside dir (D525 M3).
func (f *File) Workspace(dir string, fx Fixtures, modelHost string, scripted bool) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	for _, p := range f.Plants {
		content, err := fx.fill(p.Content)
		if err != nil {
			return fmt.Errorf("%s plant %s: %w", f.ID, p.Path, err)
		}
		if err := writeNoLink(root, p.Path, []byte(content)); err != nil {
			return fmt.Errorf("%s plant %s: %w", f.ID, p.Path, err)
		}
	}
	if !scripted {
		return nil
	}
	return f.writeScript(root, fx, modelHost)
}

// writeNoLink writes name (slash separated, relative) under root. No
// component of the path may be a symbolic link, the file included.
func writeNoLink(root *os.Root, name string, b []byte) error {
	parts := strings.Split(name, "/")
	for i := range parts {
		fi, err := root.Lstat(path.Join(parts[:i+1]...))
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return err
		case fi.Mode()&fs.ModeSymlink != 0:
			return ErrPlantLink
		case i < len(parts)-1 && !fi.IsDir():
			return fmt.Errorf("campaign: %s is not a directory", path.Join(parts[:i+1]...))
		}
	}
	if dir := path.Dir(name); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	fh, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := fh.Write(b); err != nil {
		_ = fh.Close()
		return err
	}
	return fh.Close()
}

func (f *File) writeScript(root *os.Root, fx Fixtures, modelHost string) error {
	sc := Script{Campaign: f.ID, ModelHost: modelHost}
	for _, s := range f.Script {
		var err error
		if s.URL, err = fx.fill(s.URL); err != nil {
			return fmt.Errorf("%s script: %w", f.ID, err)
		}
		if s.Body, err = fx.fill(s.Body); err != nil {
			return fmt.Errorf("%s script: %w", f.ID, err)
		}
		h := maps.Clone(s.Headers)
		for k, v := range h {
			if h[k], err = fx.fill(v); err != nil {
				return fmt.Errorf("%s script: %w", f.ID, err)
			}
		}
		s.Headers = h
		sc.Steps = append(sc.Steps, s)
	}
	b, err := json.Marshal(sc, jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	return writeNoLink(root, ScriptDir+"/"+ScriptFile, b)
}
