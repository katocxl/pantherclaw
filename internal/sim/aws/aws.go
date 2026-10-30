// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package aws is a simulated AWS account for tests and demos
// (pantherclaw-sim aws, G0 M20 D254). One server answers, by the service of
// each request's SigV4 credential scope:
//
//   - STS AssumeRole (aws-query): a session of the account's one role for
//     the requested duration (900..3600 s), under the request's session
//     policy, for the base access key only;
//   - IAM GetRole, ListAttachedRolePolicies, GetRolePolicy and
//     GetAccountSummary (aws-query, answered in XML as IAM does);
//   - ECS UpdateService and DescribeServices (aws-json) for three services,
//     whose rollout state a test sets.
//
// Every request must be signed with SigV4 by a key the simulator knows, and
// is verified by signing it again. The base key may call only
// sts:AssumeRole; a session may call an action only when both the role and
// the session policy allow it, as AWS intersects them, else AccessDenied.
// Faults inject throttling, a refused AssumeRole and sessions that outlive
// 15 minutes. GET /__sim/calls lists every call and the policy it ran
// under, for tests. Every response is marked SIMULATED; nothing here
// reaches AWS.
package aws

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

// The simulated account.
const (
	Account   = "111122223333"
	RoleName  = "pantherclaw-deploy"
	RoleARN   = "arn:aws:iam::" + Account + ":role/" + RoleName
	Region    = "us-east-1"
	BaseKeyID = "AKIASIMULATEDBASE001"
	// InlinePolicy is the role's one inline policy.
	InlinePolicy = "read-ecs"
)

// maxBody bounds a request body.
const maxBody = 64 << 10

// Faults configures fault injection.
type Faults struct {
	// Throttle answers the next Throttle requests with 400 Throttling.
	Throttle int `json:"throttle,omitzero"`
	// DenyAssumeRole refuses every AssumeRole (a changed trust policy).
	DenyAssumeRole bool `json:"deny_assume_role,omitzero"`
	// LongSessions issues sessions of an hour whatever was asked.
	LongSessions bool `json:"long_sessions,omitzero"`
}

// Call is one authenticated request.
type Call struct {
	Service string `json:"service"`
	Action  string `json:"action"`
	// Key is "base" or "session".
	Key     string `json:"key"`
	Allowed bool   `json:"allowed"`
	// Policy is the session policy's allowed actions, for a session, and
	// Resource the resource the call acted on.
	Policy   []string `json:"policy,omitzero"`
	Resource string   `json:"resource,omitzero"`
}

// grant is one action a session policy allows on one resource pattern.
type grant struct{ action, resource string }

type session struct {
	secret, token string
	expires       time.Time
	grants        []grant
}

// actions are the actions a session policy names.
func (s *session) actions() []string {
	var out []string
	for _, g := range s.grants {
		if !slices.Contains(out, g.action) {
			out = append(out, g.action)
		}
	}
	return out
}

// Server is the simulated account.
type Server struct {
	baseSecret string
	externalID string
	log        *slog.Logger

	mu       sync.Mutex
	faults   Faults
	role     []string // the actions the role's own policies allow
	sessions map[string]*session
	calls    []Call
	now      func() time.Time
	ecs      map[string]*ecsService
}

// New returns a simulator whose base key has baseSecret and whose role
// allows roleActions ("iam:GetRole", ...; "*" for every action). A
// non-empty externalID is required on every AssumeRole.
func New(baseSecret, externalID string, roleActions []string, f Faults, log *slog.Logger) *Server {
	return &Server{
		baseSecret: baseSecret, externalID: externalID, log: log, faults: f, role: slices.Clone(roleActions),
		sessions: map[string]*session{}, now: time.Now, ecs: newECSServices(),
	}
}

// SetFaults replaces the faults from the next request on.
func (s *Server) SetFaults(f Faults) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = f
}

// SetClock replaces the clock sessions and signatures are checked by.
func (s *Server) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// Calls returns every authenticated call, in order.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// Sessions returns how many sessions STS issued.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Handler serves the simulator.
func (s *Server) Handler() http.Handler {
	return handshake.Wrap("aws", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		switch {
		case r.URL.Path == "/__sim/calls" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.MarshalWrite(w, map[string]any{"calls": s.Calls(), "sessions": s.Sessions()})
		case r.URL.Path == "/__sim/faults" && r.Method == http.MethodPost:
			var f Faults
			if err := json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &f); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.SetFaults(f)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/":
			s.serve(w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

var credRe = regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=([A-Z0-9]+)/([0-9]{8})/([a-z0-9-]+)/([a-z0-9-]+)/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})$`)

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		writeError(w, http.StatusBadRequest, "MalformedInput", "body")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.faults.Throttle > 0 {
		s.faults.Throttle--
		writeError(w, http.StatusBadRequest, "Throttling", "Rate exceeded")
		return
	}
	m := credRe.FindStringSubmatch(r.Header.Get("Authorization"))
	if m == nil {
		writeError(w, http.StatusForbidden, "MissingAuthenticationToken", "the request is not signed with SigV4")
		return
	}
	keyID, region, service := m[1], m[3], m[4]
	secret, sess, key := s.secretOf(keyID)
	if secret == "" {
		writeError(w, http.StatusForbidden, "InvalidClientTokenId", "the security token included in the request is invalid")
		return
	}
	now := s.now()
	if sess != nil && (!now.Before(sess.expires) || r.Header.Get("X-Amz-Security-Token") != sess.token) {
		writeError(w, http.StatusForbidden, "ExpiredToken", "the security token included in the request is expired or invalid")
		return
	}
	if !s.verify(r, body, m, secret, sess, now) {
		writeError(w, http.StatusForbidden, "SignatureDoesNotMatch", "the request signature we calculated does not match")
		return
	}
	if target := r.Header.Get("X-Amz-Target"); target != "" {
		s.serveECS(w, body, target, service, key, sess)
		return
	}
	var in url.Values
	if r.Method == http.MethodPost {
		if in, err = url.ParseQuery(string(body)); err != nil {
			writeError(w, http.StatusBadRequest, "MalformedInput", "form")
			return
		}
	} else {
		in = r.URL.Query()
	}
	action := in.Get("Action")
	call := Call{Service: service, Action: action, Key: key, Resource: resourceOf(service, action, in)}
	if sess != nil {
		call.Policy = sess.actions()
	}
	call.Allowed = s.allowed(service, action, call.Resource, sess)
	s.calls = append(s.calls, call)
	if !call.Allowed {
		writeError(w, http.StatusForbidden, "AccessDenied", fmt.Sprintf("not authorized to perform %s:%s", service, action))
		return
	}
	switch service + ":" + action {
	case "sts:AssumeRole":
		s.assumeRole(w, in, region, now)
	case "iam:GetRole":
		s.getRole(w, in)
	case "iam:ListAttachedRolePolicies":
		s.listAttached(w, in)
	case "iam:GetRolePolicy":
		s.getRolePolicy(w, in)
	case "iam:GetAccountSummary":
		writeXML(w, "GetAccountSummary", "iam", `<SummaryMap><entry><key>Roles</key><value>1</value></entry></SummaryMap>`)
	default:
		writeError(w, http.StatusBadRequest, "InvalidAction", "unknown action "+action)
	}
}

// secretOf returns a key's secret, its session (nil for the base key) and
// its kind.
func (s *Server) secretOf(keyID string) (string, *session, string) {
	if keyID == BaseKeyID {
		return s.baseSecret, nil, "base"
	}
	if sess, ok := s.sessions[keyID]; ok {
		return sess.secret, sess, "session"
	}
	return "", nil, ""
}

// verify signs a copy of the request, with only the headers it signed,
// with the key's secret at its X-Amz-Date, and compares the result.
func (s *Server) verify(r *http.Request, body []byte, m []string, secret string, sess *session, now time.Time) bool {
	t, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil || t.Format("20060102") != m[2] || t.Sub(now) > 15*time.Minute || now.Sub(t) > 15*time.Minute {
		return false
	}
	u := *r.URL
	u.Scheme, u.Host = "http", r.Host
	c, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), bytes.NewReader(body)) //nolint:gosec // G704: a copy to sign, never sent
	if err != nil {
		return false
	}
	c.Host = r.Host
	for _, h := range strings.Split(m[5], ";") {
		if h == "host" || h == "x-amz-date" || h == "x-amz-security-token" {
			continue
		}
		vals := r.Header.Values(h)
		if len(vals) == 0 {
			return false
		}
		c.Header[http.CanonicalHeaderKey(h)] = vals
	}
	creds := sigv4.Credentials{AccessKeyID: m[1], SecretAccessKey: secret}
	if sess != nil {
		creds.SessionToken = sess.token
	}
	if err := (sigv4.Signer{Region: m[3], Service: m[4]}).Sign(c, creds, sigv4.HashPayload(body), t); err != nil {
		return false
	}
	return c.Header.Get("Authorization") == r.Header.Get("Authorization")
}

// allowed applies AWS's intersection: the base key may only assume the
// role; a session may call an action the role allows and its policy allows
// on the call's resource.
func (s *Server) allowed(service, action, resource string, sess *session) bool {
	full := service + ":" + action
	if sess == nil {
		return full == "sts:AssumeRole"
	}
	return full != "sts:AssumeRole" && grants(s.role, full) && slices.ContainsFunc(sess.grants, func(g grant) bool {
		return grants([]string{g.action}, full) && matches(g.resource, resource)
	})
}

// matches reports whether a policy's resource pattern covers resource:
// "*" covers all, and a "*" in a pattern any run of characters. A call
// on no particular resource ("*") is covered by "*" only.
func matches(pattern, resource string) bool {
	if pattern == "*" {
		return true
	}
	if resource == "*" {
		return false
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(resource, parts[0]) {
		return false
	}
	rest := resource[len(parts[0]):]
	for i, p := range parts[1:] {
		if i == len(parts)-2 {
			return strings.HasSuffix(rest, p)
		}
		j := strings.Index(rest, p)
		if j < 0 {
			return false
		}
		rest = rest[j+len(p):]
	}
	return rest == ""
}

// resourceOf is the resource a call acts on, as IAM evaluates it.
func resourceOf(service, action string, in url.Values) string {
	switch service + ":" + action {
	case "iam:GetRole", "iam:ListAttachedRolePolicies", "iam:GetRolePolicy":
		return "arn:aws:iam::" + Account + ":role/" + in.Get("RoleName")
	case "sts:AssumeRole":
		return in.Get("RoleArn")
	}
	return "*"
}

// grants reports whether actions allow full: exactly, by "*", or by a
// "service:*" or "service:Prefix*" wildcard, as IAM matches them.
func grants(actions []string, full string) bool {
	return slices.ContainsFunc(actions, func(a string) bool {
		prefix, wild := strings.CutSuffix(a, "*")
		return a == full || (wild && strings.HasPrefix(full, prefix))
	})
}

func (s *Server) assumeRole(w http.ResponseWriter, in url.Values, region string, now time.Time) {
	secs, err := strconv.Atoi(in.Get("DurationSeconds"))
	switch {
	case s.faults.DenyAssumeRole, in.Get("RoleArn") != RoleARN, s.externalID != "" && in.Get("ExternalId") != s.externalID:
		writeError(w, http.StatusForbidden, "AccessDenied", "not authorized to perform sts:AssumeRole")
		return
	case err != nil || secs < 900 || secs > 3600:
		writeError(w, http.StatusBadRequest, "ValidationError", "DurationSeconds must be 900..3600")
		return
	case region != Region:
		writeError(w, http.StatusBadRequest, "SignatureDoesNotMatch", "STS signs in "+Region)
		return
	}
	grants, ok := policyGrants(in.Get("Policy"))
	if !ok {
		writeError(w, http.StatusBadRequest, "MalformedPolicyDocument", "the session policy")
		return
	}
	if s.faults.LongSessions {
		secs = 3600
	}
	id := "ASIA" + strings.ToUpper(random(8))
	sess := &session{secret: random(20), token: "simtoken" + random(24), expires: now.Add(time.Duration(secs) * time.Second), grants: grants}
	s.sessions[id] = sess
	s.log.Info("sim.aws_assumed_role", slog.String("session", id), slog.Any("policy", sess.actions()))
	writeXML(w, "AssumeRole", "sts", fmt.Sprintf(
		`<Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials>`+
			`<AssumedRoleUser><Arn>arn:aws:sts::%s:assumed-role/%s/%s</Arn><AssumedRoleId>AROASIMULATED:%s</AssumedRoleId></AssumedRoleUser>`,
		id, sess.secret, sess.token, sess.expires.UTC().Format(time.RFC3339), Account, RoleName, xmlText(in.Get("RoleSessionName")), xmlText(in.Get("RoleSessionName"))))
}

// policyGrants reads a session policy's grants: every statement must
// Allow one action or a list of them on one resource or a list of them.
func policyGrants(doc string) ([]grant, bool) {
	if doc == "" {
		return nil, false // the simulator requires a session policy, as PantherClaw always sends one
	}
	var p struct {
		Version   string `json:"Version"`
		Statement []struct {
			Effect   string `json:"Effect"`
			Action   any    `json:"Action"`
			Resource any    `json:"Resource"`
		} `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &p) != nil || p.Version != "2012-10-17" || len(p.Statement) == 0 {
		return nil, false
	}
	var out []grant
	for _, st := range p.Statement {
		actions, ok1 := strs(st.Action)
		resources, ok2 := strs(st.Resource)
		if st.Effect != "Allow" || !ok1 || !ok2 {
			return nil, false
		}
		for _, a := range actions {
			for _, r := range resources {
				out = append(out, grant{action: a, resource: r})
			}
		}
	}
	return out, true
}

// strs reads a policy element: one string or a non-empty list of them.
func strs(v any) ([]string, bool) {
	switch x := v.(type) {
	case string:
		return []string{x}, x != ""
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok || s == "" {
				return nil, false
			}
			out = append(out, s)
		}
		return out, len(out) > 0
	}
	return nil, false
}

func (s *Server) getRole(w http.ResponseWriter, in url.Values) {
	if in.Get("RoleName") != RoleName {
		writeError(w, http.StatusNotFound, "NoSuchEntity", "the role cannot be found")
		return
	}
	trust := url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + Account + `:user/pantherclaw"},"Action":"sts:AssumeRole"}]}`)
	writeXML(w, "GetRole", "iam", fmt.Sprintf(
		`<Role><Path>/</Path><RoleName>%s</RoleName><RoleId>AROASIMULATEDROLE0001</RoleId><Arn>%s</Arn>`+
			`<CreateDate>2026-10-01T00:00:00Z</CreateDate><AssumeRolePolicyDocument>%s</AssumeRolePolicyDocument><MaxSessionDuration>3600</MaxSessionDuration></Role>`,
		RoleName, RoleARN, trust))
}

func (s *Server) listAttached(w http.ResponseWriter, in url.Values) {
	if in.Get("RoleName") != RoleName {
		writeError(w, http.StatusNotFound, "NoSuchEntity", "the role cannot be found")
		return
	}
	writeXML(w, "ListAttachedRolePolicies", "iam",
		`<AttachedPolicies><member><PolicyName>AmazonECS_FullAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/AmazonECS_FullAccess</PolicyArn></member></AttachedPolicies><IsTruncated>false</IsTruncated>`)
}

func (s *Server) getRolePolicy(w http.ResponseWriter, in url.Values) {
	if in.Get("RoleName") != RoleName || in.Get("PolicyName") != InlinePolicy {
		writeError(w, http.StatusNotFound, "NoSuchEntity", "the role policy cannot be found")
		return
	}
	doc := url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ecs:Describe*","Resource":"*"}]}`)
	writeXML(w, "GetRolePolicy", "iam", fmt.Sprintf(`<RoleName>%s</RoleName><PolicyName>%s</PolicyName><PolicyDocument>%s</PolicyDocument>`, RoleName, InlinePolicy, doc))
}

func writeXML(w http.ResponseWriter, action, service, result string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(http.StatusOK)
	ns := map[string]string{"iam": "https://iam.amazonaws.com/doc/2010-05-08/", "sts": "https://sts.amazonaws.com/doc/2011-06-15/"}[service]
	_, _ = fmt.Fprintf(w, `<%sResponse xmlns="%s"><%sResult>%s</%sResult><ResponseMetadata><RequestId>%s</RequestId></ResponseMetadata></%sResponse>`,
		action, ns, action, result, action, random(8), action)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>SIMULATED: %s</Message></Error><RequestId>%s</RequestId></ErrorResponse>`,
		code, xmlText(message), random(8))
}

func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
