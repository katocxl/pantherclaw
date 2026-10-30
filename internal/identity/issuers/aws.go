// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers

import (
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The AWS preset (D121): the workload signs an sts:GetCallerIdentity
// request with SigV4 and sends it, unsent, as its attestation; PantherClaw
// checks it and sends it to STS itself.
const (
	// AWSBody is the only request body the AWS preset sends.
	AWSBody = "Action=GetCallerIdentity&Version=2011-06-15"
	// AWSIssuer is the issuer recorded for AWS entries and attestations,
	// whichever STS endpoint answered.
	AWSIssuer = "https://sts.amazonaws.com"
	// AWSAudienceHeader carries pantherclaw:<org> and must be signed.
	AWSAudienceHeader = "X-Pantherclaw-Audience"
	// AWSMaxAge is how long a signed request attests: SigV4's own limit.
	AWSMaxAge = 15 * time.Minute
	// awsDate is the X-Amz-Date format.
	awsDate = "20060102T150405Z"
)

// AWSAlgorithms names the signature the preset accepts.
var AWSAlgorithms = []string{"AWS4-HMAC-SHA256"}

// awsHeaders are the only headers a request may carry (canonical form).
var awsHeaders = []string{"Authorization", "Content-Type", "Host", "X-Amz-Date", "X-Amz-Security-Token", AWSAudienceHeader}

var (
	awsAccountID = regexp.MustCompile(`^[0-9]{12}$`)
	awsRoleName  = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)
	// assumedRole is the ARN GetCallerIdentity returns for a role session.
	assumedRole = regexp.MustCompile(`^arn:aws(?:-[a-z]+)*:sts::([0-9]{12}):assumed-role/([A-Za-z0-9+=,.@_-]{1,64})/[A-Za-z0-9+=,.@_-]{2,64}$`)
	// awsAuthorization is a SigV4 Authorization header.
	awsAuthorization = regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=([A-Za-z0-9]{16,128})/([0-9]{8})/([a-z0-9-]{1,32})/sts/aws4_request, ` +
		`SignedHeaders=([a-z0-9;-]{1,256}), Signature=([0-9a-f]{64})$`)
)

// AWSRequest is a signed sts:GetCallerIdentity request, as the workload
// encodes it: base64url (no padding) of this JSON.
type AWSRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// Encode returns the attestation token for r.
func (r AWSRequest) Encode() (string, error) {
	b, err := json.Marshal(r)
	return base64.RawURLEncoding.EncodeToString(b), err
}

// ParseAWSRequest decodes an attestation token. It checks nothing beyond
// the encoding; CheckAWSRequest does.
func ParseAWSRequest(token string) (AWSRequest, error) {
	var r AWSRequest
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return r, rejected("aws request encoding: %v", err)
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, rejected("aws request: %v", err)
	}
	return r, nil
}

// Header returns the value of header name, whatever the key's case.
func (r AWSRequest) Header(name string) string {
	for k, v := range r.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// AWSSigned is what CheckAWSRequest read from a request.
type AWSSigned struct {
	URL       *url.URL
	SignedAt  time.Time
	Signature string
}

// CheckAWSRequest applies the rules that no configuration can disable
// (HR-464) to a request before it is sent: POST to https://<host>/ on a
// host hosts allows, the exact GetCallerIdentity body, only known headers,
// each once, a SigV4 signature for STS that signs host, x-amz-date and the
// audience header, the audience exactly pantherclaw:<org>, and a signing
// time within AWSMaxAge of now.
func CheckAWSRequest(r AWSRequest, org ids.OrgID, hosts func(string) bool, now time.Time) (AWSSigned, error) {
	var out AWSSigned
	u, err := url.Parse(r.URL)
	switch {
	case r.Method != http.MethodPost:
		return out, rejected("method %q", r.Method)
	case err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || (u.Path != "/" && u.Path != "") ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return out, rejected("url %q", r.URL)
	case !hosts(u.Hostname()):
		return out, rejected("host %q is not an allowed STS endpoint", u.Hostname())
	case r.Body != AWSBody:
		return out, rejected("body is not GetCallerIdentity")
	}
	seen := map[string]bool{}
	for k := range r.Headers {
		c := canonicalHeader(k)
		if !slices.Contains(awsHeaders, c) || seen[c] {
			return out, rejected("header %q", k)
		}
		seen[c] = true
	}
	m := awsAuthorization.FindStringSubmatch(r.Header("Authorization"))
	if m == nil {
		return out, rejected("authorization is not a SigV4 signature for STS")
	}
	signed := strings.Split(m[4], ";")
	for _, h := range []string{"host", "x-amz-date", strings.ToLower(AWSAudienceHeader)} {
		if !slices.Contains(signed, h) {
			return out, rejected("%s is not signed", h)
		}
	}
	if r.Header("X-Amz-Security-Token") != "" && !slices.Contains(signed, "x-amz-security-token") {
		return out, rejected("x-amz-security-token is not signed")
	}
	if h := r.Header("Host"); h != "" && !strings.EqualFold(h, u.Host) {
		return out, rejected("host header %q", h)
	}
	if r.Header(AWSAudienceHeader) != Audience(org) {
		return out, rejected("audience")
	}
	at, err := time.Parse(awsDate, r.Header("X-Amz-Date"))
	switch {
	case err != nil || at.Format("20060102") != m[2]:
		return out, rejected("x-amz-date")
	case at.After(now.Add(Leeway)) || now.Sub(at) > AWSMaxAge:
		return out, rejected("signed more than %s ago or in the future", AWSMaxAge)
	}
	u.Path = "/"
	return AWSSigned{URL: u, SignedAt: at, Signature: m[5]}, nil
}

// canonicalHeader is name in canonical MIME form (x-amz-date →
// X-Amz-Date).
func canonicalHeader(name string) string {
	parts := strings.Split(strings.ToLower(name), "-")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "-")
}

// AWSBinding pins AWS STS caller identities to one IAM role (HR-464).
type AWSBinding struct {
	AccountID string `json:"account_id"`
	RoleName  string `json:"role_name"`
}

// Validate checks the binding (HR-464, HR-140).
func (b AWSBinding) Validate() error {
	if !awsAccountID.MatchString(b.AccountID) || !awsRoleName.MatchString(b.RoleName) {
		return fmt.Errorf("%w: account_id must be 12 digits and role_name an IAM role name", ErrInvalidEntry)
	}
	return nil
}

// Widening lists what b accepts that prev did not (HR-141).
func (b AWSBinding) Widening(prev *AWSBinding) []string {
	switch {
	case prev == nil:
		return []string{"new trusted issuer entry"}
	case *prev != b:
		return []string{"account or role changed"}
	}
	return nil
}

// AWSCaller is what STS answered to a GetCallerIdentity request that
// PantherClaw checked and sent itself.
type AWSCaller struct {
	Account string
	Arn     string
	UserID  string
}

// MatchAWS applies the AWS preset (HR-464): the caller is a session of the
// pinned role in the pinned account. IAM users and federated users never
// match: only role sessions attest.
func MatchAWS(b AWSBinding, c AWSCaller) (Match, error) {
	if err := b.Validate(); err != nil {
		return Match{}, err
	}
	m := assumedRole.FindStringSubmatch(c.Arn)
	switch {
	case m == nil:
		return Match{}, rejected("caller %q is not a role session", c.Arn)
	case m[1] != c.Account || c.Account != b.AccountID:
		return Match{}, rejected("account")
	case m[2] != b.RoleName:
		return Match{}, rejected("role %q not pinned", m[2])
	}
	return Match{Binding: Binding{"account_id": c.Account, "role_name": m[2]}}, nil
}
