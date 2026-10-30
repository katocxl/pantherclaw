// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
)

// Errors of a per-dispatch AWS session. Each fails the dispatch before the
// action's request is sent (enforcement_failed).
var (
	// ErrAssumeRole: STS did not issue a session, or issued one this
	// gateway must not use (too long, already expired, malformed).
	ErrAssumeRole = errors.New("broker: STS did not issue a usable session")
	// ErrAWSAction: the operation names no single AWS action the session
	// policy could be narrowed to.
	ErrAWSAction = errors.New("broker: the operation names no AWS action to narrow the session to")
)

// stsVersion is the STS API version AssumeRole is called with.
const stsVersion = "2011-06-15"

// maxSessionSkew is how far past the 15 minutes a session's expiration may
// be, for clock skew between AWS and the gateway.
const maxSessionSkew = 2 * time.Minute

var (
	awsActionRe  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,127}$`)
	awsServiceRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
)

// AWSSession is a short-lived AWS session for one dispatch (G0 M20 D254,
// HR-525): temporary credentials from sts:AssumeRole, under a session
// policy that allows exactly one action, for at most 15 minutes. Sign
// signs a request with it, only for a host the credential is bound to.
// It is never cached or returned to the agent; Clear drops it.
type AWSSession struct {
	creds   sigv4.Credentials
	secret  []byte
	signer  sigv4.Signer
	hosts   []string
	expires time.Time
	policy  string
}

// Secret is the session's secret bytes, which a caller scrubs from what goes
// back to the agent; Clear clears them.
func (a *AWSSession) Secret() []byte { return a.secret }

// Expires is when the session ends.
func (a *AWSSession) Expires() time.Time { return a.expires }

// Policy is the session policy the session was narrowed to.
func (a *AWSSession) Policy() string { return a.policy }

// Clear overwrites the session secret and drops the credentials.
func (a *AWSSession) Clear() {
	clear(a.secret)
	a.creds = sigv4.Credentials{}
}

// Sign signs r, whose body is body, with the session, for the credential's
// bound hosts only (HR-060). Every header the package or the gateway set
// is signed; the SigV4 headers are the signer's alone (HR-526).
func (a *AWSSession) Sign(r *http.Request, body []byte, now time.Time) error {
	port := "443"
	if r.URL.Scheme == "http" {
		port = "80"
	}
	if !Bound(a.hosts, r.URL.Host, port) {
		return ErrNotBound
	}
	if a.creds.SecretAccessKey == "" || !now.Before(a.expires) {
		return ErrAssumeRole
	}
	return a.signer.Sign(r, a.creds, sigv4.HashPayload(body), now)
}

// SessionPolicy is the session policy of one action on one resource: Allow
// exactly "<service>:<action>" on resource, an ARN without wildcards, or
// "*" for a read (G0 M20 D270). A session's permissions are the
// intersection of the role's and this policy's, so it can never do more
// than this one action on this one resource (HR-525, T-225).
func SessionPolicy(service, action, resource string) (string, error) {
	if !awsActionRe.MatchString(action) || !awsServiceRe.MatchString(service) ||
		(resource != "*" && (!strings.HasPrefix(resource, "arn:") || !defs.ARNValueRe.MatchString(resource))) {
		return "", ErrAWSAction
	}
	b, err := json.Marshal(map[string]any{
		"Version":   "2012-10-17",
		"Statement": []map[string]any{{"Effect": "Allow", "Action": service + ":" + action, "Resource": resource}},
	}, json.Deterministic(true))
	return string(b), err
}

// AssumeRole signs an sts:AssumeRole of the credential's role with its base
// key and sends it through s (an egress client pinned to the STS host,
// which the seal must bind), with the session policy and the shortest
// duration AWS allows. STS's answer must carry a temporary key, secret and
// session token that expire within 15 minutes; anything else is refused.
// The base secret is used for this one signature only.
func AssumeRole(ctx context.Context, s Sender, hosts []string, c domain.AWSSigV4, policy string, now time.Time) (*AWSSession, error) {
	if c.Validate() != nil {
		return nil, domain.ErrAWSSigV4
	}
	u, _ := c.STS()
	port := "443"
	if u.Scheme == "http" {
		port = "80"
	}
	if !Bound(hosts, u.Host, port) {
		return nil, ErrNotBound
	}
	u.Path = "/"
	name := make([]byte, 8)
	_, _ = rand.Read(name)
	form := url.Values{
		"Action": {"AssumeRole"}, "Version": {stsVersion}, "RoleArn": {c.RoleARN}, "RoleSessionName": {"pantherclaw-" + hex.EncodeToString(name)},
		"DurationSeconds": {strconv.Itoa(domain.AWSSessionSeconds)}, "Policy": {policy},
	}
	if c.ExternalID != "" {
		form.Set("ExternalId", c.ExternalID)
	}
	body := []byte(form.Encode())
	req, err := s.HTTPRequest(ctx, egress.Request{Method: http.MethodPost, URL: u, Body: body, ContentType: "application/x-www-form-urlencoded; charset=utf-8"})
	if err != nil {
		return nil, err
	}
	base := sigv4.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: string(c.SecretAccessKey)}
	err = sigv4.Signer{Region: c.STSRegion, Service: "sts"}.Sign(req, base, sigv4.HashPayload(body), now)
	base = sigv4.Credentials{}
	if err != nil {
		return nil, errors.Join(ErrAssumeRole, err)
	}
	res, err := s.Do(req)
	if err != nil {
		return nil, errors.Join(ErrAssumeRole, err)
	}
	defer clear(res.Body)
	if res.Status != http.StatusOK || res.Truncated {
		return nil, ErrAssumeRole
	}
	var a struct {
		Result struct {
			Credentials struct {
				AccessKeyID     string `xml:"AccessKeyId"`
				SecretAccessKey string `xml:"SecretAccessKey"`
				SessionToken    string `xml:"SessionToken"`
				Expiration      string `xml:"Expiration"`
			} `xml:"Credentials"`
		} `xml:"AssumeRoleResult"`
	}
	d := xml.NewDecoder(bytes.NewReader(res.Body))
	d.Strict = true
	if err := d.Decode(&a); err != nil {
		return nil, ErrAssumeRole
	}
	cr := a.Result.Credentials
	exp, err := time.Parse(time.RFC3339, cr.Expiration)
	switch {
	case err != nil, !now.Before(exp), exp.After(now.Add(domain.AWSSessionSeconds*time.Second + maxSessionSkew)),
		!validToken(cr.AccessKeyID), !validToken(cr.SecretAccessKey), !validToken(cr.SessionToken):
		return nil, ErrAssumeRole
	}
	return &AWSSession{
		creds:  sigv4.Credentials{AccessKeyID: cr.AccessKeyID, SecretAccessKey: cr.SecretAccessKey, SessionToken: cr.SessionToken},
		secret: []byte(cr.SecretAccessKey), signer: sigv4.Signer{Region: c.Region, Service: c.Service},
		hosts: hosts, expires: exp, policy: policy,
	}, nil
}
