// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package awssts verifies AWS attestations (D121, HR-464): a workload's
// SigV4-signed sts:GetCallerIdentity request, checked by
// issuers.CheckAWSRequest and then sent to STS by PantherClaw through the
// egress client. STS answers with the caller's identity only if the
// signature is valid; nothing else of the request is trusted.
package awssts

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ErrUnverified wraps every reason STS did not vouch for a request.
var ErrUnverified = errors.New("awssts: request not verified")

// maxResponse bounds what STS may answer.
const maxResponse = 64 << 10

// defaultHost is the global and every regional STS endpoint in the aws
// partition.
var defaultHost = regexp.MustCompile(`^sts(\.[a-z]{2}(-[a-z]+)+-[0-9])?\.amazonaws\.com$`)

// Verifier sends checked GetCallerIdentity requests to STS.
type Verifier struct {
	client *http.Client
	hosts  []string // empty: defaultHost
	now    func() time.Time
}

// ValidateHosts checks the operator's identity.aws_sts_hosts.
func ValidateHosts(hosts []string) error {
	var errs []error
	for _, h := range hosts {
		if h == "" || strings.ContainsAny(h, "/:@?#* ") || h != strings.ToLower(h) {
			errs = append(errs, fmt.Errorf("aws sts host %q must be a lower-case host name", h))
		}
	}
	return errors.Join(errs...)
}

// New returns a verifier sending through client, which must be an egress
// client (httpx.NewEgressClient), to hosts (exact names), or to the global
// and regional sts.*.amazonaws.com endpoints when hosts is empty.
func New(client *http.Client, hosts []string, now func() time.Time) (*Verifier, error) {
	if err := ValidateHosts(hosts); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Verifier{client: client, hosts: hosts, now: now}, nil
}

// Allowed reports whether host is an STS endpoint the operator allows.
func (v *Verifier) Allowed(host string) bool {
	if len(v.hosts) == 0 {
		return defaultHost.MatchString(host)
	}
	return slices.Contains(v.hosts, host)
}

// Verify checks token for org, sends it to STS and returns who signed it,
// with the signing time and signature.
func (v *Verifier) Verify(ctx context.Context, org ids.OrgID, token string) (issuers.AWSCaller, issuers.AWSSigned, error) {
	r, err := issuers.ParseAWSRequest(token)
	if err != nil {
		return issuers.AWSCaller{}, issuers.AWSSigned{}, err
	}
	s, err := issuers.CheckAWSRequest(r, org, v.Allowed, v.now())
	if err != nil {
		return issuers.AWSCaller{}, s, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL.String(), strings.NewReader(issuers.AWSBody))
	if err != nil {
		return issuers.AWSCaller{}, s, err
	}
	for k, val := range r.Headers {
		if !strings.EqualFold(k, "Host") {
			req.Header.Set(k, val)
		}
	}
	// STS answers XML unless asked otherwise; never follow a redirect.
	req.Header.Set("Accept", "text/xml")
	client := *v.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return issuers.AWSCaller{}, s, fmt.Errorf("%w: sts: %w", ErrUnverified, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(body) > maxResponse {
		return issuers.AWSCaller{}, s, fmt.Errorf("%w: sts response unreadable or too large", ErrUnverified)
	}
	if resp.StatusCode != http.StatusOK {
		return issuers.AWSCaller{}, s, fmt.Errorf("%w: sts status %d", ErrUnverified, resp.StatusCode)
	}
	var out struct {
		XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ GetCallerIdentityResponse"`
		Result  struct {
			Arn     string `xml:"Arn"`
			UserID  string `xml:"UserId"`
			Account string `xml:"Account"`
		} `xml:"GetCallerIdentityResult"`
	}
	if err := xml.Unmarshal(body, &out); err != nil || out.Result.Arn == "" || out.Result.Account == "" {
		return issuers.AWSCaller{}, s, fmt.Errorf("%w: sts response is not a GetCallerIdentity result", ErrUnverified)
	}
	return issuers.AWSCaller{Account: out.Result.Account, Arn: out.Result.Arn, UserID: out.Result.UserID}, s, nil
}
