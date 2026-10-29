// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
)

// awsCredentials are the role session credentials pclaw signs with, from
// the standard environment variables (for example `aws configure
// export-credentials --format env`).
type awsCredentials struct {
	accessKey, secretKey, sessionToken, region string
}

func awsFromEnv(a *app) (awsCredentials, error) {
	get := func(k string) string { v, _ := a.env(k); return strings.TrimSpace(v) }
	c := awsCredentials{
		accessKey: get("AWS_ACCESS_KEY_ID"), secretKey: get("AWS_SECRET_ACCESS_KEY"), sessionToken: get("AWS_SESSION_TOKEN"),
		region: get("AWS_REGION"),
	}
	if c.region == "" {
		c.region = get("AWS_DEFAULT_REGION")
	}
	if c.accessKey == "" || c.secretKey == "" {
		return c, errors.New("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set (try aws configure export-credentials --format env)")
	}
	return c, nil
}

// awsAttestation signs an sts:GetCallerIdentity request for audience with
// SigV4 and encodes it, unsent: the server sends it to STS (D121). The
// regional endpoint is used when a region is set, the global one
// (us-east-1) otherwise.
func awsAttestation(c awsCredentials, audience string, now time.Time) (string, error) {
	host, region := "sts.amazonaws.com", "us-east-1"
	if c.region != "" {
		host, region = "sts."+c.region+".amazonaws.com", c.region
	}
	amzDate := now.UTC().Format("20060102T150405Z")
	headers := map[string]string{
		"content-type":           "application/x-www-form-urlencoded; charset=utf-8",
		"host":                   host,
		"x-amz-date":             amzDate,
		"x-pantherclaw-audience": audience,
	}
	if c.sessionToken != "" {
		headers["x-amz-security-token"] = c.sessionToken
	}
	auth := sigV4(c, region, "sts", "POST", "/", headers, issuers.AWSBody, amzDate)
	headers["authorization"] = auth
	return issuers.AWSRequest{Method: "POST", URL: "https://" + host + "/", Headers: headers, Body: issuers.AWSBody}.Encode()
}

// sigV4 returns the Authorization header value of a request with no query
// string whose headers (lower-case names) are all signed.
func sigV4(c awsCredentials, region, service, method, path string, headers map[string]string, body, amzDate string) string {
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	slices.Sort(names)
	var canon strings.Builder
	for _, k := range names {
		canon.WriteString(k + ":" + strings.Join(strings.Fields(headers[k]), " ") + "\n")
	}
	signed := strings.Join(names, ";")
	bodySum := sha256.Sum256([]byte(body))
	request := strings.Join([]string{method, path, "", canon.String(), signed, hex.EncodeToString(bodySum[:])}, "\n")
	reqSum := sha256.Sum256([]byte(request))
	scope := amzDate[:8] + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(reqSum[:])
	sig := hex.EncodeToString(hmacSHA256(awsSigningKey(c.secretKey, amzDate[:8], region, service), toSign))
	return "AWS4-HMAC-SHA256 Credential=" + c.accessKey + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + sig
}

// awsSigningKey derives the SigV4 signing key for one day, region and
// service.
func awsSigningKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
