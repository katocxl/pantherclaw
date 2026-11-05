// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadclient

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
)

// AWSCredentials are the role session credentials an aws_iam attestation is
// signed with (pclaw's --aws, and the AgentCore interceptor's Lambda role,
// G0 M34 D995).
type AWSCredentials struct {
	AccessKey, SecretKey, SessionToken, Region string
}

// AWSAttestation signs an sts:GetCallerIdentity request for audience with
// SigV4 and encodes it, unsent: the server sends it to STS (D121). The
// regional endpoint is used when a region is set, the global one
// (us-east-1) otherwise.
func AWSAttestation(c AWSCredentials, audience string, now time.Time) (string, error) {
	host, region := "sts.amazonaws.com", "us-east-1"
	if c.Region != "" {
		host, region = "sts."+c.Region+".amazonaws.com", c.Region
	}
	amzDate := now.UTC().Format("20060102T150405Z")
	headers := map[string]string{
		"content-type":           "application/x-www-form-urlencoded; charset=utf-8",
		"host":                   host,
		"x-amz-date":             amzDate,
		"x-pantherclaw-audience": audience,
	}
	if c.SessionToken != "" {
		headers["x-amz-security-token"] = c.SessionToken
	}
	auth := awsSigV4(c, region, "sts", http.MethodPost, "/", headers, issuers.AWSBody, amzDate)
	headers["authorization"] = auth
	return issuers.AWSRequest{Method: http.MethodPost, URL: "https://" + host + "/", Headers: headers, Body: issuers.AWSBody}.Encode()
}

// awsSigV4 returns the Authorization header value of a request with no
// query string whose headers (lower-case names) are all signed.
func awsSigV4(c AWSCredentials, region, service, method, path string, headers map[string]string, body, amzDate string) string {
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
	sig := hex.EncodeToString(awsHMAC(AWSSigningKey(c.SecretKey, amzDate[:8], region, service), toSign))
	return "AWS4-HMAC-SHA256 Credential=" + c.AccessKey + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + sig
}

// AWSSigningKey derives the SigV4 signing key for one day, region and
// service.
func AWSSigningKey(secret, date, region, service string) []byte {
	k := awsHMAC([]byte("AWS4"+secret), date)
	k = awsHMAC(k, region)
	k = awsHMAC(k, service)
	return awsHMAC(k, "aws4_request")
}

func awsHMAC(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
