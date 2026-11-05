// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"errors"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
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
// signing is workloadclient's, shared with the AgentCore interceptor (G0
// M34 D995).
func awsAttestation(c awsCredentials, audience string, now time.Time) (string, error) {
	return workloadclient.AWSAttestation(workloadclient.AWSCredentials{
		AccessKey: c.accessKey, SecretKey: c.secretKey, SessionToken: c.sessionToken, Region: c.region,
	}, audience, now)
}

// awsSigningKey derives the SigV4 signing key for one day, region and
// service.
func awsSigningKey(secret, date, region, service string) []byte {
	return workloadclient.AWSSigningKey(secret, date, region, service)
}
