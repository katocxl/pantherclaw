// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"maps"
	"regexp"
	"slices"
	"strings"
)

// S3's REST protocol, aws-rest (G0 M30 D934a). The operation is fixed by the
// signed package: its method and its subresource, sent as the whole query,
// name exactly one S3 action, and the session is narrowed to it on the
// bucket's ARN (HR-525). The path names the bucket; the body is one content
// param sent as is; headers come from enum params, never from the agent's
// own fields.

const methodPut = "PUT"

// S3BucketRe is an S3 bucket name an aws-rest path segment may carry.
var S3BucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// AWSRestBodyType is the media type of an aws-rest raw body.
const AWSRestBodyType = "application/json"

// awsRestActions are the S3 actions an aws-rest method and subresource name.
var awsRestActions = map[string]string{
	methodPut + " policy": "PutBucketPolicy",
	methodPut + " acl":    "PutBucketAcl",
}

// awsRestHeaders are the headers an aws-rest template may send from an enum
// param.
var awsRestHeaders = []string{"x-amz-acl"}

// awsRestRoutes are the aws-rest reads keyed by method and exact path
// template, trailing "/" kept (G0 M34 D993a): the Amazon Bedrock AgentCore
// control plane's lists. They are reads only, with no aws_resource (so the
// session's resource is "*"), and take JSON body fields and query by the
// normal rules; no subresource, body_param or header_params.
var awsRestRoutes = map[string]string{
	methodPost + " /runtimes/":                    "ListAgentRuntimes",
	methodGet + " /gateways/":                     "ListGateways",
	methodGet + " /gateways/{target.id}/targets/": "ListGatewayTargets",
}

// awsRestAction is the action of an aws-rest template: an S3 action named by
// its method and subresource, or a route's.
func awsRestAction(h *HTTPDispatch) (string, bool) {
	if h.Subresource == "" {
		a, ok := awsRestRoutes[h.Method+" "+h.Path]
		return a, ok
	}
	a, ok := awsRestActions[h.Method+" "+h.Subresource]
	return a, ok
}

// AWSRestS3 reports whether an aws-rest template is one of S3's, whose path
// segment is a bucket name (G0 M30 D934a), rather than a route of the route
// table (G0 M34 D993a).
func AWSRestS3(h *HTTPDispatch) bool {
	return h.Encoding == EncodingAWSRest && h.Subresource != ""
}

// validateAWSRestRoute checks an aws-rest template of the route table.
func (d *Definition) validateAWSRestRoute(at string, h *HTTPDispatch) error {
	if _, ok := awsRestRoutes[h.Method+" "+h.Path]; !ok {
		return invalid("%s: aws-rest without a subresource is one of the listed routes", at)
	}
	switch {
	case d.Access != AccessRead:
		return invalid("%s: an aws-rest route is a read", at)
	case h.AWSResource != "", h.BodyParam != "", len(h.HeaderParams) > 0, h.IdempotencyHeader != "":
		return invalid("%s: an aws-rest route has no aws_resource, body_param, header_params or idempotency header", at)
	}
	return nil
}

// validateAWSRestDispatch checks an aws-rest template: a method and fixed
// subresource that name one S3 action, a path of exactly one reference (the
// bucket), no body fields, query or idempotency header, a body_param that is
// a content param, and header_params from the allowed headers to enum
// params.
func (d *Definition) validateAWSRestDispatch(at string, h *HTTPDispatch) error {
	if h.Subresource == "" {
		return d.validateAWSRestRoute(at, h)
	}
	if _, ok := awsRestAction(h); !ok {
		return invalid("%s: aws-rest is a PUT with subresource policy or acl", at)
	}
	segs := strings.Split(strings.TrimPrefix(h.Path, "/"), "/")
	if len(segs) != 1 || !strings.HasPrefix(segs[0], "{") || strings.HasSuffix(segs[0], "*}") {
		return invalid("%s.path: aws-rest names the bucket in one reference segment", at)
	}
	if len(h.Body) > 0 || len(h.Query) > 0 || h.IdempotencyHeader != "" {
		return invalid("%s: aws-rest sends no body fields, query or idempotency header", at)
	}
	if err := d.validateAWSResource(at, h.AWSResource); err != nil {
		return err
	}
	if h.BodyParam != "" {
		if p, ok := d.Params[h.BodyParam]; !ok || p.Type != TypeContent {
			return invalid("%s.body_param: %q must name a content param", at, h.BodyParam)
		}
	}
	if len(h.HeaderParams) > maxStaticHeaders {
		return invalid("%s.header_params: at most %d", at, maxStaticHeaders)
	}
	for _, name := range slices.Sorted(maps.Keys(h.HeaderParams)) {
		header := h.HeaderParams[name]
		if p, ok := d.Params[name]; !ok || p.Type != TypeEnum || !slices.Contains(awsRestHeaders, header) {
			return invalid("%s.header_params.%s: an enum param sent as one of %v", at, name, awsRestHeaders)
		}
	}
	return nil
}
