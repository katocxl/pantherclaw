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

// awsRestAction is the S3 action of an aws-rest template.
func awsRestAction(h *HTTPDispatch) (string, bool) {
	a, ok := awsRestActions[h.Method+" "+h.Subresource]
	return a, ok
}

// validateAWSRestDispatch checks an aws-rest template: a method and fixed
// subresource that name one S3 action, a path of exactly one reference (the
// bucket), no body fields, query or idempotency header, a body_param that is
// a content param, and header_params from the allowed headers to enum
// params.
func (d *Definition) validateAWSRestDispatch(at string, h *HTTPDispatch) error {
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
