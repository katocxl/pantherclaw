// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"mime"
	"net/http"
	"slices"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// matchHeaders reports whether a request carries every fixed header of a
// mapping with exactly its value, once (G0 M20 D254). A header sent twice
// never matches: ambiguity is refused, never guessed (HR-300).
func matchHeaders(want map[string]string, got http.Header) bool {
	for name, v := range want {
		if vals := got.Values(name); len(vals) != 1 || vals[0] != v {
			return false
		}
	}
	return true
}

// decodeAWSJSON reads an aws-json body: an application/x-amz-json-1.0 or
// 1.1 media type, then the same strict JSON object any JSON mapping reads.
func decodeAWSJSON(contentType string, body []byte) (map[string]any, error) {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil || !slices.Contains(domain.AWSJSONContentTypes, mt) || len(params) > 0 {
		return nil, ambiguous("an aws-json body needs Content-Type %v", domain.AWSJSONContentTypes)
	}
	return DecodeInput(body)
}

// isRoot reports a template of the service root, which only an AWS
// protocol's mapping has.
func isRoot(tmpl []segment) bool {
	return len(tmpl) == 1 && tmpl[0] == (segment{})
}
