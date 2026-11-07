// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"maps"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// MaxAWSExtraResources is how many exact ARNs an aws template may name
// beside aws_resource (G0 M34 D993a item 3, FQ34-4).
const MaxAWSExtraResources = 3

// validateAWSExtraResources checks an aws template's extra resources: at
// most MaxAWSExtraResources, only beside an aws_resource, distinct, and each
// checked as aws_resource is (HR-525).
func (d *Definition) validateAWSExtraResources(at string, h *HTTPDispatch) error {
	extra := h.AWSExtraResources
	if len(extra) == 0 {
		return nil
	}
	if h.AWSResource == "" || len(extra) > MaxAWSExtraResources {
		return invalid("%s.aws_extra_resources: at most %d, beside an aws_resource", at, MaxAWSExtraResources)
	}
	for i, t := range extra {
		if t == "" || t == h.AWSResource || slices.Contains(extra[:i], t) {
			return invalid("%s.aws_extra_resources[%d]: a distinct ARN template", at, i)
		}
		if err := d.validateAWSResource(at, t); err != nil {
			return err
		}
	}
	return nil
}

// validateAWSJSONLists checks an aws template's [] body keys: each holds
// one value of the target, and an aws-json body may also hold one command
// or content param under one [] key (G0 M34 D993a item 3: SSM's
// Parameters[commands][]).
func (d *Definition) validateAWSJSONLists(at string, h *HTTPDispatch) error {
	params := 0
	for _, k := range slices.Sorted(maps.Keys(h.Body)) {
		if !strings.HasSuffix(k, "[]") || strings.HasPrefix(h.Body[k], "target.") {
			continue
		}
		name, isParam := strings.CutPrefix(h.Body[k], "params.")
		p, ok := d.Params[name]
		if h.Encoding != EncodingAWSJSON || !isParam || !ok || (p.Type != TypeCommand && p.Type != TypeContent) {
			return invalid("%s.body.%s: an aws-json list holds one value of the target, or one command or content param", at, k)
		}
		if params++; params > 1 {
			return invalid("%s.body.%s: an aws-json body holds at most one param list", at, k)
		}
	}
	return nil
}

// AWSResourceARNs are the resources a session for an action on target is
// narrowed to (G0 M34 D993a item 3): AWSResourceARN's, then each extra
// resource substituted in order.
func (d *Definition) AWSResourceARNs(target actionir.Target, account, region, partition string) ([]string, error) {
	first, err := d.AWSResourceARN(target, account, region, partition)
	if err != nil {
		return nil, err
	}
	out := []string{first}
	if d.IsModel() || d.Dispatch == nil || d.Dispatch.HTTP == nil {
		return out, nil
	}
	extra := d.Dispatch.HTTP.AWSExtraResources
	if len(extra) > 0 && first == "*" {
		return nil, invalid("%s: aws_extra_resources without aws_resource", d.Operation)
	}
	for _, t := range extra {
		arn, err := d.awsARN(t, target, account, region, partition)
		if err != nil {
			return nil, err
		}
		out = append(out, arn)
	}
	return out, nil
}
