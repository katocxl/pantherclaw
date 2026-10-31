// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// validateMatchHeaders checks an http mapping's fixed match headers (G0
// M20 D254, HR-526): at most maxStaticHeaders, each an unreserved header
// with a literal value, as a dispatch template's static headers are. An
// aws-json mapping must match its operation's X-Amz-Target, since every
// aws-json operation shares POST /.
func validateMatchHeaders(at string, m Mapping) error {
	if len(m.Headers) > maxStaticHeaders {
		return invalid("%s.headers: at most %d", at, maxStaticHeaders)
	}
	for _, name := range slices.Sorted(maps.Keys(m.Headers)) {
		lower := strings.ToLower(name)
		if !headerRe.MatchString(name) || slices.Contains(reservedHeaders, lower) || strings.HasPrefix(lower, "pap-") ||
			strings.HasPrefix(lower, "pc-") || !staticHeaderRe.MatchString(m.Headers[name]) ||
			slices.ContainsFunc(slices.Collect(maps.Keys(m.Headers)), func(o string) bool { return o != name && strings.EqualFold(o, name) }) {
			return invalid("%s.headers: %q must be a distinct unreserved header with a literal value of 1..128 printable ASCII characters", at, name)
		}
	}
	if m.Encoding == EncodingAWSJSON && !slices.ContainsFunc(slices.Collect(maps.Keys(m.Headers)), func(k string) bool { return strings.EqualFold(k, AWSTargetHeader) }) {
		return invalid("%s: an aws-json mapping matches its operation's %s", at, AWSTargetHeader)
	}
	return nil
}

// matchKey is a mapping's match headers in a canonical form, for the
// package's duplicate-route check.
func matchKey(h map[string]string) string {
	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(h)) {
		b.WriteString(" " + strings.ToLower(name) + "=" + h[name])
	}
	return b.String()
}

// validateAWSDispatch checks an aws-json or aws-query template (G0 M20
// D254, HR-526): a POST to the service root whose operation is fixed by the
// signed package, never by the agent. An aws-json template names its
// operation in a literal X-Amz-Target header; an aws-query template in
// literal Action and Version body fields, and sends only scalar values
// (its flat form has no lists).
func (d *Definition) validateAWSDispatch(at string, h *HTTPDispatch) error {
	// aws-query may also be a GET with its operation in the query (a
	// connection test reads that way); aws-json is always a POST.
	get := h.Encoding == EncodingAWSQuery && h.Method == methodGet
	if (h.Method != methodPost && !get) || h.Path != RootPath {
		return invalid("%s: %s is a POST to %s (aws-query also a GET)", at, h.Encoding, RootPath)
	}
	if h.IdempotencyHeader != "" {
		return invalid("%s: %s carries an idempotency token in its body, never a header", at, h.Encoding)
	}
	if err := d.validateAWSResource(at, h.AWSResource); err != nil {
		return err
	}
	for _, k := range slices.Sorted(maps.Keys(h.Body)) {
		if strings.HasSuffix(k, "[]") && !strings.HasPrefix(h.Body[k], "target.") {
			return invalid("%s.body.%s: an aws-json list holds one value of the target", at, k)
		}
	}
	switch h.Encoding { //nolint:exhaustive // only called for the two AWS encodings
	case EncodingAWSJSON:
		if !slices.ContainsFunc(slices.Collect(maps.Keys(h.Headers)), func(k string) bool { return strings.EqualFold(k, AWSTargetHeader) }) {
			return invalid("%s: aws-json names its operation in a literal %s header", at, AWSTargetHeader)
		}
	case EncodingAWSQuery:
		named, where := h.Body, "body"
		if get {
			named, where = h.Query, "query"
		}
		for _, k := range []string{"Action", "Version"} {
			if !strings.HasPrefix(named[k], "literal.") {
				return invalid("%s.%s: aws-query names its operation in a literal %s", at, where, k)
			}
		}
		if !get && (h.Query["Action"] != "" || h.Query["Version"] != "") {
			return invalid("%s.query: a POST names its operation in its body only", at)
		}
		for _, k := range slices.Sorted(maps.Keys(h.Body)) {
			if strings.Contains(k, "[") {
				return invalid("%s.body.%s: aws-query is a flat form", at, k)
			}
			name, isParam := strings.CutPrefix(h.Body[k], "params.")
			if isParam && d.Params[name].Type == TypeIdentifierList {
				return invalid("%s.body.%s: aws-query sends no lists", at, k)
			}
		}
	}
	return nil
}

// AWSAction is the one AWS action an aws-json or aws-query dispatch names,
// fixed by the package (G0 M20 D254): the operation of its X-Amz-Target
// ("Service_Version.Operation"), or its literal Action. A session for the
// dispatch is narrowed to exactly this action (HR-525).
func (d *Definition) AWSAction() (string, bool) {
	if d.Dispatch == nil || d.Dispatch.HTTP == nil {
		return "", false
	}
	h := d.Dispatch.HTTP
	switch h.Encoding { //nolint:exhaustive // any other encoding names no AWS action
	case EncodingAWSJSON:
		for k, v := range h.Headers {
			if strings.EqualFold(k, AWSTargetHeader) {
				i := strings.LastIndexByte(v, '.')
				return v[i+1:], i >= 0 && i < len(v)-1
			}
		}
	case EncodingAWSQuery:
		ref := h.Body["Action"]
		if h.Method == methodGet {
			ref = h.Query["Action"]
		}
		a, ok := strings.CutPrefix(ref, "literal.")
		return a, ok && a != ""
	}
	return "", false
}

// The one POST verification read HR-190 allows (founder decisions D283,
// D290): its fixed X-Amz-Target, the only package that may declare it and
// the SigV4 service its session must be sealed for. The name is PantherClaw's
// reserved namespace, which an org key can neither sign nor import (HR-162),
// so a package's signature stands behind it.
const (
	ECSDescribeServicesTarget = "AmazonEC2ContainerServiceV20141113.DescribeServices"
	ECSPackage                = "pc.aws.ecs"
	ECSPublisher              = "pantherclaw"
	ECSSigningService         = "ecs"
)

// PostVerificationRead reports the shape of the one verification read that
// is not a GET (D283, D290): an aws-json access: read POST to the root whose
// only header is exactly ECSDescribeServicesTarget, with no query, no
// idempotency header and a body of nothing but the target, so its session is
// narrowed to that one action (D270) and only the target can vary. ECS has no
// GET. Package.VerificationRead also checks which package declares it.
func (d *Definition) PostVerificationRead() bool {
	if d.Access != AccessRead || d.Dispatch == nil || d.Dispatch.HTTP == nil {
		return false
	}
	h := d.Dispatch.HTTP
	if h.Method != methodPost || h.Path != RootPath || h.Encoding != EncodingAWSJSON || len(h.Query) > 0 ||
		h.IdempotencyHeader != "" || h.AWSResource != "" || h.Success != nil || len(h.Headers) != 1 || len(h.Body) == 0 {
		return false
	}
	for k, v := range h.Headers {
		if !strings.EqualFold(k, AWSTargetHeader) || v != ECSDescribeServicesTarget {
			return false
		}
	}
	for _, ref := range h.Body {
		if !strings.HasPrefix(ref, "target.") {
			return false
		}
	}
	return true
}

// VerificationRead reports whether a definition's HTTP dispatch has the shape
// of a verification read: an access: read GET, or the D283 exception
// (HR-190). A gateway asks the Package, which also knows who declared it.
func (d *Definition) VerificationRead() bool {
	if d.Access != AccessRead || d.Dispatch == nil || d.Dispatch.HTTP == nil {
		return false
	}
	return d.Dispatch.HTTP.Method == methodGet || d.PostVerificationRead()
}

// VerificationRead reports whether d, one of p's definitions, may be a
// verification read (HR-190): the POST exception only in pc.aws.ecs from
// pantherclaw, never in an org's package (D290).
func (p *Package) VerificationRead(d *Definition) bool {
	return d.VerificationRead() && (!d.PostVerificationRead() || (p.Name == ECSPackage && p.Publisher == ECSPublisher))
}

// The HTTP methods an AWS template uses, spelled here because domain
// packages stay free of net/http.
const (
	methodGet  = "GET"
	methodPost = "POST"
)

// AWS resource ARN template references (G0 M20 D270): besides the
// decision's target (target.id, target.id.<group>, target.account), the
// connection's own account, region and partition, which come from its
// sealed credential, never from the agent.
const (
	AWSRefAccount   = "aws.account"
	AWSRefRegion    = "aws.region"
	AWSRefPartition = "aws.partition"
)

var (
	// arnLiteralRe is a literal part of an ARN template: never a wildcard.
	arnLiteralRe = regexp.MustCompile(`^[A-Za-z0-9:/_.+=,@-]*$`)
	// ARNValueRe is a value substituted into an ARN: never a wildcard, so
	// no target can widen the resource a session may act on.
	ARNValueRe = regexp.MustCompile(`^[A-Za-z0-9:/_.+=,@-]{1,512}$`)
	arnRefRe   = regexp.MustCompile(`\{([^{}]*)\}`)
)

// validateAWSResource checks an aws template's resource ARN template: a
// write must have one (HR-525, T-225); it starts arn:, its literals hold
// no wildcard, and each reference is the target or the connection's
// account, region or partition.
func (d *Definition) validateAWSResource(at, t string) error {
	if t == "" {
		if d.Access == AccessWrite {
			return invalid("%s: an aws write names its resource in aws_resource (D270)", at)
		}
		return nil
	}
	if !strings.HasPrefix(t, "arn:") || len(t) > 512 || strings.Count(t, "{") != strings.Count(t, "}") {
		return invalid("%s.aws_resource: an ARN template of at most 512 bytes", at)
	}
	for _, lit := range arnRefRe.Split(t, -1) {
		if !arnLiteralRe.MatchString(lit) {
			return invalid("%s.aws_resource: literal %q (no wildcards)", at, lit)
		}
	}
	for _, m := range arnRefRe.FindAllStringSubmatch(t, -1) {
		switch ref := m[1]; {
		case ref == AWSRefAccount || ref == AWSRefRegion || ref == AWSRefPartition, ref == "target.id":
		case ref == "target.account":
			if d.Target.Account == PresenceNone {
				return invalid("%s.aws_resource: %s for a target without an account", at, ref)
			}
		case strings.HasPrefix(ref, "target.id."):
			if !d.Target.hasPart(strings.TrimPrefix(ref, "target.id.")) {
				return invalid("%s.aws_resource: %s names no group of target.id_pattern", at, ref)
			}
		default:
			return invalid("%s.aws_resource: %q is not the target or the connection's account, region or partition", at, ref)
		}
	}
	return nil
}

// AWSResourceARN is the resource a session for an action on target is
// narrowed to (D270): the template with each reference substituted, or
// "*" for a read without one. A substituted value with a wildcard or a
// character outside an ARN's, or a missing part, builds nothing.
func (d *Definition) AWSResourceARN(target actionir.Target, account, region, partition string) (string, error) {
	t := ""
	if d.Dispatch != nil && d.Dispatch.HTTP != nil {
		t = d.Dispatch.HTTP.AWSResource
	}
	if t == "" {
		if d.Access == AccessWrite {
			return "", invalid("%s: an aws write without aws_resource", d.Operation)
		}
		return "*", nil
	}
	var err error
	out := arnRefRe.ReplaceAllStringFunc(t, func(m string) string {
		ref := m[1 : len(m)-1]
		var v string
		switch {
		case ref == AWSRefAccount:
			v = account
		case ref == AWSRefRegion:
			v = region
		case ref == AWSRefPartition:
			v = partition
		case ref == "target.id":
			v = target.ID
		case ref == "target.account":
			v = target.Account
		case strings.HasPrefix(ref, "target.id."):
			v, _ = d.Target.Part(target.ID, strings.TrimPrefix(ref, "target.id."))
		}
		if !ARNValueRe.MatchString(v) && err == nil {
			err = invalid("%s: aws_resource %s has no usable value", d.Operation, ref)
		}
		return v
	})
	return out, err
}
