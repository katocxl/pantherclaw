// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package contentscan is the gateway's content scan (G0 M27 D503, D507, D512;
// F938; HR-649, HR-650): tool results and outbound bodies, at most 64 KiB
// each, stored nowhere. A finding is a kind and a location. The scan never
// decides anything: it reports to the Authority, which alone reads the org's
// mode and can only restrict.
//
// A scan that could not finish says so with a scan_incomplete finding and
// never reads as "no known flags": a body over the bound, a built-in failure
// and an out-of-process classifier that is down, slow or malformed. The
// built-in keeps running when the out-of-process classifier fails.
package contentscan

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/contentsignals/builtin"
	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	"github.com/katocxl/pantherclaw/internal/contentsignals/ports"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// DefaultTimeout bounds one call of the out-of-process classifier.
const DefaultTimeout = 250 * time.Millisecond

// Scanner scans bodies. The zero value runs the built-in only.
type Scanner struct {
	// Builtin is the built-in classifier; nil is builtin.Classifier.
	Builtin ports.ContentClassifier
	// External is the customer-run classifier; nil is none.
	External ports.ContentClassifier
	// Timeout bounds External; zero is DefaultTimeout.
	Timeout time.Duration
	Log     *slog.Logger
}

// Scan flags one body. It never returns an error: what it could not look at
// comes back as a finding.
func (s *Scanner) Scan(ctx context.Context, surface ports.Surface, location string, body []byte) []domain.Finding {
	if len(body) == 0 {
		return nil
	}
	var out []domain.Finding
	if len(body) > domain.MaxBody {
		out = append(out, incomplete(domain.IncompleteOverBound))
		body = body[:domain.MaxBody]
	}
	in := ports.Input{Surface: surface, Location: location, Content: body}
	var b ports.ContentClassifier = builtin.Classifier{}
	if s.Builtin != nil {
		b = s.Builtin
	}
	found, err := run(ctx, b, in)
	out = append(out, found...)
	if err != nil {
		s.warn(ctx, "gateway.content_scan_failed", err)
		out = append(out, incomplete(domain.IncompleteBuiltin))
	}
	if s.External != nil {
		cctx, cancel := context.WithTimeout(ctx, s.timeout())
		defer cancel()
		found, err := run(cctx, s.External, in)
		if err != nil {
			s.warn(ctx, "gateway.content_classifier_unavailable", err)
			out = append(out, incomplete(domain.IncompleteClassifier))
		}
		out = append(out, found...)
	}
	return domain.Pick(out)
}

func incomplete(why string) domain.Finding {
	return domain.Finding{Kind: domain.KindScanIncomplete, Location: why}
}

func (s *Scanner) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return DefaultTimeout
}

// warn logs a failure, by its error alone: no error here holds content, and
// nothing about the body is logged (HR-649).
func (s *Scanner) warn(ctx context.Context, msg string, err error) {
	if s.Log != nil {
		s.Log.WarnContext(ctx, msg, pclog.Err(err))
	}
}

// run calls a classifier, a panic counting as a failure, and keeps only
// findings that are valid: what is not well-formed is a failure too, so a
// classifier cannot pass a value off as a location.
func run(ctx context.Context, c ports.ContentClassifier, in ports.Input) (out []domain.Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("contentscan: classifier panicked")
		}
	}()
	found, err := c.Classify(ctx, in)
	for _, f := range found {
		if !f.Valid() {
			return out, fmt.Errorf("contentscan: malformed finding")
		}
		out = append(out, f)
	}
	return out, err
}
