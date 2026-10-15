// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"
	"time"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ExposureView is what the exposure port read for a built-in query: rows
// already filtered by the caller's exposure.read scope (D8), and how the
// snapshot they come from stands.
type ExposureView struct {
	Items []Item
	// Restricted: the caller's scope is narrower than the org.
	Restricted bool
	// ComputedAt is the snapshot's time; Stale marks a change recorded
	// since (ChangedAt).
	ComputedAt time.Time
	Stale      bool
	ChangedAt  *time.Time
	// Gaps are inputs the computation could not read.
	Gaps      []string
	Truncated bool
}

// ExposureReader reads the breach-radius views (exposure, D27, D28) under
// the caller in ctx, checking exposure.read and the edition itself.
type ExposureReader interface {
	// WhoCanWrite lists the current rights that write to a resource group
	// or through a connection, grant-constrained (EFFECTIVE) apart from
	// technical reach (CREDENTIAL) (F308).
	WhoCanWrite(ctx context.Context, resourceGroup string, connection *ids.UUID) (ExposureView, error)
	// Widest ranks the agents with the widest exposure by the explicit
	// keys consequence, scope, usability, enforceability, ownership and
	// remediation readiness (F313).
	Widest(ctx context.Context, limit int) (ExposureView, error)
}

// ErrExposureUnavailable reports a server without the exposure views: the
// question is not answered, never answered as empty.
var ErrExposureUnavailable = pcerr.New(pcerr.FailedPrecondition, "NOT_AVAILABLE",
	"breach radius is not available on this server")

// Exposure-backed built-in queries.
const (
	BuiltinWhoCanWrite    Builtin = "who_can_write"   // F308
	BuiltinWidestExposure Builtin = "widest_exposure" // F313
)

// widestLimit bounds a widest-exposure ranking.
const widestLimit = 50

func exposureBuiltin(b Builtin) bool {
	return b == BuiltinWhoCanWrite || b == BuiltinWidestExposure
}

// validateExposure checks an exposure-backed query's parameters.
func (b BuiltinQuery) validateExposure() error {
	allowed := map[Builtin][]string{BuiltinWhoCanWrite: {"resource", "connection"}, BuiltinWidestExposure: {}}
	for _, used := range b.Params.used() {
		ok := false
		for _, a := range allowed[b.Name] {
			ok = ok || a == used
		}
		if !ok {
			return ErrInvalidQuery("parameter " + used + " does not apply to " + string(b.Name))
		}
	}
	if b.Name == BuiltinWhoCanWrite {
		if b.Params.Resource == "" && b.Params.Connection == nil {
			return ErrInvalidQuery("resource or connection is required")
		}
		if len(b.Params.Resource) > maxTextLen || !printable(b.Params.Resource) {
			return ErrInvalidQuery("resource is malformed")
		}
	}
	return nil
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// runExposure answers an exposure-backed built-in query in one page.
func (s *Service) runExposure(ctx context.Context, b BuiltinQuery, pr page.Request) (Result, error) {
	if err := b.validateExposure(); err != nil {
		return Result{}, err
	}
	if !pr.After.IsZero() {
		return Result{}, page.ErrBadToken // one page
	}
	if s.Exposure == nil {
		return Result{}, ErrExposureUnavailable
	}
	var v ExposureView
	var err error
	if b.Name == BuiltinWhoCanWrite {
		v, err = s.Exposure.WhoCanWrite(ctx, b.Params.Resource, b.Params.Connection)
	} else {
		v, err = s.Exposure.Widest(ctx, widestLimit)
	}
	if err != nil {
		return Result{}, err
	}
	asOf := s.now()
	computed := v.ComputedAt
	out := Result{
		Items: v.Items, Count: len(v.Items), AsOf: asOf,
		Scope: Scope{Permission: td.PermExposureRead, All: !v.Restricted},
		Range: Range{End: &computed, Changing: v.Stale},
	}
	if v.Restricted {
		out.Omissions = append(out.Omissions, Omission{Code: omissionScopeLimited,
			Detail: "results cover only the agents where you hold " + string(td.PermExposureRead)})
	}
	if v.Stale {
		d := "computed at " + v.ComputedAt.UTC().Format(time.RFC3339) + "; authority changed since"
		if v.ChangedAt != nil {
			d += " " + v.ChangedAt.UTC().Format(time.RFC3339)
		}
		out.Omissions = append(out.Omissions, Omission{Code: "STALE", Detail: d})
	}
	for _, g := range v.Gaps {
		out.Omissions = append(out.Omissions, Omission{Code: "INPUT_GAP", Detail: g})
	}
	if v.Truncated {
		out.Omissions = append(out.Omissions, Omission{Code: "TRUNCATED", Detail: "the snapshot holds more rights than were computed"})
	}
	if len(out.Items) == 0 {
		out.Empty = EmptyNothingInScope
		if v.ComputedAt.IsZero() {
			out.Empty = EmptyNoDataCollected
		}
	}
	return out, nil
}
