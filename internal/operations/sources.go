// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package operations

import (
	"context"
	"errors"
	"time"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The queue's sources owned by other streams (G0 M10 D33, D49), read
// through ports the server wires. Each port reads under the caller in ctx
// and checks its own permission and edition. A nil port is reported as
// "not available"; a port that refuses the caller's permission as outside
// its permissions, and one refused by the edition as not in this edition:
// never as empty, and never as safe.

// ContainmentAction is a containment action not yet confirmed on every
// material path (response, D22).
type ContainmentAction struct {
	ID        ids.UUID
	Kind      string
	ScopeType string
	ScopeID   string
	Control   string
	// Status is REQUESTED, PARTIAL, FAILED or UNSUPPORTED.
	Status    string
	Requested time.Time
	Incident  *ids.UUID
	Case      *ids.UUID
}

// ContainmentReader lists unconfirmed containment actions: every unsettled
// one and those settled FAILED or UNSUPPORTED lately, newest first, and
// whether more exist than it returned (D69 M5).
type ContainmentReader interface {
	Unconfirmed(ctx context.Context) ([]ContainmentAction, bool, error)
}

// PostureFinding is an open posture finding (exposure, D30).
type PostureFinding struct {
	ID       ids.UUID
	Kind     string
	Title    string
	Severity string
	State    string
	Agent    *ids.UUID
	Since    time.Time
}

// FindingReader lists the open posture findings the caller may read.
type FindingReader interface {
	OpenFindings(ctx context.Context) ([]PostureFinding, error)
}

// ExportDestination is a SIEM export destination's delivery health
// (edges, D36).
type ExportDestination struct {
	ID            ids.UUID
	Name          string
	State         string
	Health        string
	LastDelivered *time.Time
	FailingSince  *time.Time
}

// ExportReader lists export destinations.
type ExportReader interface {
	Destinations(ctx context.Context) ([]ExportDestination, error)
}

// Sources are the ports; any may be nil.
type Sources struct {
	Containment ContainmentReader
	Findings    FindingReader
	Exports     ExportReader
}

// availability is how a port answered.
type availability string

const (
	available    availability = ""
	unavailable  availability = "not reported yet"
	restricted   availability = "outside your permissions"
	notInEdition availability = "not in this edition"
)

// availabilityOf classifies a port error: a refused permission or edition
// is a state to report, anything else a failure.
func availabilityOf(err error) (availability, error) {
	var e *pcerr.Error
	if !errors.As(err, &e) {
		return "", err
	}
	switch {
	case e.Code() == pcerr.PermissionDenied:
		return restricted, nil
	case e.Code() == pcerr.FailedPrecondition && e.Reason() == "EDITION_REQUIRED":
		return notInEdition, nil
	default:
		return "", err
	}
}

// external is what the ports returned for one request.
type external struct {
	containment          []ContainmentAction
	containmentState     availability
	containmentTruncated bool
	findings             []PostureFinding
	findingsState        availability
	exports              []ExportDestination
	exportsState         availability
}

// readSources reads every port under the caller in ctx.
func (s *Service) readSources(ctx context.Context) (external, error) {
	var out external
	var err error
	if s.Sources.Containment == nil {
		out.containmentState = unavailable
	} else if out.containment, out.containmentTruncated, err = s.Sources.Containment.Unconfirmed(ctx); err != nil {
		if out.containmentState, err = availabilityOf(err); err != nil {
			return external{}, err
		}
	}
	if s.Sources.Findings == nil {
		out.findingsState = unavailable
	} else if out.findings, err = s.Sources.Findings.OpenFindings(ctx); err != nil {
		if out.findingsState, err = availabilityOf(err); err != nil {
			return external{}, err
		}
	}
	if s.Sources.Exports == nil {
		out.exportsState = unavailable
	} else if out.exports, err = s.Sources.Exports.Destinations(ctx); err != nil {
		if out.exportsState, err = availabilityOf(err); err != nil {
			return external{}, err
		}
	}
	return out, nil
}

// notes lists the sources that did not report, for the queue and summary.
func (x external) notes() []string {
	var out []string
	add := func(name string, a availability) {
		if a != available {
			out = append(out, name+": "+string(a))
		}
	}
	add("unconfirmed containment", x.containmentState)
	add("posture findings", x.findingsState)
	return out
}
