// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package siem

import (
	"context"
	"strconv"
	"time"

	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
)

// Notifier enqueues notifications in the caller's transaction (M5).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// ReflexHealth reports failing delivery to Operations (D36, HR-260): an
// owned failure, a siem signal and a siem.delivery_failing notification,
// once per failing episode (the dedupe key carries when it began).
type ReflexHealth struct {
	Failures reflexports.FailureSink
	Raiser   reflexports.Raiser
	// Notify is optional.
	Notify Notifier
}

var _ HealthSink = ReflexHealth{}

// FailureKind is the owned failure kind of failing delivery.
const FailureKind = "siem.delivery_failing"

// DestinationSubject names a destination in signals and failures.
func DestinationSubject(f DeliveryFailure) reflexdomain.Subject {
	return reflexdomain.Subject{Type: reflexdomain.SubjectResource, ID: "siem_destination:" + f.Destination.String()}
}

// DeliveryFailing implements HealthSink.
func (h ReflexHealth) DeliveryFailing(ctx context.Context, tx db.TenantTx, f DeliveryFailure) error {
	subject := DestinationSubject(f)
	key := FailureKind + ":" + f.Destination.String() + ":" + strconv.FormatInt(f.Since.Unix(), 10)
	since := f.Since.UTC().Format(time.RFC3339)
	seq := strconv.FormatInt(f.HeldAt, 10)
	if h.Failures != nil {
		if _, err := h.Failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
			Org: f.Org, Kind: FailureKind,
			Summary:   "SIEM export to " + f.Name + " has failed " + strconv.Itoa(f.Failures) + " times in a row since " + since + " (" + f.Code + "); export is held at sequence " + seq + ".",
			NextStep:  "Check the receiver, then retry the destination; no event is skipped while it is held.",
			Scope:     []reflexdomain.Subject{subject},
			DedupeKey: key,
		}); err != nil {
			return err
		}
	}
	if h.Raiser != nil {
		if _, err := h.Raiser.Raise(ctx, tx.Pgx(), reflexdomain.Signal{
			Org: f.Org, Source: reflexdomain.SourceSIEM, Title: "SIEM export is failing",
			Summary:  "Destination " + f.Name + " has failed " + strconv.Itoa(f.Failures) + " times in a row since " + since + "; export is held at sequence " + seq + ".",
			Severity: reflexdomain.SeverityHigh, Attention: reflexdomain.AttentionAlert, Basis: reflexdomain.BasisObserved,
			Subjects: []reflexdomain.Subject{subject}, DedupeKey: key, GroupKey: subject.String(), OccurredAt: time.Now().UTC(),
			Facts: map[string]string{"destination": f.Destination.String(), "code": f.Code, "failures": strconv.Itoa(f.Failures), "held_at_seq": seq},
		}); err != nil {
			return err
		}
	}
	if h.Notify != nil {
		if _, err := h.Notify.Enqueue(ctx, tx, napp.Message{
			Org: f.Org, Type: FailureKind, DedupeKey: key,
			Params: map[string]string{"destination": f.Destination.String(), "code": f.Code, "failures": strconv.Itoa(f.Failures), "since": since, "seq": seq},
		}); err != nil {
			return err
		}
	}
	return nil
}
