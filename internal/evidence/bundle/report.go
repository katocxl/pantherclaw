// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"encoding/json/v2"
	"fmt"
	"strings"
)

// Status is the outcome of one check.
type Status string

// Check outcomes (HR-196).
const (
	Passed       Status = "passed"
	Failed       Status = "failed"
	NotAvailable Status = "not_available"
)

// ReportFormat is the format identifier of a JSON report.
const ReportFormat = "pantherclaw.verify-report/v1"

// Limits is the fixed statement every report ends with (G0 M7 design
// decision 13, F510, F511).
const Limits = "What passed shows the integrity of the evidence in this bundle: it was issued by the holder of the keys you pinned " +
	"and has not been changed since. It does not show that the bundle is complete, that an external effect happened, " +
	"or that anything is certified."

// Check is one verification check.
type Check struct {
	Name    string `json:"check"`
	Subject string `json:"subject,omitzero"`
	Status  Status `json:"status"`
	Detail  string `json:"detail"`
}

// Report lists every check, in order, with the overall result: failed if
// any check failed, passed otherwise (checks that were not available are
// listed, never counted as passed).
type Report struct {
	Format string  `json:"format"`
	Result Status  `json:"result"`
	Checks []Check `json:"checks"`
	Limits string  `json:"limits"`
	// notFull: a range pack whose receipts are not all in the pack.
	notFull bool
}

// RangeNotFullyVerifiable reports a range pack some of whose receipts are
// not in the pack: what it holds verifies, but the report cannot be
// re-derived in full. A baseline gate must refuse such a pack.
func (r *Report) RangeNotFullyVerifiable() bool { return r.notFull }

func newReport() *Report { return &Report{Format: ReportFormat, Result: Passed, Limits: Limits} }

func (r *Report) add(name, subject string, s Status, format string, args ...any) {
	r.Checks = append(r.Checks, Check{Name: name, Subject: subject, Status: s, Detail: fmt.Sprintf(format, args...)})
	if s == Failed {
		r.Result = Failed
	}
}

// Failed reports whether any check failed.
func (r *Report) Failed() bool { return r.Result == Failed }

// Count returns how many checks had status s.
func (r *Report) Count(s Status) int {
	n := 0
	for _, c := range r.Checks {
		if c.Status == s {
			n++
		}
	}
	return n
}

// Invalid returns the report of an input that could not be decoded.
func Invalid(err error) *Report {
	r := newReport()
	r.add("bundle.format", "", Failed, "%v", err)
	return r
}

// JSON returns the report as JSON.
func (r *Report) JSON() ([]byte, error) { return json.Marshal(r) }

// Text returns the report for people: one line per check, a summary and the
// limits.
func (r *Report) Text() string {
	var b strings.Builder
	for _, c := range r.Checks {
		subject := ""
		if c.Subject != "" {
			subject = " [" + c.Subject + "]"
		}
		fmt.Fprintf(&b, "%-13s %s%s: %s\n", strings.ToUpper(strings.ReplaceAll(string(c.Status), "_", " ")), c.Name, subject, c.Detail)
	}
	fmt.Fprintf(&b, "\nResult: %s (%d passed, %d failed, %d not available)\n\n%s\n",
		strings.ToUpper(string(r.Result)), r.Count(Passed), r.Count(Failed), r.Count(NotAvailable), r.Limits)
	return b.String()
}
