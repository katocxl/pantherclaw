// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"cmp"
	"context"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	covapp "github.com/katocxl/pantherclaw/internal/coverage/app"
	covdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// CoveragePath is the coverage pages' path (G0 M9; F329, F439, F021).
const CoveragePath = "/coverage"

// Coverage reads coverage records (coverage/app.Service).
type Coverage interface {
	ListCoverage(ctx context.Context, f covapp.Filter, size int32, token string) ([]covapp.Record, string, error)
	GetCoverage(ctx context.Context, sc covdomain.Scope) (covapp.Record, error)
	ListSnapshots(ctx context.Context, sc covdomain.Scope, size int32, token string) ([]covapp.SnapshotRecord, string, error)
}

// WithCoverage adds the coverage pages, which only read; call it before
// Mount.
func (h *Handler) WithCoverage(c Coverage, f covdomain.Freshness) *Handler {
	h.coverage, h.freshness = c, f
	return h
}

func (h *Handler) mountCoverage(m *http.ServeMux) {
	if h.coverage == nil {
		return
	}
	h.withSession(m, http.MethodGet, CoveragePath, h.coverageList)
	h.withSession(m, http.MethodGet, CoveragePath+"/{agent}/{connection}/{operation}", h.coverageCard)
}

// coverageRow is one record on the list, or the card's header.
type coverageRow struct {
	Agent, Connection, Operation string
	// State is what the record reads now; Computed what its snapshot
	// computed, shown when a lapse or a change downgraded it.
	State, Computed, Class string
	Snapshot, Expires      string
	Link                   string
}

type routeRow struct {
	Name, Status, Class, Evidence string
}

// changeRow is one difference between the last two snapshots.
type changeRow struct {
	What, Before, After string
}

type exclusionRow struct {
	Scope, By, Until, Reason string
}

type coverageView struct {
	page
	Rows      []coverageRow
	Next      string
	Card      *coverageRow
	Reasons   []string
	Routes    []routeRow
	LastValid string
	Lapse     string
	Excluded  []exclusionRow
	// Changes compare the last two snapshots: Before and After are when
	// they were computed.
	Changes       []changeRow
	Before, After string
	TTL           string
	Kinds         string
}

// stateClass is the CSS class of a state: only ENFORCED reads as safe.
func stateClass(s covdomain.State) string {
	if s == covdomain.Enforced {
		return "ok"
	}
	if s == covdomain.Unknown {
		return "alert"
	}
	return "note"
}

func rowOf(r covapp.Record) coverageRow {
	row := coverageRow{
		Agent: r.Scope.Agent.String(), Connection: r.Scope.Connection.String(), Operation: r.Scope.Operation,
		State: r.State.String(), Class: stateClass(r.State),
	}
	if r.Computed != r.State {
		row.Computed = r.Computed.String()
	}
	row.Link = CoveragePath + "/" + url.PathEscape(row.Agent) + "/" + url.PathEscape(row.Connection) + "/" +
		url.PathEscape(row.Operation)
	if s := r.Snapshot; s != nil {
		row.Snapshot = s.ComputedAt.UTC().Format(pageTime)
		if s.ExpiresAt != nil && r.State == covdomain.Enforced {
			row.Expires = s.ExpiresAt.UTC().Format(pageTime)
		}
	}
	return row
}

func (h *Handler) coverageDenied(w http.ResponseWriter, title string) {
	h.renderAny(w, http.StatusNotFound, "error.html", page{
		Title: title, Message: "This coverage record does not exist, or you cannot see it: coverage needs the coverage.read permission.",
	})
}

// coverageList shows the current record of every scope the person may
// read.
func (h *Handler) coverageList(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	recs, next, err := h.coverage.ListCoverage(callerContext(r, s), covapp.Filter{}, 100, r.URL.Query().Get("page"))
	switch {
	case pcerr.CodeOf(err) == pcerr.PermissionDenied || pcerr.CodeOf(err) == pcerr.InvalidArgument:
		h.coverageDenied(w, "Coverage")
		return
	case err != nil:
		h.fail(w, r, err)
		return
	}
	v := coverageView{page: page{Title: "Coverage", Session: s}, TTL: h.freshness.EnforcedTTL.String()}
	for _, rec := range recs {
		v.Rows = append(v.Rows, rowOf(rec))
	}
	if next != "" {
		v.Next = CoveragePath + "?page=" + url.QueryEscape(next)
	}
	h.renderAny(w, http.StatusOK, "coverage_list.html", v)
}

// coverageCard shows one scope's record: its state now and why, every
// route, the last valid record, exclusions and the freshness contract.
func (h *Handler) coverageCard(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	agent, errA := ids.ParseUUID(r.PathValue("agent"))
	conn, errC := ids.ParseUUID(r.PathValue("connection"))
	if errA != nil || errC != nil {
		h.coverageDenied(w, "Coverage card")
		return
	}
	sc := covdomain.Scope{Agent: agent, Connection: conn, Operation: r.PathValue("operation")}
	rec, err := h.coverage.GetCoverage(callerContext(r, s), sc)
	switch {
	case pcerr.CodeOf(err) == pcerr.NotFound || pcerr.CodeOf(err) == pcerr.PermissionDenied:
		h.coverageDenied(w, "Coverage card")
		return
	case err != nil:
		h.fail(w, r, err)
		return
	}
	row := rowOf(rec)
	v := coverageView{page: page{Title: "Coverage card", Session: s}, Card: &row, TTL: h.freshness.EnforcedTTL.String()}
	for _, reason := range rec.Reasons {
		v.Reasons = append(v.Reasons, covdomain.Explain(reason))
	}
	routes := rec.Body.Routes
	if rec.Recomputed != nil {
		routes = covapp.RoutesOf(*rec.Recomputed)
	}
	for _, rt := range routes {
		class, evidence := "note", ""
		if rt.Status == string(covdomain.StatusMediated) || rt.Status == string(covdomain.StatusClosed) {
			class = "ok"
		}
		if rt.Closure != "" {
			evidence = "closure " + rt.Closure
		}
		v.Routes = append(v.Routes, routeRow{Name: routeName(rt), Status: strings.ReplaceAll(rt.Status, "_", " "), Class: class, Evidence: evidence})
	}
	if err := h.compare(callerContext(r, s), sc, &v); err != nil {
		h.fail(w, r, err)
		return
	}
	if lv := rec.LastValid; lv != nil {
		v.LastValid = lv.ID.String() + ", computed " + lv.ComputedAt.UTC().Format(pageTime)
		if rec.Recomputed != nil {
			v.Lapse = covdomain.Explain("lapsed:" + rec.Lapse)
		} else {
			v.Lapse = covdomain.Explain(rec.Lapse)
		}
	}
	for _, x := range rec.Exclusions {
		scope := "the whole scope"
		if x.RouteKind != nil {
			scope = "the " + strings.ReplaceAll(*x.RouteKind, "_", " ") + " route"
		}
		v.Excluded = append(v.Excluded, exclusionRow{
			Scope: scope, By: x.CreatedBy.String(), Until: x.ExpiresAt.UTC().Format(pageTime), Reason: x.Reason,
		})
	}
	var kinds []string
	for _, k := range covdomain.InvalidationKinds {
		if k.Invalidates() {
			kinds = append(kinds, strings.ReplaceAll(string(k), "_", " "))
		}
	}
	v.Kinds = strings.Join(kinds, ", ")
	h.renderAny(w, http.StatusOK, "coverage_card.html", v)
}

func routeName(rt covapp.SnapshotRoute) string {
	name := strings.ReplaceAll(rt.Kind, "_", " ")
	if rt.Channel != "" {
		name += " (" + rt.Channel + ")"
	}
	if rt.Locator != "" {
		name += " " + rt.Locator
	}
	return name
}

// compare fills the before-and-after comparison of the scope's last two
// snapshots: the state and every route whose status changed, appeared or
// went away.
func (h *Handler) compare(ctx context.Context, sc covdomain.Scope, v *coverageView) error {
	snaps, _, err := h.coverage.ListSnapshots(ctx, sc, 2, "")
	if err != nil || len(snaps) < 2 {
		return err
	}
	after, before := snaps[0], snaps[1]
	v.Before, v.After = before.ComputedAt.UTC().Format(pageTime), after.ComputedAt.UTC().Format(pageTime)
	if before.State != after.State {
		v.Changes = append(v.Changes, changeRow{What: "state", Before: before.State, After: after.State})
	}
	status := func(s covapp.SnapshotRecord) map[string]string {
		m := map[string]string{}
		for _, rt := range s.Body.Routes {
			m[routeName(rt)] = strings.ReplaceAll(rt.Status, "_", " ")
		}
		return m
	}
	b, a := status(before), status(after)
	names := slices.Sorted(maps.Keys(a))
	for _, n := range slices.Sorted(maps.Keys(b)) {
		if _, ok := a[n]; !ok {
			names = append(names, n)
		}
	}
	for _, n := range names {
		if b[n] != a[n] {
			v.Changes = append(v.Changes, changeRow{What: n, Before: cmp.Or(b[n], "absent"), After: cmp.Or(a[n], "absent")})
		}
	}
	return nil
}
