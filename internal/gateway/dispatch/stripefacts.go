// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/stripefacts"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// CodeStripeLivemode: a Stripe answer reported livemode true; nothing is
// decided or sent, and the connection's circuit opens (HR-303, G0 M14 D54).
const CodeStripeLivemode = "stripe_livemode"

// stripeFactNames are the stripe.* facts an operation's prerequisites and
// its package's consequence rules name, in that order (G0 M14 D51).
func stripeFactNames(conn *control.Connection, def *defs.Definition) []string {
	var names []string
	add := func(n string) {
		if strings.HasPrefix(n, "stripe.") && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	for _, p := range def.Prerequisites {
		add(p.Fact)
	}
	for _, c := range conn.Package.Consequences {
		if c.Operation == def.Operation {
			for _, f := range c.RequiresFacts {
				add(f)
			}
		}
	}
	return names
}

// stripeFacts reads and reports the stripe.* facts an action needs before
// its decision, as reportGitHubFacts does for GitHub (D51); stop says the
// caller answers res without asking for a decision: the report failed, so
// the server may still hold a fresh earlier observation, or an answer was
// in live mode (D54).
func (e *Engine) stripeFacts(ctx context.Context, conn *control.Connection, a actionir.ActionIR, t *timer) (res Result, stop bool) {
	tried, unreported, live := e.reportStripeFacts(ctx, conn, a)
	if !tried {
		return Result{}, false
	}
	t.lap("facts")
	switch {
	case live:
		e.stripeLivemode(ctx, conn, "fact")
		return Result{Class: CannotAuthorize, Code: CodeStripeLivemode, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}, true
	case unreported != nil:
		return Result{Class: CannotAuthorize, Code: CodeFactsUnreported, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}, true
	}
	return Result{}, false
}

// reportStripeFacts reads the facts with the connection's static key,
// within the fact timeout, and reports them, every fact it could not read
// as unread. The key must match the definition's credential pattern before
// any read is sent (HR-301, HR-303).
func (e *Engine) reportStripeFacts(ctx context.Context, conn *control.Connection, a actionir.ActionIR) (tried bool, unreported error, live bool) {
	if e.reportFacts == nil || conn.Package == nil || conn.GetKind() != "http" {
		return false, nil, false
	}
	if k := conn.Credential.GetKind(); k != "" && k != credentials.KindStatic {
		return false, nil, false
	}
	def, ok := conn.Package.Definition(a.Operation)
	if !ok {
		return false, nil, false
	}
	names := stripeFactNames(conn, def)
	if len(names) == 0 {
		return false, nil, false
	}
	read, cancel := context.WithTimeout(ctx, e.factTimeout)
	defer cancel()
	observed := time.Now()
	var obs []*pb.FactObservation
	add := func(name string, value map[string]any) {
		raw, err := json.Marshal(map[string]any{"object": value}, json.Deterministic(true))
		if err == nil {
			obs = append(obs, &pb.FactObservation{
				Name: name, SubjectType: a.Target.Type, SubjectId: a.Target.ID, Value: raw, ObserveTime: timestamppb.New(observed),
			})
		}
	}
	var reasons map[string]string
	report := func(why string) {
		for _, n := range names {
			if !slices.ContainsFunc(obs, func(o *pb.FactObservation) bool { return o.GetName() == n }) {
				reason := why
				if r, ok := reasons[n]; ok {
					reason = r
				}
				add(n, stripefacts.UnreadFact(reason))
			}
		}
		if err := e.reportFacts(ctx, conn.GetId(), obs); err != nil {
			e.log.WarnContext(ctx, "gateway.facts_not_reported", slog.String("connection_id", conn.GetId()),
				slog.String("operation", a.Operation), pclog.Err(err))
			unreported = err
		}
	}
	get, release, err := e.stripeGetter(ctx, conn, def)
	if err != nil {
		e.log.WarnContext(ctx, "gateway.facts_unavailable", slog.String("connection_id", conn.GetId()),
			slog.String("operation", a.Operation), pclog.Err(err))
		report("no Stripe client or key")
		return true, unreported, false
	}
	defer release()
	var facts []stripefacts.Fact
	facts, reasons, live = stripefacts.ReadAll(read, get, a.Target.ID, names, observed)
	for _, f := range facts {
		add(f.Name, f.Value)
	}
	report("not read from Stripe")
	return true, unreported, live
}

// stripeGetter is a fact read's Getter: GET at the connection's base URL
// through its egress client, with Stripe-Version pinned and the opened key
// placed, once it matches def's credential pattern. release clears the key.
func (e *Engine) stripeGetter(ctx context.Context, conn *control.Connection, def *defs.Definition) (stripefacts.Getter, func(), error) {
	c, err := e.client(conn)
	if err != nil {
		return nil, nil, err
	}
	plain, err := e.openStatic(ctx, conn)
	if err != nil {
		return nil, nil, err
	}
	if def.Dispatch == nil || def.Dispatch.CredentialPattern == "" || !def.Dispatch.CredentialMatches(plain) {
		clear(plain)
		return nil, nil, errCredentialPattern
	}
	base := strings.TrimSuffix(conn.GetBaseUrl(), "/")
	get := func(ctx context.Context, path, account string) (egress.Response, error) {
		u, err := url.Parse(base + path)
		if err != nil {
			return egress.Response{}, err
		}
		req, err := c.HTTPRequest(ctx, egress.Request{Method: http.MethodGet, URL: u})
		if err != nil {
			return egress.Response{}, err
		}
		req.Header.Set("User-Agent", "pantherclaw-gateway")
		req.Header.Set("Stripe-Version", stripefacts.APIVersion)
		if account != "" {
			req.Header.Set("Stripe-Account", account)
		}
		if err := placeCredential(conn, req, plain); err != nil {
			return egress.Response{}, err
		}
		return c.Do(req)
	}
	return get, func() { clear(plain) }, nil
}
