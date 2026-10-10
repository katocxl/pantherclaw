// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packbuild

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// txnFile is a transaction's file: everything the explorer shows of it.
// Receipts are compact JWS; the basis of a person's resolution is their
// untrusted text.
type txnFile struct {
	ID              string           `json:"id"`
	Run             string           `json:"run"`
	Agent           string           `json:"agent"`
	Operation       string           `json:"operation"`
	Connection      string           `json:"connection,omitzero"`
	Decision        string           `json:"decision"`
	Reason          string           `json:"reason,omitzero"`
	Execution       string           `json:"execution_state"`
	Effect          string           `json:"effect_state,omitzero"`
	Required        string           `json:"effect_level_required,omitzero"`
	Achieved        string           `json:"effect_level_achieved,omitzero"`
	Monitor         bool             `json:"monitor,omitzero"`
	Created         string           `json:"created_at"`
	Decisions       []decisionPart   `json:"decisions"`
	Dispatch        *executionPart   `json:"execution,omitzero"`
	Observations    []observation    `json:"observations,omitzero"`
	Effects         []effectPart     `json:"effects,omitzero"`
	Reconciliations []reconciliation `json:"reconciliations,omitzero"`
	Links           []link           `json:"links,omitzero"`
}

type decisionPart struct {
	Evaluation int    `json:"evaluation"`
	Receipt    string `json:"receipt,omitzero"`
	Seq        int64  `json:"seq,omitzero"`
	Created    string `json:"created_at"`
}

type executionPart struct {
	Outcome      string `json:"outcome"`
	TargetStatus int    `json:"target_status,omitzero"`
	RecordedBy   string `json:"recorded_by"`
	TargetRef    string `json:"target_ref,omitzero"`
	Dispatched   string `json:"dispatched_at,omitzero"`
	Recorded     string `json:"recorded_at"`
	Receipt      string `json:"receipt,omitzero"`
	Seq          int64  `json:"seq,omitzero"`
}

type observation struct {
	ID             string            `json:"id"`
	Source         string            `json:"source"`
	Gateway        string            `json:"gateway"`
	HTTPStatus     int               `json:"http_status"`
	Outcome        string            `json:"outcome"`
	Found          *bool             `json:"found,omitzero"`
	Complete       *bool             `json:"complete,omitzero"`
	Fields         map[string]string `json:"fields,omitzero"`
	ResponseDigest string            `json:"response_sha256,omitzero"`
	Observed       string            `json:"observed_at"`
}

type effectPart struct {
	Seq      int    `json:"seq"`
	State    string `json:"state"`
	Required string `json:"level_required,omitzero"`
	Achieved string `json:"level_achieved,omitzero"`
	Basis    string `json:"basis,omitzero"`
	Receipt  string `json:"receipt,omitzero"`
	Created  string `json:"created_at"`
}

type reconciliation struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	State    string `json:"state"`
	Via      string `json:"resolved_via,omitzero"`
	User     string `json:"user,omitzero"`
	Basis    string `json:"basis,omitzero"`
	Opened   string `json:"opened_at"`
	Resolved string `json:"resolved_at,omitzero"`
}

type link struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Kind    string `json:"kind"`
	Created string `json:"created_at"`
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func rfcp(t *time.Time) string {
	if t == nil {
		return ""
	}
	return rfc(*t)
}

// transaction adds one readable transaction: its file, its states in the
// manifest, and what it involves.
func (b *builder) transaction(ev txapp.Evidence) error {
	t := ev.Transaction
	receipts := b.r.include.Receipts
	f := txnFile{
		ID: t.ID.String(), Run: t.Run.String(), Agent: t.Agent.String(), Operation: t.Operation, Decision: t.Decision,
		Reason: t.Reason, Execution: string(t.Execution), Effect: string(t.Effect), Required: string(t.Required),
		Achieved: string(t.Achieved), Monitor: t.Monitor, Created: rfc(t.Created), Decisions: []decisionPart{},
	}
	if t.Connection != nil {
		f.Connection = t.Connection.String()
		b.connections[*t.Connection] = true
	}
	for _, d := range ev.Decisions {
		p := decisionPart{Evaluation: d.Evaluation, Seq: d.Integrity.Seq, Created: rfc(d.Created)}
		if receipts {
			p.Receipt = d.JWS
		}
		if d.JWS == "" {
			b.gap(fmt.Sprintf("transaction %s decision %d", t.ID, d.Evaluation), pack.GapRemoved, "the receipt's body was removed by retention")
		}
		f.Decisions = append(f.Decisions, p)
	}
	if x := ev.Execution; x != nil {
		f.Dispatch = &executionPart{
			Outcome: x.Outcome, TargetStatus: x.TargetStatus, RecordedBy: x.RecordedBy, TargetRef: x.TargetRef,
			Dispatched: rfcp(x.Dispatched), Recorded: rfc(x.Recorded), Seq: x.Integrity.Seq,
		}
		if receipts {
			f.Dispatch.Receipt = x.JWS
		}
	}
	for _, o := range ev.Observations {
		ob := observation{
			ID: o.ID.String(), Source: o.Source, Gateway: o.Gateway.String(), HTTPStatus: o.HTTPStatus, Outcome: o.Outcome,
			Found: o.Found, Complete: o.Complete, Fields: o.Fields, Observed: rfc(o.Observed),
		}
		if len(o.ResponseDigest) > 0 {
			ob.ResponseDigest = fmt.Sprintf("%x", o.ResponseDigest)
		}
		f.Observations = append(f.Observations, ob)
	}
	for _, e := range ev.Effects {
		p := effectPart{
			Seq: e.Seq, State: string(e.State), Required: string(e.Required), Achieved: string(e.Achieved), Basis: e.Basis,
			Created: rfc(e.Created),
		}
		if receipts {
			p.Receipt = e.JWS
		}
		f.Effects = append(f.Effects, p)
	}
	for _, k := range ev.Reconciliations {
		rc := reconciliation{
			ID: k.ID.String(), Kind: string(k.Kind), State: string(k.State), Via: string(k.Via), Basis: k.Basis,
			Opened: rfc(k.Opened), Resolved: rfcp(k.Resolved),
		}
		if k.User != nil {
			rc.User = k.User.String()
		}
		f.Reconciliations = append(f.Reconciliations, rc)
	}
	for _, l := range ev.Links {
		f.Links = append(f.Links, link{From: l.From.String(), To: l.To.String(), Kind: string(l.Kind), Created: rfc(l.Created)})
	}
	// An unknown outcome is an unknown effect until evidence resolves it
	// (F471, F528): never a success, never left out.
	if f.Effect == "" && f.Dispatch != nil && f.Dispatch.Outcome == "unknown" {
		f.Effect = "UNKNOWN"
	}
	if err := b.add("transactions/"+t.ID.String()+".json", pack.KindTransaction, f); err != nil {
		return err
	}
	effect := f.Effect
	if effect == "" {
		effect = "NONE_RECORDED"
	}
	b.m.EffectStates[effect]++
	st := pack.TransactionState{
		ID: f.ID, Operation: f.Operation, Decision: f.Decision, Execution: f.Execution, Effect: f.Effect,
		Required: f.Required, Achieved: f.Achieved, Monitor: f.Monitor,
	}
	if f.Dispatch != nil {
		st.Outcome = f.Dispatch.Outcome
	}
	b.m.Transactions = append(b.m.Transactions, st)
	b.txns = append(b.txns, ev)
	b.agents[t.Agent] = true
	if b.first.IsZero() || t.Created.Before(b.first) {
		b.first = t.Created
	}
	if t.Created.After(b.last) {
		b.last = t.Created
	}
	return nil
}

// receiptClaims reads what a decision receipt says it was made on. The
// receipt is the server's own stored record; `pclaw verify` checks its
// signature from the bundles.
type receiptClaims struct {
	Pap struct {
		Basis struct {
			Policy string `json:"policy"`
			Levels []struct {
				Kind     string `json:"kind"`
				ID       string `json:"id"`
				Revision int    `json:"revision"`
			} `json:"levels"`
			Definition string `json:"definition"`
		} `json:"basis"`
		Connection string `json:"connection"`
		Approval   *struct {
			Request string `json:"request"`
		} `json:"approval"`
	} `json:"pap"`
}

func claimsOf(jws string) (receiptClaims, bool) {
	var c receiptClaims
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return c, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, false
	}
	return c, json.Unmarshal(raw, &c) == nil
}

// versions lists the revisions every decision of the scope applied (F527).
func (b *builder) versions() error {
	v := &pack.Versions{}
	seenLevel := map[pack.Level]bool{}
	for _, ev := range b.txns {
		for _, d := range ev.Decisions {
			c, ok := claimsOf(d.JWS)
			if !ok {
				continue
			}
			v.Policies = appendNew(v.Policies, c.Pap.Basis.Policy)
			v.Definitions = appendNew(v.Definitions, c.Pap.Basis.Definition)
			v.Connections = appendNew(v.Connections, c.Pap.Connection)
			if c.Pap.Approval != nil {
				v.Approvals = appendNew(v.Approvals, c.Pap.Approval.Request)
			}
			for _, l := range c.Pap.Basis.Levels {
				lv := pack.Level{Kind: l.Kind, ID: l.ID, Revision: l.Revision}
				if !seenLevel[lv] {
					seenLevel[lv] = true
					v.Levels = append(v.Levels, lv)
				}
			}
		}
	}
	for _, s := range [][]string{v.Policies, v.Definitions, v.Connections, v.Approvals} {
		slices.Sort(s)
	}
	slices.SortFunc(v.Levels, func(x, y pack.Level) int {
		return strings.Compare(fmt.Sprintf("%s/%s/%09d", x.Kind, x.ID, x.Revision), fmt.Sprintf("%s/%s/%09d", y.Kind, y.ID, y.Revision))
	})
	b.m.Versions = v
	return b.add("versions.json", pack.KindVersions, v)
}

func appendNew(list []string, s string) []string {
	if s == "" || slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

// pathOf returns where agent lives, cached.
func (b *builder) pathOf(ctx context.Context, q *dbq.Queries, agent ids.UUID) (td.Path, error) {
	if p, ok := b.agentPaths[agent]; ok {
		return p, nil
	}
	a, err := q.GetAgent(ctx, b.org, agent)
	if err != nil {
		return nil, err
	}
	p, err := agents.PathOf(ctx, q, a)
	if err != nil {
		return nil, err
	}
	b.agentPaths[agent] = p
	return p, nil
}

type approvalRequest struct {
	ID          string             `json:"id"`
	Transaction string             `json:"transaction"`
	Evaluation  int32              `json:"evaluation"`
	Operation   string             `json:"operation"`
	State       string             `json:"state"`
	EndReason   string             `json:"end_reason,omitzero"`
	Created     string             `json:"created_at"`
	Deadline    string             `json:"deadline_at"`
	Approved    string             `json:"approved_at,omitzero"`
	Consumed    string             `json:"consumed_at,omitzero"`
	Ended       string             `json:"ended_at,omitzero"`
	Responses   []approvalResponse `json:"responses"`
}

type approvalResponse struct {
	ID          string `json:"id"`
	User        string `json:"user"`
	Kind        string `json:"kind"`
	Requirement *int16 `json:"requirement,omitzero"`
	Reason      string `json:"reason_code,omitzero"`
	Alternative string `json:"alternative_code,omitzero"`
	// Asserted: the response was made with a security-key assertion; the
	// assertion's bytes are not exported.
	Asserted bool   `json:"asserted"`
	Created  string `json:"created_at"`
	Voided   string `json:"voided_at,omitzero"`
	Void     string `json:"void_reason,omitzero"`
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// approvals adds the approval requests that held the scope's transactions
// and their responses, where the creator holds approval.read.
func (b *builder) approvals() error {
	var out []approvalRequest
	err := b.s.Pool.InTenantTx(b.ctx, b.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var readable []ids.UUID
		outside := 0
		for _, ev := range b.txns {
			p, err := b.pathOf(ctx, q, ev.Transaction.Agent)
			if err != nil {
				return err
			}
			if b.c.Can(td.PermApprovalRead, p) {
				readable = append(readable, ev.Transaction.ID)
			} else {
				outside++
			}
		}
		if outside > 0 {
			b.gap("approvals", pack.GapOutsidePermission, "the approvals of %d transactions are outside your approval.read", outside)
		}
		if len(readable) == 0 {
			return nil
		}
		reqs, err := q.PackApprovalRequests(ctx, b.org, readable)
		if err != nil {
			return err
		}
		reqIDs := make([]ids.UUID, 0, len(reqs))
		byID := map[ids.UUID]int{}
		for _, r := range reqs {
			byID[r.ID] = len(out)
			reqIDs = append(reqIDs, r.ID)
			a := approvalRequest{
				ID: r.ID.String(), Operation: r.Operation, State: r.State, EndReason: str(r.EndReason), Created: rfc(r.CreatedAt),
				Deadline: rfc(r.DeadlineAt), Approved: rfcp(r.ApprovedAt), Consumed: rfcp(r.ConsumedAt), Ended: rfcp(r.EndedAt),
				Responses: []approvalResponse{},
			}
			if r.TransactionID != nil {
				a.Transaction = r.TransactionID.String()
			}
			if r.Evaluation != nil {
				a.Evaluation = *r.Evaluation
			}
			out = append(out, a)
		}
		resps, err := q.PackApprovalResponses(ctx, b.org, reqIDs)
		if err != nil {
			return err
		}
		for _, r := range resps {
			i, ok := byID[r.RequestID]
			if !ok {
				continue
			}
			resp := approvalResponse{
				ID: r.ID.String(), User: r.UserID.String(), Kind: r.Kind, Reason: str(r.ReasonCode),
				Alternative: str(r.AlternativeCode), Asserted: r.Asserted, Created: rfc(r.CreatedAt), Voided: rfcp(r.VoidedAt),
				Void: str(r.VoidReason),
			}
			if r.Requirement.Valid {
				resp.Requirement = &r.Requirement.Int16
			}
			out[i].Responses = append(out[i].Responses, resp)
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	if out == nil {
		out = []approvalRequest{}
	}
	return b.add("approvals.json", pack.KindApprovals, out)
}

// window is the containment window: the scope's range when it has one,
// otherwise its transactions' times with a margin.
func (b *builder) window() (time.Time, time.Time, bool) {
	now := b.s.now()
	from, to := b.first.Add(-containmentMargin), b.last.Add(containmentMargin)
	if t, err := timeOf(b.r.scope.From); err == nil && t != nil {
		from = *t
	}
	if t, err := timeOf(b.r.scope.To); err == nil && t != nil {
		to = *t
	}
	if to.After(now) {
		to = now
	}
	return from, to, !b.first.IsZero() || b.r.scope.From != ""
}

type auditBody struct {
	Object *struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"object"`
}

// containment adds the containment and restoration events of the scope's
// agents and connections, and the org's kill switch, in its window (F529).
func (b *builder) containment() error {
	from, to, ok := b.window()
	events := []pack.Event{}
	if !ok {
		b.m.Containment = events
		return b.add("containment.json", pack.KindContainment, events)
	}
	err := b.s.Pool.InTenantTx(b.ctx, b.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		agentIDs := make([]ids.UUID, 0, len(b.agents))
		for a := range b.agents {
			agentIDs = append(agentIDs, a)
		}
		changes, err := q.PackAgentChanges(ctx, dbq.PackAgentChangesParams{
			OrgID: b.org, AgentIds: agentIDs, FromTime: from, ToTime: to, MaxRows: maxEvents,
		})
		if err != nil {
			return err
		}
		for _, c := range changes {
			events = append(events, pack.Event{Entry: c.ID.String(), Kind: c.Kind, At: rfc(c.CreatedAt), Object: "agent " + c.AgentID.String()})
		}
		if !b.c.Can(td.PermContainmentRead, td.OrgPath(b.org)) {
			b.gap("containment", pack.GapOutsidePermission,
				"connection quarantines and the kill switch need containment.read at org scope; only the agents' events are included")
			return nil
		}
		entries, err := q.PackContainmentEvents(ctx, dbq.PackContainmentEventsParams{
			OrgID: b.org, Kinds: orgEventKinds, FromTime: from, ToTime: to, MaxRows: maxEvents,
		})
		if err != nil {
			return err
		}
		for _, e := range entries {
			var body auditBody
			_ = json.Unmarshal(e.Body, &body)
			kind := strings.TrimPrefix(e.Kind, "audit.")
			object := ""
			if body.Object != nil {
				object = body.Object.Type + " " + body.Object.ID
				if body.Object.Type == "connection" {
					id, err := ids.ParseUUID(body.Object.ID)
					if err != nil || !b.connections[id] {
						continue
					}
				}
			}
			events = append(events, pack.Event{Entry: e.ID.String(), Kind: kind, At: rfc(e.OccurredAt), Object: object})
		}
		if len(changes) == maxEvents || len(entries) == maxEvents {
			b.gap("containment", pack.GapLimit, "more than %d events in the window: the pack holds the first ones", maxEvents)
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	slices.SortFunc(events, func(x, y pack.Event) int { return strings.Compare(x.At+x.Entry, y.At+y.Entry) })
	b.m.Containment = events
	return b.add("containment.json", pack.KindContainment, events)
}

// proofs adds verify bundles of the readable transactions, 50 at a time:
// their receipts, chained ledger entries, inclusion proofs to the latest
// checkpoint and, when anchored, the anchor (HR-196). Without receipts the
// pack names the latest checkpoint only.
func (b *builder) proofs() error {
	if !b.r.include.Receipts {
		return b.latestCheckpoint()
	}
	var txns []ids.UUID
	for _, ev := range b.txns {
		txns = append(txns, ev.Transaction.ID)
	}
	anchored := false
	for i := 0; i < len(txns); i += evapp.MaxTransactions {
		chunk := txns[i:min(i+evapp.MaxTransactions, len(txns))]
		n := i/evapp.MaxTransactions + 1
		x, err := b.s.Bundles.ExportBundle(b.ctx, evapp.Selection{Transactions: chunk}, 0)
		switch {
		case errors.Is(err, evapp.ErrNothingToExport):
			b.gap(fmt.Sprintf("proofs %d", n), pack.GapNotCheckpointed, "the receipts of %d transactions are not chained yet", len(chunk))
			continue
		case errors.Is(err, evapp.ErrBundleTooLarge):
			b.gap(fmt.Sprintf("proofs %d", n), pack.GapLimit, "the proofs of %d transactions are too large for one bundle", len(chunk))
			continue
		case err != nil:
			return err
		}
		bd, err := bundle.Decode(x.Bundle)
		if err != nil {
			return err
		}
		b.files = append(b.files, pack.File{Path: fmt.Sprintf("proofs/bundle-%04d.json", n), Kind: pack.KindBundle, Data: x.Bundle})
		if len(bd.Checkpoints) == 0 {
			b.gap(fmt.Sprintf("proofs %d", n), pack.GapNotCheckpointed, "no checkpoint covers these receipts yet")
			continue
		}
		latest := bd.Checkpoints[len(bd.Checkpoints)-1]
		if b.m.Checkpoint == nil || x.CheckpointSize > b.m.Checkpoint.Size {
			b.m.Checkpoint = &pack.Checkpoint{Size: x.CheckpointSize, Note: latest}
		}
		if bd.Anchor != nil {
			anchored = true
			if s, err := anchor.ParseStatement(bd.Anchor.Statement); err == nil {
				b.m.Anchor = &pack.Anchor{
					Period: rfc(s.Period), Checkpoint: bd.Anchor.Checkpoint, Root: base64.StdEncoding.EncodeToString(s.Root[:]),
				}
			}
		}
	}
	if err := b.latestCheckpoint(); err != nil {
		return err
	}
	if !anchored && len(txns) > 0 {
		b.gap("anchor", pack.GapNotAnchored, "no anchor holds a checkpoint of these receipts: anchoring is off, or has not run yet")
	}
	return nil
}

// latestCheckpoint names the org's latest checkpoint when no bundle did.
func (b *builder) latestCheckpoint() error {
	if b.m.Checkpoint == nil {
		if cp, _, err := b.s.Bundles.GetCheckpoint(b.ctx, 0); err == nil {
			b.m.Checkpoint = &pack.Checkpoint{Size: cp.Size, Note: string(cp.Note)}
		} else if !errors.Is(err, evapp.ErrNoCheckpoint) && pcerr.CodeOf(err) != pcerr.PermissionDenied {
			return err
		}
	}
	if b.m.Checkpoint == nil {
		b.gap("checkpoint", pack.GapNotCheckpointed, "the org has no signed checkpoint yet")
	}
	return nil
}

// captures records what happened to payload captures (HR-199): only a
// holder of evidence.read_restricted who asked gets them, and only where
// capture exists.
func (b *builder) captures() error {
	if !b.r.include.Captures {
		return nil
	}
	if !b.c.CanAnywhere(td.PermEvidenceReadRestricted) {
		b.gap("captures", pack.GapOutsidePermission, "payload captures need evidence.read_restricted")
		return nil
	}
	if b.s.Captures == nil {
		b.gap("captures", pack.GapNotCaptured, "payload capture is not available on this server")
		return nil
	}
	b.m.Filters = append(b.m.Filters, "evidence.read_restricted for payload captures")
	for _, ev := range b.txns {
		p, err := b.agentPath(ev.Transaction.Agent)
		if err != nil {
			return err
		}
		if !b.c.Can(td.PermEvidenceReadRestricted, p) {
			b.gap("captures of "+ev.Transaction.ID.String(), pack.GapOutsidePermission, "evidence.read_restricted is not held where its agent lives")
			continue
		}
		files, err := b.s.Captures.Captures(b.ctx, b.org, ev.Transaction.ID)
		if err != nil {
			return err
		}
		for _, f := range files {
			if !strings.HasPrefix(f.Path, "captures/"+ev.Transaction.ID.String()+"/") {
				return fmt.Errorf("packbuild: capture file %q outside its transaction", f.Path)
			}
			b.files = append(b.files, f)
		}
	}
	return nil
}

func (b *builder) agentPath(agent ids.UUID) (td.Path, error) {
	var p td.Path
	err := b.s.Pool.InTenantTx(b.ctx, b.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		p, err = b.pathOf(ctx, dbq.New(tx), agent)
		return err
	}, db.ReadOnly())
	return p, err
}

// redactions says what the pack never holds (F530).
func (b *builder) redactions() {
	b.m.Redactions = []string{
		"Replay input values (evidence.read_restricted) are not exported.",
		"Credentials and request headers are never captured or exported.",
		"Approval responses state whether a security-key assertion was made, not its bytes.",
		"Observed values are only the fields each verifier declares.",
	}
	if !b.r.include.Receipts {
		b.m.Redactions = append(b.m.Redactions, "Receipts and their inclusion proofs are left out at the creator's request; "+
			"the pack names the latest checkpoint only.")
	}
	if !b.r.include.Captures || b.s.Captures == nil {
		b.m.Redactions = append(b.m.Redactions, "Payload captures are not included.")
	}
}
