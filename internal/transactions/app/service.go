// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app runs verification on the server side (G0 M7 track A, design
// decisions 1–3): it leases verification tasks to the gateway serving
// their connection, turns what the gateway observed into effect states and
// signed effect receipts, resolves reconciliations from evidence (only
// towards "occurred"), and ends tasks whose window closed.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strconv"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// Limits of the lease protocol (HR-190).
const (
	// LeaseFor is how long a lease lasts; the schema refuses longer.
	LeaseFor = 30 * time.Second
	// MaxClaim is the most tasks one claim leases.
	MaxClaim = 16
	// MaxFields is the most observed fields one report carries.
	MaxFields = 16
	// MaxFieldValue is the longest observed value, in bytes.
	MaxFieldValue = 256
)

// TypeEffectReceipt is the JOSE type of an effect receipt (PAP-1 §9.3).
const TypeEffectReceipt = "pap-effect+jwt"

// Errors.
var (
	// ErrLease refuses a report without a live lease of this gateway: an
	// unknown task, another gateway's, an expired or a used lease.
	ErrLease = pcerr.New(pcerr.FailedPrecondition, "LEASE_INVALID", "no live lease of this gateway for the task")
	// ErrUndeclared refuses a report that carries a field the verifier does
	// not declare, or a malformed one (HR-190).
	ErrUndeclared = pcerr.New(pcerr.InvalidArgument, "FIELD_UNDECLARED", "the report carries a field the verifier does not declare")
)

// Lease is a verification task leased to a gateway (HR-190). Secret is
// returned once; the store keeps only its SHA-256.
type Lease struct {
	Task       ids.UUID
	Secret     []byte
	Purpose    domain.Purpose
	Connection ids.UUID
	Operation  string
	// Request is the read the server computed: mode, target and params.
	Request []byte
	// Correlate is the idempotency key an item of a listing must carry to
	// be the write's effect: pc-<transaction> (HR-008).
	Correlate string
	Attempt   int
	Deadline  time.Time
}

// Report is what a gateway observed under a lease: only the fields the
// verifier declares, by JSON pointer, and a digest of the answer; for a
// target-log task, the objects listed (HR-112).
type Report struct {
	Task           ids.UUID
	Secret         []byte
	HTTPStatus     int
	Found          bool
	Complete       bool
	Fields         map[string]string
	ResponseDigest []byte
	Items          []TargetLogItem
}

// TargetLogItem is one object a target log listed: its id at the target,
// the idempotency key it was created with (empty when none), and when.
type TargetLogItem struct {
	ObjectRef   string
	Correlation string
	Created     time.Time
}

// MaxTargetLogItems is the most objects one target-log report carries.
const MaxTargetLogItems = 1000

// TargetLogEvery is how often each connection's target log is read, and
// TargetLogOverlap how far each window reaches back into the previous one
// (G0 M7 design decision 6).
const (
	TargetLogEvery   = 15 * time.Minute
	TargetLogOverlap = 5 * time.Minute
)

// Applied is what a report changed.
type Applied struct {
	Observation ids.UUID
	State       domain.EffectState
	// Resolved says the report resolved the transaction's reconciliation
	// (as occurred).
	Resolved bool
	// Done says the task ended (its state is final or its window closed).
	Done bool
}

// VerifierRef names the verifier of an effect receipt.
type VerifierRef struct {
	Operation   string `json:"operation"`
	Establishes string `json:"establishes"`
	Gateway     string `json:"gateway,omitzero"`
	Connection  string `json:"connection,omitzero"`
}

// Effect is what one effect receipt states (PAP-1 §9.3).
type Effect struct {
	Org         ids.OrgID
	Transaction ids.UUID
	Seq         int
	State       domain.EffectState
	Required    defs.Level
	Achieved    defs.Level
	// Basis is the kind of evidence: verifier, late_report, target_log,
	// person, compensation, definition or deadline.
	Basis        string
	Observations []ids.UUID
	Verifier     *VerifierRef
	Expected     map[string]string
	Observed     map[string]string
	// Effects are one result per declared effect kind: the verified one
	// carries State, the others are UNVERIFIABLE (F490's part).
	Effects []EffectResult
	Limits  string
	Reason  string
	// Person is who resolved it, for the "person" basis.
	Person *ids.UUID
	// Compensation is the compensating transaction, for the
	// "compensation" basis; Reversibility is the original definition's, so
	// an irreversible effect reads "compensated, not reversed" (HR-193).
	Compensation  *ids.UUID
	Reversibility defs.Reversibility
	At            time.Time
}

// EffectResult is the state of one declared effect kind.
type EffectResult struct {
	Kind  string             `json:"kind"`
	State domain.EffectState `json:"state"`
}

// Signed is a signed effect receipt and the canonical body its ledger
// entry carries.
type Signed struct {
	JWS  string
	Body []byte
}

// Sign signs an effect receipt.
type Sign func(Effect) (Signed, error)

// Store is the verification port. Every method runs in one tenant
// transaction.
type Store interface {
	// Claim leases up to limit due tasks of the connections gateway serves
	// (HR-190).
	Claim(ctx context.Context, org ids.OrgID, gateway ids.UUID, limit int, leaseFor time.Duration) ([]Lease, error)
	// Report records what the gateway observed under a lease, assesses
	// it, appends an effect receipt when the state changes, resolves the
	// reconciliation when the effect happened, and retries or ends the
	// task.
	Report(ctx context.Context, org ids.OrgID, gateway ids.UUID, r Report, sign Sign) (Applied, error)
	// Expire returns leases nobody reported to PENDING and ends tasks whose
	// window closed, appending the deadline's effect receipt.
	Expire(ctx context.Context, org ids.OrgID, sign Sign) (int, error)
	// ScheduleTargetLogs creates a target-log task for each active
	// connection whose pinned package declares a target log and has none
	// open, for the window since its last complete run, minus overlap
	// (HR-112).
	ScheduleTargetLogs(ctx context.Context, org ids.OrgID, overlap time.Duration) (int, error)
}

// Signer signs a compact JWS of a JOSE type (the receipts key's signer).
type Signer interface {
	Sign(typ string, payload []byte) (string, error)
}

// Service is the verification application.
type Service struct {
	Store    Store
	Receipts Signer
	// Issuer names the deployment in receipts (as finalize.Authority's).
	Issuer string
}

// Claim leases due tasks to gw.
func (s *Service) Claim(ctx context.Context, org ids.OrgID, gateway ids.UUID, limit int) ([]Lease, error) {
	if limit <= 0 || limit > MaxClaim {
		limit = MaxClaim
	}
	return s.Store.Claim(ctx, org, gateway, limit, LeaseFor)
}

// Report applies a gateway's report.
func (s *Service) Report(ctx context.Context, org ids.OrgID, gateway ids.UUID, r Report) (Applied, error) {
	if len(r.Fields) > MaxFields {
		return Applied{}, ErrUndeclared
	}
	for k, v := range r.Fields {
		if !defs.ValidPointer(k) || len(v) > MaxFieldValue {
			return Applied{}, ErrUndeclared
		}
	}
	if len(r.Secret) != 32 || (len(r.ResponseDigest) != 0 && len(r.ResponseDigest) != sha256.Size) {
		return Applied{}, ErrLease
	}
	if len(r.Items) > MaxTargetLogItems {
		return Applied{}, ErrUndeclared
	}
	return s.Store.Report(ctx, org, gateway, r, s.sign)
}

// ScheduleTargetLogs schedules one org's target-log reads.
func (s *Service) ScheduleTargetLogs(ctx context.Context, org ids.OrgID) (int, error) {
	return s.Store.ScheduleTargetLogs(ctx, org, TargetLogOverlap)
}

// Expire ends what the clock ended for one org.
func (s *Service) Expire(ctx context.Context, org ids.OrgID) (int, error) {
	return s.Store.Expire(ctx, org, s.sign)
}

// sign builds and signs an effect receipt (PAP-1 §9.3). Expected and
// observed values appear as digests: the values stay in observations.
func (s *Service) sign(e Effect) (Signed, error) {
	if s.Receipts == nil {
		return Signed{}, errors.New("transactions: no receipt signer")
	}
	basis := map[string]any{"kind": e.Basis}
	if len(e.Observations) > 0 {
		obs := make([]string, len(e.Observations))
		for i, o := range e.Observations {
			obs[i] = o.String()
		}
		basis["observations"] = obs
	}
	if e.Person != nil {
		basis["person"] = e.Person.String()
	}
	if e.Compensation != nil {
		basis["transaction"] = e.Compensation.String()
	}
	pap := map[string]any{
		"v": 1, "kind": "effect", "org": e.Org.String(), "txn": e.Transaction.String(), "seq": e.Seq,
		"state": string(e.State), "required": string(e.Required), "basis": basis, "simulated": false,
		"at": e.At.UTC().Format(time.RFC3339Nano),
	}
	if e.Achieved != "" {
		pap["achieved"] = string(e.Achieved)
	}
	if e.Verifier != nil {
		pap["verifier"] = e.Verifier
	}
	if e.Expected != nil {
		pap["expected_sha256"] = digest(e.Expected)
	}
	if e.Observed != nil {
		pap["observed_sha256"] = digest(e.Observed)
	}
	if len(e.Effects) > 0 {
		pap["effects"] = e.Effects
	}
	if e.Limits != "" {
		pap["limits"] = e.Limits
	}
	if e.Reason != "" {
		pap["reason"] = e.Reason
	}
	if e.Reversibility != "" {
		pap["reversibility"] = string(e.Reversibility)
	}
	iss := s.Issuer
	if iss == "" {
		iss = "pantherclaw"
	}
	jti := e.Transaction.String() + "/" + strconv.Itoa(e.Seq)
	payload, err := json.Marshal(map[string]any{"iss": iss, "jti": jti, "iat": e.At.Unix(), "pap": pap}, json.Deterministic(true))
	if err != nil {
		return Signed{}, err
	}
	token, err := s.Receipts.Sign(TypeEffectReceipt, payload)
	if err != nil {
		return Signed{}, err
	}
	sum := sha256.Sum256([]byte(token))
	body, err := evdomain.CanonicalBody(map[string]string{
		"txn": e.Transaction.String(), "seq": strconv.Itoa(e.Seq), "state": string(e.State),
		"receipt_sha256": hex.EncodeToString(sum[:]),
	})
	if err != nil {
		return Signed{}, err
	}
	return Signed{JWS: token, Body: body}, nil
}

// digest is the hex SHA-256 of a canonical field map.
func digest(m map[string]string) string {
	b, err := evdomain.CanonicalBody(m)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Backoff is the delay before the attempt-th retry of an inconclusive read:
// 5 s, then three times longer each time, at most 5 minutes (G0 M7 design
// decision 2).
func Backoff(attempt int) time.Duration {
	d := 5 * time.Second
	for i := 1; i < attempt && d < 5*time.Minute; i++ {
		d *= 3
	}
	return min(d, 5*time.Minute)
}

// Declared is the set of fields a verifier may report (HR-190): the
// expected fields and the status field.
func Declared(v *defs.VerifierSpec) map[string]bool {
	out := map[string]bool{}
	for _, e := range v.Expect {
		out[e.Field] = true
	}
	if v.States != nil {
		out[v.States.Field] = true
	}
	return out
}

// Effects lists one result per declared effect kind of d: the direct
// effects carry state, the side effects (no verifier of their own) are
// UNVERIFIABLE.
func Effects(d *defs.Definition, state domain.EffectState) []EffectResult {
	var out []EffectResult
	for _, e := range d.Effects {
		out = append(out, EffectResult{Kind: e.Kind, State: state})
	}
	for _, e := range d.SideEffects {
		out = append(out, EffectResult{Kind: e.Kind, State: domain.Unverifiable})
	}
	return out
}
