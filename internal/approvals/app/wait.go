// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Wait handles (slice 212, HR-174). A held agent waits on its
// transaction's handle instead of polling with retries. A wait serves only
// its own run and instance, is read-only and bounded, never extends a
// deadline and never dispatches anything: on READY the agent resubmits the
// identical action.
const (
	// LongPollMax caps one Wait call.
	LongPollMax = 30 * time.Second
	// Recheck is how often a waiter reads the state again in case a notice
	// was missed.
	Recheck = 5 * time.Second
	// StreamHeartbeat and StreamLifetime pace the SSE route.
	StreamHeartbeat = 15 * time.Second
	StreamLifetime  = 5 * time.Minute
	// RetryAfter is how long a live handle's waiter should wait before
	// waiting again.
	RetryAfter = 5 * time.Second
	// DefaultWaitsPerInstance and DefaultWaitsPerServer bound concurrent
	// waits.
	DefaultWaitsPerInstance = 4
	DefaultWaitsPerServer   = 1000
)

// Errors of wait handles.
var (
	ErrNoWait = pcerr.New(pcerr.NotFound, "WAIT_HANDLE_NOT_FOUND", "no wait handle for this transaction")
	// ErrTooManyWaits: retry after RetryAfter.
	ErrTooManyWaits = pcerr.New(pcerr.ResourceExhausted, "WAIT_LIMIT_REACHED", "too many waits; retry later")
)

// WaitView is a wait handle's state: states, codes and times only, never
// an approver's identity, a note or the display (HR-174).
type WaitView struct {
	Handle           ids.UUID
	State            string
	Code             string
	Deadline         time.Time
	ConsumeBy        *time.Time
	EvidenceDeadline *time.Time
	RequestID        ids.UUID
	ProposedParams   []byte
	RetryAfter       time.Duration
}

// Final reports whether the handle will not change again: the request
// ended, or its approval was used.
func (v WaitView) Final() bool {
	return v.State != apdomain.WaitPending && v.State != apdomain.WaitEvidenceRequested && v.State != apdomain.WaitReady
}

func (v WaitView) same(o WaitView) bool {
	return v.State == o.State && v.Code == o.Code && v.RequestID == o.RequestID && v.Deadline.Equal(o.Deadline)
}

// Waits serves wait handles: reads, long polls and streams, woken by
// LISTEN pc_wait (whose payload is "org_id:transaction_id" only, HR-056),
// within per-instance and per-server limits.
type Waits struct {
	pool                   *db.Pool
	log                    *slog.Logger
	perInstance, perServer int
	longPoll               time.Duration

	mu        sync.Mutex
	instances map[ids.UUID]int
	total     int
	waiters   map[waitKey]map[chan struct{}]struct{}
}

type waitKey struct {
	org ids.OrgID
	txn ids.UUID
}

// NewWaits returns the wait handles; zero limits take the defaults.
func NewWaits(pool *db.Pool, perInstance, perServer int, log *slog.Logger) *Waits {
	if perInstance <= 0 {
		perInstance = DefaultWaitsPerInstance
	}
	if perServer <= 0 {
		perServer = DefaultWaitsPerServer
	}
	if log == nil {
		log = pclog.Discard()
	}
	return &Waits{
		pool: pool, log: log, perInstance: perInstance, perServer: perServer, longPoll: LongPollMax,
		instances: map[ids.UUID]int{}, waiters: map[waitKey]map[chan struct{}]struct{}{},
	}
}

// WithLongPoll lowers the cap of one Wait call below LongPollMax.
func (w *Waits) WithLongPoll(d time.Duration) *Waits {
	if d > 0 && d < LongPollMax {
		w.longPoll = d
	}
	return w
}

// Read returns the state of the handle (a transaction id) for the instance
// whose run it belongs to; run, when not zero, must be that run. Anyone
// else gets ErrNoWait.
func (w *Waits) Read(ctx context.Context, org ids.OrgID, instance, run, handle ids.UUID) (WaitView, error) {
	p := dbq.WaitRequestParams{OrgID: org, TransactionID: &handle, InstanceID: &instance}
	if !run.IsZero() {
		p.RunID = &run
	}
	var row dbq.WaitRequestRow
	err := w.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		row, err = dbq.New(tx).WaitRequest(ctx, p)
		if db.IsNoRows(err) {
			return ErrNoWait
		}
		return err
	}, db.ReadOnly())
	if err != nil {
		return WaitView{}, err
	}
	st, code := apdomain.At(apdomain.State(row.State), apdomain.Times{
		Deadline: row.DeadlineAt, EvidenceDeadline: row.EvidenceDeadlineAt, ConsumeBy: row.ConsumeBy,
	}, row.Now)
	if code == "" && row.EndReason != nil {
		code = *row.EndReason
	}
	v := WaitView{
		Handle: handle, State: apdomain.WaitState(st, code), Code: code, Deadline: row.DeadlineAt, RequestID: row.ID,
		RetryAfter: RetryAfter,
	}
	switch v.State {
	case apdomain.WaitEvidenceRequested:
		v.Code, v.EvidenceDeadline = row.Question, row.EvidenceDeadlineAt
	case apdomain.WaitReady:
		v.ConsumeBy, v.RetryAfter = row.ConsumeBy, 0
	case apdomain.WaitNarrowerProposed:
		v.ProposedParams = row.Proposed
	}
	if v.Final() {
		v.RetryAfter = 0
	}
	return v, nil
}

// acquire takes one of the instance's and the server's wait slots.
func (w *Waits) acquire(instance ids.UUID) (func(), error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.total >= w.perServer || w.instances[instance] >= w.perInstance {
		return nil, ErrTooManyWaits
	}
	w.total++
	w.instances[instance]++
	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.total--
		if w.instances[instance]--; w.instances[instance] <= 0 {
			delete(w.instances, instance)
		}
	}, nil
}

// subscribe returns a channel woken when the handle's request changes.
func (w *Waits) subscribe(org ids.OrgID, txn ids.UUID) (chan struct{}, func()) {
	k, ch := waitKey{org, txn}, make(chan struct{}, 1)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.waiters[k] == nil {
		w.waiters[k] = map[chan struct{}]struct{}{}
	}
	w.waiters[k][ch] = struct{}{}
	return ch, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		delete(w.waiters[k], ch)
		if len(w.waiters[k]) == 0 {
			delete(w.waiters, k)
		}
	}
}

func (w *Waits) wake(k waitKey) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for ch := range w.waiters[k] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Wait long-polls the handle for at most timeout (the long-poll cap by
// default and at most): it answers at once when the state differs from known (or
// known is empty) or is final, and otherwise when the state changes or the
// time passes (timedOut).
func (w *Waits) Wait(ctx context.Context, org ids.OrgID, instance, run, handle ids.UUID, known string, timeout time.Duration) (
	v WaitView, timedOut bool, err error,
) {
	if timeout <= 0 || timeout > w.longPoll {
		timeout = w.longPoll
	}
	release, err := w.acquire(instance)
	if err != nil {
		return WaitView{}, false, err
	}
	defer release()
	ch, unsubscribe := w.subscribe(org, handle)
	defer unsubscribe()
	until := time.NewTimer(timeout)
	defer until.Stop()
	for {
		if v, err = w.Read(ctx, org, instance, run, handle); err != nil || known == "" || v.State != known || v.Final() {
			return v, false, err
		}
		select {
		case <-ctx.Done():
			return v, true, nil
		case <-until.C:
			return v, true, nil
		case <-ch:
		case <-time.After(Recheck):
		}
	}
}

// Stream sends the handle's state at once, then each change, and a
// heartbeat every StreamHeartbeat, until the state is final, StreamLifetime
// passes, ctx ends or send fails (the SSE route, HR-174).
func (w *Waits) Stream(ctx context.Context, org ids.OrgID, instance, handle ids.UUID, send func(v WaitView, heartbeat bool) error) error {
	release, err := w.acquire(instance)
	if err != nil {
		return err
	}
	defer release()
	ch, unsubscribe := w.subscribe(org, handle)
	defer unsubscribe()
	life, beat := time.NewTimer(StreamLifetime), time.NewTicker(StreamHeartbeat)
	defer life.Stop()
	defer beat.Stop()
	last, err := w.Read(ctx, org, instance, ids.UUID{}, handle)
	if err != nil {
		return err
	}
	if err := send(last, false); err != nil || last.Final() {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-life.C:
			return nil
		case <-beat.C:
			if err := send(last, true); err != nil {
				return err
			}
			continue
		case <-ch:
		case <-time.After(Recheck):
		}
		v, err := w.Read(ctx, org, instance, ids.UUID{}, handle)
		if err != nil {
			return err
		}
		if !v.same(last) {
			if err := send(v, false); err != nil || v.Final() {
				return err
			}
			last = v
		}
	}
}

// Run listens for pc_wait notifications and wakes the handle's waiters,
// reconnecting with backoff, until ctx ends. Without it, waiters still
// read the state every Recheck.
func (w *Waits) Run(ctx context.Context) error {
	backoff := 100 * time.Millisecond
	for ctx.Err() == nil {
		err := w.listen(ctx)
		if ctx.Err() != nil {
			return nil //nolint:nilerr // shutdown, not a failure
		}
		w.log.WarnContext(ctx, "approvals.wait_listen_failed", pclog.Err(err))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Second)
	}
	return nil
}

func (w *Waits) listen(ctx context.Context) error {
	conn, err := w.pool.Pgx().Acquire(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "UNLISTEN *")
		conn.Release()
	}()
	if _, err := conn.Exec(ctx, "LISTEN pc_wait"); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		org, txn, ok := strings.Cut(n.Payload, ":")
		if !ok {
			continue
		}
		o, err1 := ids.Parse[ids.Org](org)
		t, err2 := ids.ParseUUID(txn)
		if err1 != nil || err2 != nil {
			continue
		}
		w.wake(waitKey{o, t})
	}
}
