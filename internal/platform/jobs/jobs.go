// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package jobs sets up River, PostgreSQL-backed background jobs used as a
// transactional outbox (ADR-0006, ARCHITECTURE §8).
//
// Rules:
//   - Jobs are inserted with InsertTx inside the business transaction, so a
//     job exists if and only if the change that caused it committed.
//   - Job arguments carry identifiers only, never secrets or payloads
//     (HR-056). Register refuses argument types that could carry them.
//   - Work that touches tenant data opens its own db.InTenantTx for the org
//     named in the arguments (HR-054). River tables themselves are global.
//   - Expiry is enforced at use time; jobs only notify and clean up.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/tenantctx"
)

// TxType is the transaction type River is instantiated with.
type TxType = pgx.Tx

// Client is the River client type used throughout PantherClaw.
type Client = river.Client[pgx.Tx]

// Registry collects workers before the client starts.
type Registry struct {
	workers *river.Workers
	kinds   []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{workers: river.NewWorkers()} }

// Kinds lists the registered job kinds.
func (r *Registry) Kinds() []string { return slices.Clone(r.kinds) }

// Register adds a worker after checking that its argument type can only
// carry identifiers and small scalars (HR-056).
func Register[T river.JobArgs](r *Registry, w river.Worker[T]) error {
	var args T
	if err := CheckArgs(reflect.TypeOf(args)); err != nil {
		return fmt.Errorf("jobs: %s: %w", args.Kind(), err)
	}
	if f, ok := orgField(reflect.TypeOf(args)); ok {
		w = orgWorker[T]{Worker: w, field: f}
	}
	if err := river.AddWorkerSafely(r.workers, w); err != nil {
		return fmt.Errorf("jobs: register %s: %w", args.Kind(), err)
	}
	r.kinds = append(r.kinds, args.Kind())
	return nil
}

var orgIDType = reflect.TypeFor[ids.OrgID]()

// orgField returns the index of the org id field (OrgID or Org) of a job
// argument struct.
func orgField(t reflect.Type) ([]int, bool) {
	if t == nil || t.Kind() != reflect.Struct {
		return nil, false
	}
	for _, name := range []string{"OrgID", "Org"} {
		if f, ok := t.FieldByName(name); ok && f.Type == orgIDType {
			return f.Index, true
		}
	}
	return nil, false
}

// orgWorker runs a job whose arguments name an org with that org in the
// context, so the entitlements it reads are the org's (G0 UI D9).
type orgWorker[T river.JobArgs] struct {
	river.Worker[T]
	field []int
}

// Work implements river.Worker.
func (w orgWorker[T]) Work(ctx context.Context, job *river.Job[T]) error {
	if org, ok := reflect.ValueOf(job.Args).FieldByIndex(w.field).Interface().(ids.OrgID); ok && !org.IsZero() {
		ctx = tenantctx.WithOrg(ctx, org)
	}
	return w.Worker.Work(ctx, job)
}

// forbiddenFieldParts are rejected in argument field names: arguments name
// the records to work on, they never contain the records.
var forbiddenFieldParts = []string{
	"secret", "token", "password", "passphrase", "credential", "private", "key_material",
	"payload", "body", "content", "data", "raw", "proof", "cookie", "authorization",
}

var (
	timeType     = reflect.TypeFor[time.Time]()
	durationType = reflect.TypeFor[time.Duration]()
)

// idType reports whether t is an ids.ID instantiation (struct with UUID()).
func idType(t reflect.Type) bool {
	m, ok := t.MethodByName("UUID")
	return ok && t.Kind() == reflect.Struct && m.Type.NumIn() == 1 && m.Type.NumOut() == 1 &&
		strings.HasSuffix(t.PkgPath(), "internal/platform/ids")
}

// CheckArgs validates a job-argument struct type (HR-056). Allowed fields:
// typed IDs, booleans, integers, short strings (names, enums), time.Time,
// time.Duration and slices of those. Bytes, maps, interfaces, pointers,
// nested structs and sensitive-looking names are rejected.
func CheckArgs(t reflect.Type) error {
	if t == nil || t.Kind() != reflect.Struct {
		return errors.New("job arguments must be a struct")
	}
	for i := range t.NumField() {
		f := t.Field(i)
		name := strings.ToLower(f.Name)
		for _, part := range forbiddenFieldParts {
			if strings.Contains(name, part) {
				return fmt.Errorf("field %s: name suggests a secret or payload (HR-056)", f.Name)
			}
		}
		if err := checkFieldType(f.Type); err != nil {
			return fmt.Errorf("field %s: %w", f.Name, err)
		}
	}
	return nil
}

func checkFieldType(t reflect.Type) error {
	if t == timeType || t == durationType || idType(t) {
		return nil
	}
	//exhaustive:ignore // allowlist; every other kind is rejected below
	switch t.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.String:
		return nil
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return errors.New("byte slices may carry payloads (HR-056)")
		}
		return checkFieldType(t.Elem())
	default:
		return fmt.Errorf("type %s is not allowed in job arguments (HR-056)", t)
	}
}

// Config configures a client.
type Config struct {
	// Queues maps queue names to their maximum concurrent workers. Leave it
	// empty for an insert-only client (the API role).
	Queues       map[string]int
	PeriodicJobs []*river.PeriodicJob
	Logger       *slog.Logger
	// JobTimeout bounds each job; defaults to one minute.
	JobTimeout time.Duration
}

// NewClient returns a River client for schema pc.
func NewClient(pool *db.Pool, reg *Registry, cfg Config) (*Client, error) {
	rc := &river.Config{
		Schema:               db.Schema,
		Logger:               cfg.Logger,
		JobTimeout:           cfg.JobTimeout,
		MaxAttempts:          10,
		RescueStuckJobsAfter: 10 * time.Minute,
		PeriodicJobs:         cfg.PeriodicJobs,
	}
	if rc.JobTimeout == 0 {
		rc.JobTimeout = time.Minute
	}
	if len(cfg.Queues) > 0 {
		if reg == nil {
			return nil, errors.New("jobs: a worker client needs a registry")
		}
		rc.Workers = reg.workers
		rc.Queues = make(map[string]river.QueueConfig, len(cfg.Queues))
		for q, n := range cfg.Queues {
			if n < 1 || n > 1000 {
				return nil, fmt.Errorf("jobs: queue %q: max workers must be 1..1000", q)
			}
			rc.Queues[q] = river.QueueConfig{MaxWorkers: n}
		}
	}
	c, err := river.NewClient(riverpgxv5.New(pool.Pgx()), rc)
	if err != nil {
		return nil, fmt.Errorf("jobs: new client: %w", err)
	}
	return c, nil
}

// InsertTx enqueues a job in the tenant transaction tx (transactional
// outbox): the job is visible only if the transaction commits.
func InsertTx(ctx context.Context, c *Client, tx db.TenantTx, args river.JobArgs, opts *river.InsertOpts) error {
	if _, err := c.InsertTx(ctx, tx.Pgx(), args, opts); err != nil {
		return fmt.Errorf("jobs: insert %s: %w", args.Kind(), err)
	}
	return nil
}

// InsertGlobalTx enqueues a job in a global transaction (for platform-wide
// maintenance jobs such as dispatching per-org work).
func InsertGlobalTx(ctx context.Context, c *Client, tx db.GlobalTx, args river.JobArgs, opts *river.InsertOpts) error {
	if _, err := c.InsertTx(ctx, tx.Pgx(), args, opts); err != nil {
		return fmt.Errorf("jobs: insert %s: %w", args.Kind(), err)
	}
	return nil
}
