// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/promotions"
	"github.com/katocxl/pantherclaw/internal/protect"
)

// m11Optional are the fields of the M11 instances that may stay nil, and
// why. Every other exported pointer, interface, func or map field is a
// port that must be wired.
var m11Optional = map[string]string{
	"packbuild.Service.Captures": "restricted payload captures are configured separately (M7 B9)",
	"packbuild.Service.Clock":    "nil means the system clock",
}

// m11Required are the instances each process role must build.
var m11Required = map[string][]string{
	RoleAll: {
		"automations.core", "automations.engine", "automations.triggers", "protect.gate", "protect.publishers", "promotions",
		"packbuild", "automations.engine.driver",
	},
	RoleWorker: {"automations.core", "automations.engine", "automations.engine.driver", "automations.triggers", "packbuild"},
}

// TestM11_WiringComplete: the real server, started as one process (all)
// and as a worker-only process, builds every M11 part 2 instance with
// every port set, with one automations core per process (G0 M11 part 2
// D96, K6, D102 L3). In-process e2e tests bypass this wiring, so this is
// where a port left nil shows.
func TestM11_WiringComplete(t *testing.T) {
	for _, role := range []string{RoleAll, RoleWorker} {
		t.Run(role, func(t *testing.T) {
			got := serveAndRecord(t, role)
			for _, kind := range m11Required[role] {
				if len(got[kind]) == 0 {
					t.Errorf("%s: the server builds no %s", role, kind)
				}
			}
			if n := len(got["automations.core"]); n > 1 {
				t.Errorf("%s: %d automations core instances, want one shared (K6)", role, n)
			}
			for kind, vs := range got {
				for i, v := range vs {
					for _, gap := range m11NilPorts(v) {
						t.Errorf("%s: %s #%d: %s is nil", role, kind, i+1, gap)
					}
				}
			}
			driverUsesSharedCore(t, role, got)
			for i, v := range got["protect.publishers"] {
				p := reflect.ValueOf(v).Elem()
				if pub := v.(*protect.Publishers); pub.Sources[protect.ItemPromotion] == nil {
					t.Errorf("%s: protect.publishers #%d: promotions are not an exposure source (D116 U1)", role, i+1)
				}
				undo := p.FieldByName("Undo")
				for _, k := range undo.MapKeys() {
					if undo.MapIndex(k).Pointer() == reflect.ValueOf(notYet).Pointer() {
						t.Errorf("%s: protect.publishers #%d: the %s rollback is not wired", role, i+1, k)
					}
				}
			}
		})
	}
}

// TestM11_NoJobClientStopsStartUp (D115 R3, D120): when the security
// steps' insert-only job client cannot be built, the server, started as
// one process (all) and as a worker-only process, refuses to start:
// cmdServe returns that error instead of panicking, and the API never
// listens.
func TestM11_NoJobClientStopsStartUp(t *testing.T) {
	boom := errors.New("no job queue")
	prev := insertJobClient
	insertJobClient = func(*db.Pool, *slog.Logger) (*jobs.Client, error) { return nil, boom }
	t.Cleanup(func() { insertJobClient = prev })
	for _, role := range []string{RoleAll, RoleWorker} {
		t.Run(role, func(t *testing.T) {
			d := dbtest.New(t)
			cfg := testConfig(t, d, role)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			var logs bytes.Buffer
			listening := false
			err := cmdServe(ctx, []string{"--config", cfg}, &logs, noEnv, func(string) { listening = true })
			if !errors.Is(err, boom) || !strings.Contains(err.Error(), "automation security steps: job client") {
				t.Fatalf("serve: %v, want the security steps' job client error\n%s", err, logs.String())
			}
			if listening {
				t.Fatal("the API listened before start-up failed")
			}
		})
	}
}

// serveAndRecord runs the server as role until its instances are built
// and returns them by kind.
func serveAndRecord(t *testing.T, role string) map[string][]any {
	t.Helper()
	var mu sync.Mutex
	got := map[string][]any{}
	m11Probe = func(kind string, v any) {
		mu.Lock()
		defer mu.Unlock()
		got[kind] = append(got[kind], v)
	}
	t.Cleanup(func() { m11Probe = nil })
	d := dbtest.New(t)
	cfg := testConfig(t, d, role)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var logs bytes.Buffer
	go func() { done <- cmdServe(ctx, []string{"--config", cfg}, &logs, noEnv, func(string) {}) }()
	// The instances are built at start-up: wait until no new one appears
	// for two seconds.
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, vs := range got {
			n += len(vs)
		}
		return n
	}
	deadline, last, since := time.Now().Add(60*time.Second), -1, time.Now()
	exited := false
wait:
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			// What was built before start-up failed is still checked.
			t.Errorf("serve exited early: %v", err)
			exited = true
			break wait
		case <-time.After(200 * time.Millisecond):
		}
		if n := count(); n != last {
			last, since = n, time.Now()
		} else if n > 0 && time.Since(since) > 2*time.Second {
			break wait
		}
	}
	cancel()
	if !exited {
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("graceful shutdown did not finish")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if v, ok := got["automations.core"]; ok {
		// The core's services are the ports' holders.
		for _, c := range v {
			core := c.(*automationsCore)
			got["automations.service"] = append(got["automations.service"], core.svc)
			got["changes"] = append(got["changes"], core.changes)
		}
	}
	return got
}

// m11NilPorts lists v's exported pointer, interface, func and map fields that
// are nil and not listed in m11Optional.
func m11NilPorts(v any) []string {
	out := m11StructPorts(reflect.ValueOf(v))
	slices.Sort(out)
	return out
}

// m11StructPorts is m11NilPorts over a value; a service that keeps its ports in
// an unexported dependencies struct (triggers.Service.d) is looked into.
func m11StructPorts(rv reflect.Value) []string {
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return []string{"the instance"}
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil
	}
	rt := rv.Type()
	var out []string
	for i := range rt.NumField() {
		f := rt.Field(i)
		if !f.IsExported() {
			if f.Type.Kind() == reflect.Struct && f.Type.Name() == "Deps" {
				out = append(out, m11StructPorts(rv.Field(i))...)
			}
			continue
		}
		name := rt.Name() + "." + f.Name
		if pkg := rt.PkgPath(); pkg != "" {
			name = pkg[strings.LastIndex(pkg, "/")+1:] + "." + name
		}
		if _, ok := m11Optional[name]; ok {
			continue
		}
		switch fv := rv.Field(i); fv.Kind() { //exhaustive:ignore // values and slices are not ports
		case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map:
			if fv.IsNil() {
				out = append(out, name)
			}
		}
	}
	return out
}

// driverUsesSharedCore: the engine the driver jobs run pauses, voids and
// checks ceilings through the process's one core, whose grants service
// runs the promotion gate, so automation issuance never skips it (D105).
func driverUsesSharedCore(t *testing.T, role string, got map[string][]any) {
	t.Helper()
	cores := got["automations.core"]
	for i, v := range got["automations.engine.driver"] {
		e := reflect.ValueOf(v).Elem()
		for _, port := range []string{"Pauser", "Voider", "Ceilings"} {
			p := e.FieldByName(port)
			var core *automationsCore
			for _, c := range cores {
				if !p.IsNil() && p.Elem().Interface() == any(c.(*automationsCore).svc) {
					core = c.(*automationsCore)
				}
			}
			switch {
			case core == nil:
				t.Errorf("%s: driver engine #%d: %s is not an automations core", role, i+1, port)
			case len(cores) > 1 || core.grants == nil || core.grants.Promotions == nil:
				t.Errorf("%s: driver engine #%d: %s is not the process's one core with the promotion gate", role, i+1, port)
			}
		}
	}
	// One gated grants service per process, the core's (D113).
	if gs := got["grants"]; len(gs) != 1 {
		t.Errorf("%s: %d grants services built through newGrants, want the one shared", role, len(gs))
	} else if len(cores) == 1 && gs[0] != any(cores[0].(*automationsCore).grants) {
		t.Errorf("%s: the core issues through another grants service than the process's gated one", role)
	}
	for i, c := range cores {
		core := c.(*automationsCore)
		if core.grants == nil || core.grants.Promotions == nil {
			t.Errorf("%s: automations core #%d: its grants service has no promotion gate", role, i+1)
		} else if _, ok := core.grants.Promotions.(promotions.Gate); !ok {
			t.Errorf("%s: automations core #%d: the production gate is %T, not govern's promotions.Gate (D116)", role, i+1, core.grants.Promotions)
		}
		if core.grants != nil {
			if st, ok := core.grants.Store.(*grantspg.Store); !ok || st.Promotions == nil {
				t.Errorf("%s: automations core #%d: its grants store does not gate in the transaction (D93)", role, i+1)
			} else if _, real := st.Promotions.(promotions.Gate); !real {
				t.Errorf("%s: automations core #%d: the store gate is %T, not promotions.Gate (D116)", role, i+1, st.Promotions)
			}
		}
		if core.svc.Compromise == nil {
			t.Errorf("%s: automations core #%d: no compromised-publisher check (D109 E1)", role, i+1)
		}
		if core.svc.Grants != core.grants {
			t.Errorf("%s: automations core #%d: the app issues through another grants service", role, i+1)
		}
	}
}
