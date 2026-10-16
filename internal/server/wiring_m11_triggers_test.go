// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/endpoints"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// The ports this stream hands to core (TriggerActivator) and the engine
// (Deliverer) build without a database (G0 M11 part 2 D11).
func TestAutomationTriggerPortsBuild(t *testing.T) {
	core := newAutomationsCore(nil, nil, "")
	if act, err := automationTriggerActivator(nil, nil, nil, core); err != nil || act == nil {
		t.Fatalf("no TriggerActivator: %v", err)
	}
	trig, err := newAutomationTriggers(nil, nil, nil, core)
	if err != nil {
		t.Fatal(err)
	}
	d, err := automationDeliverer(nil, nil, trig, nil, "https://pc.example.com", nil)
	if err != nil || d == nil {
		t.Fatalf("Deliverer: %v", err)
	}
	if _, err := automationDeliverer(nil, nil, trig, nil, "not a url", nil); err == nil {
		t.Fatal("a Deliverer without a public URL")
	}
}

// D112: every trigger service this stream builds — the API's and the
// workers' (automationTriggerServices), the activator core holds and the
// one behind the Deliverer the engine builds — has the shared core's Starter,
// Pauser and execution lookup; none is left "not available".
func TestAutomationTriggerServicesShareTheCore(t *testing.T) {
	core := newAutomationsCore(nil, nil, "")
	built := map[string]reflect.Value{}

	plain, err := newAutomationTriggers(nil, nil, nil, core)
	if err != nil {
		t.Fatal(err)
	}
	built["newAutomationTriggers"] = reflect.ValueOf(plain)

	trig, ep, err := automationTriggerServices(nil, nil, nil, "https://pc.example.com", nil, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	built["automationTriggerServices"] = reflect.ValueOf(trig)
	built["automationTriggerServices endpoints"] = field(reflect.ValueOf(ep), "triggers")

	a, err := automationTriggerActivator(nil, nil, nil, core)
	act, ok := a.(triggers.Activator)
	if err != nil || !ok {
		t.Fatalf("the activator is not the trigger service's (%v)", err)
	}
	built["automationTriggerActivator"] = field(reflect.ValueOf(act), "s")

	kek := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		t.Fatal(err)
	}
	e, err := driverEngine(core, engineDeps{kp: kp, publicURL: "https://pc.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	cleanup, _ := e.Cleaner.(pgengine.Cleanup)
	d, ok := cleanup.Deliveries.(endpoints.Deliverer)
	if !ok {
		t.Fatalf("the engine's Deliverer %T", cleanup.Deliveries)
	}
	built["engine Deliverer"] = field(field(reflect.ValueOf(d), "s"), "triggers")

	for name, svc := range built {
		if svc.IsNil() {
			t.Fatalf("%s: no trigger service", name)
		}
		deps := field(svc, "d")
		for _, port := range []string{"Starter", "Pauser", "Executions"} {
			if field(deps, port).IsNil() {
				t.Errorf("%s: %s is nil", name, port)
			}
		}
	}
}

// field reads a (possibly unexported) field, through a pointer.
func field(v reflect.Value, name string) reflect.Value {
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	return v.FieldByName(name)
}
