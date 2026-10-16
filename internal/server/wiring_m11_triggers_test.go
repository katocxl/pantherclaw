// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"reflect"
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/endpoints"
)

// The ports this stream hands to core (TriggerActivator) and the engine
// (Deliverer) build without a database (G0 M11 part 2 D11).
func TestAutomationTriggerPortsBuild(t *testing.T) {
	core := newAutomationsCore(nil, nil, "")
	if automationTriggerActivator(nil, nil, nil, core) == nil {
		t.Fatal("no TriggerActivator")
	}
	d, err := automationDeliverer(nil, nil, nil, "https://pc.example.com", nil, core)
	if err != nil || d == nil {
		t.Fatalf("Deliverer: %v", err)
	}
	if _, err := automationDeliverer(nil, nil, nil, "not a url", nil, core); err == nil {
		t.Fatal("a Deliverer without a public URL")
	}
}

// D112: every trigger service this stream builds — the API's and the
// workers' (automationTriggerServices), the activator core holds and the
// one behind the engine's Deliverer — has the shared core's Starter,
// Pauser and execution lookup; none is left "not available".
func TestAutomationTriggerServicesShareTheCore(t *testing.T) {
	core := newAutomationsCore(nil, nil, "")
	built := map[string]reflect.Value{}

	built["newAutomationTriggers"] = reflect.ValueOf(newAutomationTriggers(nil, nil, nil, core))

	trig, ep, err := automationTriggerServices(nil, nil, nil, "https://pc.example.com", nil, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	built["automationTriggerServices"] = reflect.ValueOf(trig)
	built["automationTriggerServices endpoints"] = field(reflect.ValueOf(ep), "triggers")

	act, ok := automationTriggerActivator(nil, nil, nil, core).(triggers.Activator)
	if !ok {
		t.Fatal("the activator is not the trigger service's")
	}
	built["automationTriggerActivator"] = field(reflect.ValueOf(act), "s")

	del, err := automationDeliverer(nil, nil, nil, "https://pc.example.com", nil, core)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := del.(endpoints.Deliverer)
	if !ok {
		t.Fatalf("Deliverer %T", del)
	}
	built["automationDeliverer"] = field(field(reflect.ValueOf(d), "s"), "triggers")

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
