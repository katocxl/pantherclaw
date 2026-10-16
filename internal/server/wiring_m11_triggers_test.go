// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import "testing"

// The ports this stream hands to core (TriggerActivator) and the engine
// (Deliverer) build without a database (G0 M11 part 2 D11).
func TestAutomationTriggerPortsBuild(t *testing.T) {
	if automationTriggerActivator(nil, nil, nil, nil) == nil {
		t.Fatal("no TriggerActivator")
	}
	d, err := automationDeliverer(nil, nil, nil, "https://pc.example.com", nil)
	if err != nil || d == nil {
		t.Fatalf("Deliverer: %v", err)
	}
	if _, err := automationDeliverer(nil, nil, nil, "not a url", nil); err == nil {
		t.Fatal("a Deliverer without a public URL")
	}
}
