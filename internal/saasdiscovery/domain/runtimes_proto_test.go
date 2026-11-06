// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"strings"
	"testing"

	"buf.build/go/protovalidate"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
)

func TestRuntimeFindingsPassTheSubmissionContract(t *testing.T) {
	for _, kind := range []string{domain.KindAgentCoreRuntime, domain.KindVertexReasoningEngine, domain.KindFoundryAgent, "unknown_runtime"} {
		t.Run(kind, func(t *testing.T) {
			err := protovalidate.Validate(&pantherclawv1.ScanFinding{Kind: kind, Key: strings.Repeat("a", 64)})
			if (err == nil) != (kind != "unknown_runtime") {
				t.Fatalf("validation for %q: %v", kind, err)
			}
		})
	}
}
