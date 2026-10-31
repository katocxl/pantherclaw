// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package hubrpc_test

import (
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
)

// Covers: F843

func request(index, item int) *pantherclawv1.InstallHubItemRequest {
	return &pantherclawv1.InstallHubItemRequest{IndexJws: strings.Repeat("a", index), Item: make([]byte, item)}
}

// TestLargestIndexAndItemFitOneRPC: what the format allows can be installed
// (D100a), and hub.proto holds the same two limits.
func TestLargestIndexAndItemFitOneRPC(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	largest := request(domain.MaxIndexBytes, domain.MaxItemBytes)
	if err := v.Validate(largest); err != nil {
		t.Fatalf("largest request refused: %v", err)
	}
	if n := proto.Size(largest); n > rpc.MaxRequestBytes {
		t.Fatalf("largest request is %d bytes, over the %d one RPC takes", n, rpc.MaxRequestBytes)
	}
	// A template's usual parameters fit in what the limits leave free.
	largest.Params = map[string]string{
		"environment":    "production",
		"agent":          "01890000-0000-7000-8000-00000000000a",
		"repos":          strings.Repeat("acme/service-name,", 40),
		"default_branch": "main",
		"time_zone":      "Europe/Amsterdam",
	}
	if err := v.Validate(largest); err != nil {
		t.Fatalf("largest request with parameters refused: %v", err)
	}
	if n := proto.Size(largest); n > rpc.MaxRequestBytes {
		t.Fatalf("largest request with parameters is %d bytes, over the %d one RPC takes", n, rpc.MaxRequestBytes)
	}
	if err := v.Validate(request(domain.MaxIndexBytes+1, 1)); err == nil {
		t.Error("hub.proto took an index over MaxIndexBytes")
	}
	if err := v.Validate(request(1, domain.MaxItemBytes+1)); err == nil {
		t.Error("hub.proto took an item over MaxItemBytes")
	}
}
