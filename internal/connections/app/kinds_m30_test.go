// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"errors"
	"testing"

	"buf.build/go/protovalidate"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestHR704_AConnectionTakesOnlyDimensionsAnEmbeddingCarries (G0 M30
// D1213a): a vectorstore connection of 12288 dimensions, the most items a
// float_array carries, is accepted at create by both the API's field rule
// and the connection check; 12289 is refused by each.
func TestHR704_AConnectionTakesOnlyDimensionsAnEmbeddingCarries(t *testing.T) {
	if capp.MaxVectorstoreDimensions != defs.MaxFloatItems {
		t.Fatalf("dimensions %d, float_array items %d", capp.MaxVectorstoreDimensions, defs.MaxFloatItems)
	}
	cfg := func(d int32) capp.VectorstoreConfig {
		return capp.VectorstoreConfig{
			Host: "vectors.example.test", Database: "rag", User: "writer", SSLMode: capp.SSLVerifyFull,
			Schema: "rag", Table: "docs", Dimensions: d, Distance: "cosine",
		}
	}
	msg := func(d int32) *pb.VectorstoreConfig {
		return &pb.VectorstoreConfig{
			Host: "vectors.example.test", Database: "rag", User: "writer", Sslmode: capp.SSLVerifyFull,
			SchemaName: "rag", TableName: "docs", Dimensions: d, Distance: "cosine",
		}
	}
	if _, err := cfg(12288).Check(); err != nil {
		t.Fatalf("12288 refused: %v", err)
	}
	if err := protovalidate.Validate(msg(12288)); err != nil {
		t.Fatalf("12288 refused by the API: %v", err)
	}
	if _, err := cfg(12289).Check(); !errors.Is(err, capp.ErrVectorstoreConfig) {
		t.Fatalf("12289: %v", err)
	}
	var verr *protovalidate.ValidationError
	if err := protovalidate.Validate(msg(12289)); !errors.As(err, &verr) {
		t.Fatalf("12289 by the API: %v", err)
	}
}
