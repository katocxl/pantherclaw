// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// BenchmarkRecordAndSeal is the in-process part of keeping replay inputs
// on the Authorize path: a held refund evaluated in memory as is, and
// evaluated through a Recorder whose recording is then sealed (encode,
// compress, AES-256-GCM). It reports the plaintext and sealed sizes.
func BenchmarkRecordAndSeal(b *testing.B) {
	s := pipelinetest.NewScenario(b, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	if err := s.W.SetPolicy([]pdomain.Rule{holdOver50}, nil); err != nil {
		b.Fatal(err)
	}
	req := refund(s, s.Run(g.ID, s.Alice), "ch_1", "70.00")
	b.Run("evaluate", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := (&pipeline.Pipeline{Reader: s.W}).Evaluate(b.Context(), req); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("evaluate+record+seal", func(b *testing.B) {
		sealer := recording.NewSealer(pccrypto.NewEnvelope(pipelinetest.TestDEKs{}))
		txn := ids.NewV7()
		var plain, sealed int
		b.ReportAllocs()
		for b.Loop() {
			rec := recording.NewRecorder(s.W, req)
			if _, err := (&pipeline.Pipeline{}).EvaluateWith(b.Context(), rec, req); err != nil {
				b.Fatal(err)
			}
			r, err := rec.Recording()
			if err != nil {
				b.Fatal(err)
			}
			out, err := sealer.Seal(b.Context(), s.Org, txn, 1, r)
			if err != nil {
				b.Fatal(err)
			}
			if plain == 0 {
				raw, _ := recording.Encode(r)
				plain, sealed = len(raw), len(out.Inputs)
			}
		}
		b.ReportMetric(float64(plain), "plain-bytes")
		b.ReportMetric(float64(sealed), "sealed-bytes")
	})
}
