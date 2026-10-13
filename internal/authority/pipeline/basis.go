// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
)

// Basis is what a decision was made on (F080): the policy version, every
// level of authority with its revision, the definition and the facts.
// Approvals bind its digest (HR-030, M5): any change makes a new basis.
type Basis struct {
	Policy     string            `json:"policy"`
	Levels     []gdomain.Version `json:"levels"`
	Definition string            `json:"definition"`
	Facts      string            `json:"facts"`
}

// Digest is "sha256:" + SHA-256 of the RFC 8785 canonical JSON of b.
func (b Basis) Digest() string {
	raw, err := json.Marshal(b)
	if err != nil {
		return ""
	}
	v := jsontext.Value(raw)
	if err := v.Canonicalize(); err != nil {
		return ""
	}
	sum := sha256.Sum256(v)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *state) basis() Basis {
	b := Basis{Policy: "none", Levels: s.chain.Versions(), Definition: s.a.Definition.Digest, Facts: fdomain.Digest(s.used)}
	if b.Levels == nil {
		b.Levels = []gdomain.Version{}
	}
	if s.policy != nil {
		b.Policy = s.policy.Version
	}
	return b
}

// bindingBasis is the basis an approval binds: the decision's basis with
// its facts replaced by the members the approval binds (HR-030 option B,
// founder decision 2026-10-13). The receipts keep the whole basis, with
// every fact and when it was observed.
func (s *state) bindingBasis(bound []apdomain.BoundFact) Basis {
	b := s.basis()
	b.Facts = apdomain.BoundFactsDigest(bound)
	return b
}
