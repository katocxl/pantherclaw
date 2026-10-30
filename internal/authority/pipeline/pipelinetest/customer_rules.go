// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipelinetest

import (
	"context"
	"crypto/sha256"
	"slices"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// SetCustomerRules makes rules the org's ACTIVE customer consequence rules
// (G0 M17 D106), each with the reference package's definition of its
// consequence operation, at version 1.
func (w *World) SetCustomerRules(rules ...defs.ConsequenceRule) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.customer = nil
	for _, r := range rules {
		d, _ := w.pkg.Definition(r.Consequence.Operation)
		ref := consequences.CustomerRef{Version: 1, Digest: sha256.Sum256([]byte(r.ID))}
		if d != nil {
			ref.Pin.Package, ref.Pin.Version, ref.Pin.Digest = w.pkg.Name, w.pkg.Version, d.Digest
		}
		w.customer = append(w.customer, consequences.Rule{ConsequenceRule: r, Definition: d, Source: consequences.SourceCustomer, Customer: &ref})
	}
}

// CustomerRules implements pipeline.Reader.
func (w *World) CustomerRules(context.Context, ids.OrgID) ([]consequences.Rule, error) {
	if err := w.fail("CustomerRules"); err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.customer), nil
}
