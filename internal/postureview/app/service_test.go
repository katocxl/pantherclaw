// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/postureview/domain"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type partial struct {
	out []domain.Finding
	err error
}

func (partial) Name() domain.Source { return domain.SourceCatalog }

func (s partial) Findings(context.Context, ports.Viewer, domain.Filter) ([]domain.Finding, bool, error) {
	return s.out, false, s.err
}

// TestD277_RestrictedSourceKeepsWhatItFound: a source that answers for the
// viewer's reach and also says it is restricted keeps its findings, counted
// and held to that reach; a fatal error still drops them; an edition refusal
// counts nothing.
// Covers: F863
func TestD277_RestrictedSourceKeepsWhatItFound(t *testing.T) {
	outside := ids.NewV7()
	src := partial{
		err: td.ErrPermissionDenied(td.PermCatalogManage),
		out: []domain.Finding{{SourceID: "in-reach", Kind: "k"}, {SourceID: "outside", Kind: "k", AgentID: &outside}},
	}
	v := ports.Viewer{Posture: ports.Reach{Org: true}}
	s := &Service{Sources: []ports.Source{src}}

	found, statuses, err := s.collect(context.Background(), v, domain.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].SourceID != "in-reach" {
		t.Errorf("found: %+v", found)
	}
	if len(statuses) != 1 || statuses[0].State != SourceRestricted || statuses[0].Findings != 1 {
		t.Errorf("status: %+v", statuses)
	}

	boom := errors.New("boom")
	src.err = boom
	s.Sources = []ports.Source{src}
	if found, _, err := s.collect(context.Background(), v, domain.Filter{}); !errors.Is(err, boom) || found != nil {
		t.Errorf("fatal: %+v %v", found, err)
	}

	src.err = ErrEdition
	s.Sources = []ports.Source{src}
	found, statuses, err = s.collect(context.Background(), v, domain.Filter{})
	if err != nil || len(found) != 0 || statuses[0].State != SourceNotInEdition || statuses[0].Findings != 0 {
		t.Errorf("edition: %+v %+v %v", found, statuses, err)
	}
}
