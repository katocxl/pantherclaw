// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/cases/domain"
	"github.com/katocxl/pantherclaw/internal/cases/store"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ExportFormat names the case export document.
const ExportFormat = "pantherclaw.case.v1"

// MaxExportEntries caps one export.
const MaxExportEntries = 10000

// Errors of the export.
var (
	ErrChainBroken = pcerr.New(pcerr.Internal, "CASE_CHAIN_BROKEN",
		"the case's entries do not chain to its head; nothing was exported")
	ErrTooLarge = pcerr.New(pcerr.FailedPrecondition, "CASE_TOO_LARGE", "the case has more entries than one export holds")
)

type exportRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type exportEntry struct {
	Seq         int64          `json:"seq"`
	ID          string         `json:"id"`
	LedgerEntry string         `json:"ledger_entry_id"`
	PrevHash    string         `json:"prev_hash"`
	Hash        string         `json:"entry_hash"`
	Superseded  bool           `json:"superseded,omitzero"`
	Body        jsontext.Value `json:"body"`
}

type exportCase struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Source        string `json:"source"`
	State         string `json:"state"`
	Owner         string `json:"owner,omitempty"`
	FollowUpOwner string `json:"follow_up_owner,omitempty"`
	Disposition   string `json:"disposition,omitempty"`
	Impact        string `json:"impact,omitempty"`
	Genesis       string `json:"genesis_hash"`
	HeadSeq       int64  `json:"head_seq"`
	HeadHash      string `json:"head_hash"`
	Created       string `json:"created_at"`
	Closed        string `json:"closed_at,omitempty"`
}

type exportDoc struct {
	Format     string        `json:"format"`
	Org        string        `json:"org"`
	Case       exportCase    `json:"case"`
	Entries    []exportEntry `json:"entries"`
	Evidence   []exportRef   `json:"evidence"`
	Links      []exportRef   `json:"links"`
	ExportedAt string        `json:"exported_at"`
	ExportedBy exportRef     `json:"exported_by"`
}

// Export is a case export for handoff (F249).
type Export struct {
	// Document is canonical JSON: the case, every entry's body with its
	// chain hashes and ledger entry id, and every evidence id they name.
	Document []byte
	// AuditEntry is the ledger entry that records the export.
	AuditEntry ids.UUID
}

func idStr(p *ids.UUID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

// Export exports case c (case.read and evidence.export over the case,
// HR-247). The chain is verified first; the export is audited.
func (s *Service) Export(ctx context.Context, c ids.UUID) (Export, error) {
	caller, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Export{}, err
	}
	if err := cases(ctx, s.Editions); err != nil {
		return Export{}, err
	}
	var out Export
	err = s.Pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		sc := scope{c: caller, q: dbq.New(tx)}
		k, agents, err := sc.readable(ctx, tx, c)
		if err != nil {
			return err
		}
		ok, err := sc.over(ctx, td.PermEvidenceExport, agents)
		if err != nil {
			return err
		}
		if !ok {
			return ErrForbidden
		}
		if k.HeadSeq > MaxExportEntries {
			return ErrTooLarge
		}
		if err := store.VerifyChain(ctx, tx, c); errors.Is(err, store.ErrChainBroken) {
			return ErrChainBroken
		} else if err != nil {
			return err
		}
		superseded, err := store.Superseded(ctx, tx, c)
		if err != nil {
			return err
		}
		doc := exportDoc{
			Format: ExportFormat, Org: caller.Org.String(), Entries: []exportEntry{}, Evidence: []exportRef{}, Links: []exportRef{},
			ExportedAt: time.Now().UTC().Format(time.RFC3339Nano),
			ExportedBy: exportRef{Kind: caller.Actor().Type, ID: caller.Actor().ID},
			Case: exportCase{
				ID: k.ID.String(), Title: k.Title, Source: k.Source, State: string(k.State), Owner: idStr(k.Owner),
				FollowUpOwner: idStr(k.FollowUpOwner), Disposition: string(k.Disposition), Impact: string(k.Impact),
				Genesis: hex.EncodeToString(domain.GenesisHash(k.ID)), HeadSeq: k.HeadSeq, HeadHash: hex.EncodeToString(k.HeadHash),
				Created: k.Created.UTC().Format(time.RFC3339Nano),
			},
		}
		if k.Closed != nil {
			doc.Case.Closed = k.Closed.UTC().Format(time.RFC3339Nano)
		}
		seenEv, seenLink := map[exportRef]bool{}, map[exportRef]bool{}
		for seq := int64(0); ; {
			es, err := store.Entries(ctx, tx, c, seq, store.MaxEntriesPage)
			if err != nil {
				return err
			}
			for _, e := range es {
				doc.Entries = append(doc.Entries, exportEntry{
					Seq: e.Seq, ID: e.ID.String(), LedgerEntry: e.LedgerEntry.String(), PrevHash: hex.EncodeToString(e.PrevHash),
					Hash: hex.EncodeToString(e.Hash), Superseded: superseded[e.ID], Body: jsontext.Value(e.Body),
				})
				for _, r := range e.Evidence {
					x := exportRef{Kind: r.Kind, ID: r.ID.String()}
					if !seenEv[x] {
						seenEv[x] = true
						doc.Evidence = append(doc.Evidence, x)
					}
				}
				if e.Ref != nil {
					x := exportRef{Kind: e.Ref.Kind, ID: e.Ref.ID}
					if !seenLink[x] {
						seenLink[x] = true
						doc.Links = append(doc.Links, x)
					}
				}
				seq = e.Seq
			}
			if len(es) < store.MaxEntriesPage {
				break
			}
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		v := jsontext.Value(raw)
		if err := v.Canonicalize(); err != nil {
			return err
		}
		out.Document = v
		ev, err := audit.Record(ctx, tx, audit.Event{
			Name: "case.exported", Actor: caller.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "case", ID: c.String()},
			Details: map[string]string{
				"entries":   strconv.Itoa(len(doc.Entries)),
				"head_hash": doc.Case.HeadHash,
			},
		})
		if err != nil {
			return err
		}
		out.AuditEntry = ev.ID
		return nil
	})
	return out, err
}
