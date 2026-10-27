// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package datarequests

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	MaxPartBytes        = 64 << 20
	MaxExportBytes      = 2 << 30
	fileChunkBytes      = 4 << 20
	maxParts            = 64
	ExportFormat        = "pantherclaw.export/v1"
	ExportJWSType       = "pap-export+jwt"
	ExportCosignContext = "pantherclaw.export/v1"
	maxExportFiles      = 20_000
)

type ExportPart struct {
	Number int32  `json:"number"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type ExportFile struct {
	Path   string `json:"path"`
	Part   int32  `json:"part"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Projection struct {
	Table   string   `json:"table"`
	Columns []string `json:"columns"`
}
type ExportManifest struct {
	Format          string       `json:"format"`
	RegistryVersion int          `json:"registry_version"`
	Org             string       `json:"org"`
	Request         string       `json:"request"`
	CreatedAt       time.Time    `json:"created_at"`
	ExpiresAt       time.Time    `json:"expires_at"`
	LedgerThrough   int64        `json:"ledger_through"`
	Projections     []Projection `json:"projections"`
	Excluded        []string     `json:"excluded"`
	Parts           []ExportPart `json:"parts"`
	Files           []ExportFile `json:"files"`
	Cosign          *pack.Cosign `json:"mldsa,omitzero"`
}

type archiveBuilder struct {
	q        *dbq.Queries
	org      ids.OrgID
	id       ids.UUID
	manifest *ExportManifest
	buf      bytes.Buffer
	zip      *zip.Writer
	total    int64
}

func (b *archiveBuilder) add(ctx context.Context, name string, content []byte) error {
	if len(content) > MaxPartBytes-4096 || len(b.manifest.Files) >= maxExportFiles {
		return ErrTooLarge
	}
	if b.zip != nil && b.buf.Len()+len(content)+4096 > MaxPartBytes {
		if err := b.flush(ctx); err != nil {
			return err
		}
	}
	if b.zip == nil {
		b.zip = zip.NewWriter(&b.buf)
	}
	f, err := b.zip.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
	if err != nil {
		return err
	}
	if _, err = f.Write(content); err != nil {
		return err
	}
	h := sha256.Sum256(content)
	parts, err := partCount(b.manifest.Parts)
	if err != nil {
		return err
	}
	b.manifest.Files = append(b.manifest.Files, ExportFile{Path: name, Part: parts + 1, Size: int64(len(content)), SHA256: hex.EncodeToString(h[:])})
	return nil
}

func (b *archiveBuilder) flush(ctx context.Context) error {
	if b.zip == nil {
		return nil
	}
	if err := b.zip.Close(); err != nil {
		return err
	}
	n := b.buf.Len()
	if n > MaxPartBytes || b.total+int64(n) > MaxExportBytes || len(b.manifest.Parts) >= maxParts {
		return ErrTooLarge
	}
	parts, err := partCount(b.manifest.Parts)
	if err != nil {
		return err
	}
	part := parts + 1
	sum := sha256.Sum256(b.buf.Bytes())
	if err := b.q.InsertDataRequestPart(ctx, dbq.InsertDataRequestPartParams{OrgID: b.org, RequestID: b.id, Number: part, Content: b.buf.Bytes(), Sha256: sum[:]}); err != nil {
		return err
	}
	b.manifest.Parts = append(b.manifest.Parts, ExportPart{Number: part, Size: int64(n), SHA256: hex.EncodeToString(sum[:])})
	b.total += int64(n)
	b.zip = nil
	b.buf.Reset()
	return nil
}

// Build rechecks the exporting person's current authority, exports only
// reviewed projections and includes every chained evidence entry through
// the recorded ledger head, split into standard proof bundles.
func (s *Service) Build(ctx context.Context, org ids.OrgID, id ids.UUID) error {
	var request dbq.PcDataRequest
	var caller tapp.Caller
	var through int64
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		request, err = q.GetDataRequest(ctx, org, id)
		if err != nil {
			return err
		}
		if request.State != "BUILDING" {
			return nil
		}
		if request.CreatedBy == nil {
			return td.ErrPermissionDenied(td.PermDataExport)
		}
		u, err := q.GetUser(ctx, org, *request.CreatedBy)
		if err != nil {
			return err
		}
		if u.State != "ACTIVE" {
			return td.ErrPermissionDenied(td.PermDataExport)
		}
		principal := td.PrincipalRef{Kind: td.KindUser, ID: u.ID}
		bs, err := tapp.Bindings(ctx, q, org, principal)
		if err != nil {
			return err
		}
		caller = tapp.Caller{Subject: td.Subject{Org: org, Principal: principal, Bindings: bs}}
		if err := caller.Require(td.PermDataExport, td.OrgPath(org)); err != nil {
			return err
		}
		through, err = q.LedgerHeadSeq(ctx, org)
		return err
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	if request.State != "BUILDING" {
		return nil
	}
	ctx = tapp.WithCaller(ctx, caller)
	// The proof exporter bounds each standard bundle. Keep at most one
	// bundle in memory; never accumulate the org's full evidence history.
	bundles := s.Bundles
	if bundles == nil {
		return errors.New("datarequests: evidence exporter unavailable")
	}
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.LockDataRequest(ctx, org, id)
		if err != nil {
			return err
		}
		if r.State != "BUILDING" {
			return nil
		}
		// Revalidate the queued person's live authority in this snapshot.
		// The earlier lookup cannot authorize work after a queued role or
		// user revocation.
		u, err := q.GetUser(ctx, org, *request.CreatedBy)
		if err != nil {
			return err
		}
		if u.State != "ACTIVE" {
			return td.ErrPermissionDenied(td.PermDataExport)
		}
		bindings, err := tapp.Bindings(ctx, q, org, caller.Principal)
		if err != nil {
			return err
		}
		caller.Bindings = bindings
		if err := caller.Require(td.PermDataExport, td.OrgPath(org)); err != nil {
			return err
		}
		ctx = tapp.WithCaller(ctx, caller)
		if _, err := q.DeleteDataRequestParts(ctx, org, id); err != nil {
			return err
		}
		now, err := q.TenantDatabaseTime(ctx)
		if err != nil {
			return err
		}
		m := ExportManifest{
			Format: ExportFormat, RegistryVersion: 1, Org: org.String(), Request: id.String(), CreatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour), LedgerThrough: through,
			Excluded: []string{"credentials and sealed material", "DEKs and wrapped keys", "tokens and secret hashes", "browser and CLI session storage", "provider client secrets and connection authentication", "payload captures and raw evaluation inputs", "tables and columns outside the explicit projection registry"},
		}
		b := archiveBuilder{q: q, org: org, id: id, manifest: &m}
		for _, t := range exportTables {
			m.Projections = append(m.Projections, Projection{Table: t.Name, Columns: t.Columns})
			if err := exportTableRows(ctx, tx, &b, t); err != nil {
				return err
			}
		}
		for from, i := int64(1), 1; from <= through; from, i = from+evapp.MaxRange, i+1 {
			to := min(through, from+evapp.MaxRange-1)
			e, err := bundles.ExportBundleTx(ctx, tx, evapp.Selection{From: from, To: to}, 0)
			if err != nil {
				return err
			}
			if err := b.add(ctx, fmt.Sprintf("evidence/%06d.json", i), e.Bundle); err != nil {
				return err
			}
		}
		if err := b.flush(ctx); err != nil {
			return err
		}
		if s.Keys == nil {
			return errors.New("datarequests: no signing registry")
		}
		payload, err := pack.Canonical(m)
		if err != nil {
			return err
		}
		if s.Cosign {
			alt := s.Keys.AltKeys(keys.PurposeCheckpointsPQ)
			if len(alt) == 0 || alt[0].State != keys.StateActive {
				return errors.New("datarequests: no ML-DSA signer")
			}
			priv, ok := alt[0].Private.Reveal().(*mldsa.PrivateKey)
			if !ok {
				return errors.New("datarequests: invalid ML-DSA signer")
			}
			sig, err := priv.Sign(nil, payload, &mldsa.Options{Context: ExportCosignContext})
			if err != nil {
				return err
			}
			m.Cosign = &pack.Cosign{Algorithm: "ML-DSA-65", Kid: alt[0].KID, Signature: sig}
			payload, err = pack.Canonical(m)
			if err != nil {
				return err
			}
		}
		signer, err := s.Keys.Signer(keys.PurposeEvidencePacks)
		if err != nil {
			return err
		}
		manifest, err := signer.Sign(ExportJWSType, payload)
		if err != nil {
			return err
		}
		if len(manifest) > 1<<20 {
			return ErrTooLarge
		}
		parts, err := partCount(m.Parts)
		if err != nil {
			return err
		}
		n, err := q.MarkExportReady(ctx, dbq.MarkExportReadyParams{OrgID: org, ID: id, ReadyAt: &now, Parts: parts, TotalSize: b.total, Manifest: &manifest})
		if err != nil {
			return err
		}
		if n != 1 {
			return db.ErrLostRace
		}
		return requestAudit(ctx, tx, caller, "data.export_ready", id)
	}, db.RepeatableRead())
	if errors.Is(err, ErrTooLarge) {
		return s.failExport(ctx, org, id, "EXPORT_TOO_LARGE")
	}
	return err
}

func exportTableRows(ctx context.Context, tx db.TenantTx, b *archiveBuilder, t exportTable) error {
	cols := make([]string, len(t.Columns))
	for i, col := range t.Columns {
		cols[i] = pgx.Identifier{col}.Sanitize()
	}
	key := "id"
	if t.Name == "org_entitlements" {
		key = "org_id"
	}
	query := "SELECT " + pgx.Identifier{key}.Sanitize() + ", to_jsonb(x) FROM (SELECT " + strings.Join(cols, ",") + " FROM " + pgx.Identifier{"pc", t.Name}.Sanitize() + " WHERE org_id=$1 AND " + pgx.Identifier{key}.Sanitize() + ">$2 ORDER BY " + pgx.Identifier{key}.Sanitize() + " LIMIT 1) x"
	var after ids.UUID
	var chunk bytes.Buffer
	number := 0
	flush := func() error {
		number++
		err := b.add(ctx, fmt.Sprintf("tables/%s/%06d.jsonl", t.Name, number), chunk.Bytes())
		chunk.Reset()
		return err
	}
	for {
		rows, err := tx.Query(ctx, query, tx.OrgID(), after)
		if err != nil {
			return err
		}
		type row struct {
			id  ids.UUID
			raw []byte
		}
		page := []row{}
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.raw); err != nil {
				rows.Close()
				return err
			}
			page = append(page, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(page) == 0 {
			break
		}
		for _, r := range page {
			v := jsontext.Value(r.raw)
			if err := v.Canonicalize(); err != nil {
				return err
			}
			if len(v) > MaxPartBytes-4096 {
				return ErrTooLarge
			}
			if chunk.Len() > 0 && chunk.Len()+len(v)+1 > fileChunkBytes {
				if err := flush(); err != nil {
					return err
				}
			}
			chunk.Write(v)
			chunk.WriteByte('\n')
			after = r.id
		}
	}
	if chunk.Len() > 0 || number == 0 {
		return flush()
	}
	return nil
}

func (s *Service) failExport(ctx context.Context, org ids.OrgID, id ids.UUID, code string) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).FailDataRequest(ctx, &code, org, id)
		return err
	})
}

// partCount is the number of parts as the int32 the manifest and the
// database store. flush refuses a part beyond maxParts, so a larger count
// means a broken builder and is refused rather than truncated.
func partCount(parts []ExportPart) (int32, error) {
	n := len(parts)
	if n < 0 || n > maxParts {
		return 0, ErrTooLarge
	}
	return int32(n), nil
}
