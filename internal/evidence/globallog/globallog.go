// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package globallog keeps the deployment-wide root log and has public
// witnesses cosign it (G0 M35 D1041, FQ35-3; HR-781..783).
//
// Anchoring builds each period's global tree afresh over the orgs' blinded
// leaves, so the anchors on their own are not an append-only log. This log
// is: its leaves are the anchors' global roots in period order (leaf hash
// RFC 9162 SHA-256(0x00 ‖ root)), stored as C2SP tlog tiles of height 8,
// and each growth gets a C2SP checkpoint of origin "<log origin>/global"
// signed by the global_log key (Ed25519), after an RFC 9162 consistency
// proof from the previous checkpoint verified. Nothing in it names an org.
//
// Witnesses (c2sp.org/tlog-witness) receive only this log's checkpoints,
// never an org's (FQ35-3, HR-782): add-checkpoint with the size the witness
// last cosigned and the consistency proof from it. Their cosignature/v1
// lines are verified against the configured keys before they are kept.
//
// Nothing here is on the authorization path: the job runs in the worker,
// reads anchors and writes only this log, its cosignatures and the platform
// audit (design decision 20). Witness responses are never logged.
package globallog

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
	"github.com/katocxl/pantherclaw/internal/evidence/witness"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Limits.
const (
	// MaxLeavesPerAppend bounds the anchors one append adds.
	MaxLeavesPerAppend = 1024
	// witnessTimeout bounds one witness exchange.
	witnessTimeout = 30 * time.Second
)

// Failure codes of the platform audit events.
const (
	CodeLogInconsistent  = "GLOBAL_LOG_INCONSISTENT"
	CodeCheckpointBad    = "GLOBAL_CHECKPOINT_INVALID"
	CodeWitnessFailed    = "WITNESS_FAILED"
	CodeWitnessRefused   = "WITNESS_REFUSED"
	CodeWitnessUnknown   = "WITNESS_UNKNOWN_LOG"
	CodeWitnessAhead     = "WITNESS_AHEAD"
	CodeWitnessInvalid   = "WITNESS_COSIGNATURE_INVALID"
	CodeThresholdNotMet  = "WITNESS_THRESHOLD_NOT_MET"
	CodeNoGlobalLogKey   = "KEY_UNAVAILABLE"
	originSuffix         = "/global"
	maxConflictRetries   = 1
	defaultTickInterval  = 5 * time.Minute
	tickTimeoutAllowance = 9 * time.Minute
)

// Actor records the log's failures in the platform audit.
var Actor = domain.Actor{Type: "system", ID: "evidence-global-log"}

// ErrNoSigner reports a missing active global_log key.
var ErrNoSigner = errors.New("globallog: no active global_log key")

// Origin returns the root log's checkpoint origin for a deployment's log
// origin (PAP-1 §9.4).
func Origin(logOrigin string) string { return logOrigin + originSuffix }

// Service appends anchors to the root log and has it witnessed.
type Service struct {
	Pool *db.Pool
	Keys *keys.Registry
	// LogOrigin is evidence.log_origin.
	LogOrigin string
	// Witnesses are evidence.witnesses; Threshold is
	// evidence.witness_threshold.
	Witnesses []*witness.Client
	Threshold int
	Clock     clock.Clock
	Log       *slog.Logger
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return pclog.Discard()
	}
	return s.Log
}

func (s *Service) now() time.Time {
	if s.Clock == nil {
		return time.Now().UTC()
	}
	return s.Clock.Now()
}

// Origin is the root log's checkpoint origin.
func (s *Service) Origin() string { return Origin(s.LogOrigin) }

// Tiles reads the root log's tiles through q (merkle.TileReader). q may be
// a global or a tenant transaction's: the tiles hold no tenant data.
type Tiles struct{ Q *dbq.Queries }

// ReadTile implements merkle.TileReader.
func (t Tiles) ReadTile(ctx context.Context, id merkle.TileID) ([]byte, error) {
	b, err := t.Q.ReadGlobalLogTile(ctx, int16(id.Level), int64(id.Index)) //nolint:gosec // G115: level ≤ 63, index < 2^56
	if db.IsNoRows(err) || (err == nil && len(b) < id.Width*merkle.HashSize) {
		return nil, merkle.ErrTileNotFound
	}
	return b, err
}

// signer returns the note signer of the active global_log key.
func (s *Service) signer() (note.Signer, string, error) {
	ks := s.Keys.Keys(keys.PurposeGlobalLog)
	if len(ks) == 0 || ks[0].State != keys.StateActive {
		return nil, "", ErrNoSigner
	}
	sg, err := note.NewEd25519Signer(s.Origin(), ks[0].Private.Reveal())
	if err != nil {
		return nil, "", err
	}
	return sg, ks[0].KID, nil
}

// Verifiers returns the Ed25519 verifiers of every global_log key the
// keystore holds, retiring and revoked ones included: they check that a
// stored checkpoint is the note this deployment signed.
func (s *Service) Verifiers(ctx context.Context) ([]note.Verifier, error) {
	ks, err := keystore.PublishedKeys(ctx, s.Pool, []keys.Purpose{keys.PurposeGlobalLog})
	if err != nil {
		return nil, err
	}
	out := make([]note.Verifier, 0, len(ks))
	for _, k := range ks {
		v, err := note.NewEd25519Verifier(s.Origin(), k.Public)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// IntegrityError is a mismatch in the stored log: nothing is signed.
type IntegrityError struct {
	Code   string
	Detail string
}

func (e *IntegrityError) Error() string { return "globallog: " + e.Code + ": " + e.Detail }

// Appended is what Append did.
type Appended struct {
	Size  uint64 // the log's size afterwards
	Added int    // leaves added
}

// Append adds every anchor not in the log yet as a leaf, in period order,
// and signs a checkpoint of the new tree after checking it extends the
// previous checkpoint. One appender runs at a time (an advisory lock).
func (s *Service) Append(ctx context.Context) (Appended, error) {
	sg, kid, err := s.signer()
	if err != nil {
		return Appended{}, err
	}
	vs, err := s.Verifiers(ctx)
	if err != nil {
		return Appended{}, err
	}
	var out Appended
	err = s.Pool.InGlobalTx(ctx, db.GlobalLog, func(ctx context.Context, tx db.GlobalTx) error {
		out = Appended{}
		q := dbq.New(tx)
		if err := q.LockGlobalLog(ctx); err != nil {
			return err
		}
		size, err := q.GlobalLogSize(ctx)
		if err != nil {
			return err
		}
		old := uint64(size) //nolint:gosec // G115: ≥ 0
		out.Size = old
		var prevRoot merkle.Hash
		var prevSize uint64
		if cp, err := q.LatestGlobalCheckpoint(ctx); err == nil {
			c, _, err := note.OpenCheckpoint(cp.Note, s.Origin(), vs...)
			root, rerr := merkle.HashFromBytes(cp.RootHash)
			if err != nil || rerr != nil || c.Size != uint64(cp.TreeSize) || !c.Root.Equal(root) { //nolint:gosec // G115: > 0
				return &IntegrityError{Code: CodeCheckpointBad, Detail: fmt.Sprintf("the stored checkpoint of size %d does not verify", cp.TreeSize)}
			}
			if c.Size != old {
				return &IntegrityError{Code: CodeLogInconsistent, Detail: fmt.Sprintf("the log holds %d leaves, its checkpoint %d", old, c.Size)}
			}
			prevRoot, prevSize = c.Root, c.Size
		} else if !db.IsNoRows(err) {
			return err
		} else if old != 0 {
			return &IntegrityError{Code: CodeLogInconsistent, Detail: fmt.Sprintf("the log holds %d leaves and no checkpoint", old)}
		}
		rows, err := q.AnchorsNotInGlobalLog(ctx, MaxLeavesPerAppend)
		if err != nil || len(rows) == 0 {
			return err
		}
		leaves := make([]merkle.Hash, len(rows))
		for i, r := range rows {
			if len(r.Root) != merkle.HashSize {
				return &IntegrityError{Code: CodeLogInconsistent, Detail: "an anchor's root is not 32 bytes"}
			}
			leaves[i] = merkle.LeafHash(r.Root)
			if err := q.InsertGlobalLogLeaf(ctx, int64(old)+int64(i), r.ID, r.Root); err != nil { //nolint:gosec // G115: bounded
				return err
			}
		}
		t := Tiles{Q: q}
		tiles, err := merkle.AppendTiles(ctx, t, old, leaves) //nolint:contextcheck // tiles read in this transaction
		if err != nil {
			return err
		}
		for _, tl := range tiles {
			if err := q.InsertGlobalLogTile(ctx, dbq.InsertGlobalLogTileParams{
				Level: int16(tl.Level), TileIndex: int64(tl.Index), Width: int16(tl.Width), Hashes: tl.Hashes, //nolint:gosec // G115: bounded by the format
			}); err != nil {
				return err
			}
		}
		newSize := old + uint64(len(leaves))
		root, err := merkle.Root(ctx, t, newSize)
		if err != nil {
			return err
		}
		if prevSize > 0 {
			proof, err := merkle.ConsistencyProof(ctx, t, prevSize, newSize)
			if err != nil {
				return err
			}
			if err := merkle.VerifyConsistency(prevSize, newSize, proof, prevRoot, root); err != nil {
				return &IntegrityError{Code: CodeLogInconsistent, Detail: fmt.Sprintf("size %d does not extend size %d: %v", newSize, prevSize, err)}
			}
		}
		signed, err := note.SignCheckpoint(note.Checkpoint{Origin: s.Origin(), Size: newSize, Root: root}, sg)
		if err != nil {
			return err
		}
		if err := q.InsertGlobalCheckpoint(ctx, dbq.InsertGlobalCheckpointParams{
			TreeSize: int64(newSize), RootHash: root[:], Note: signed, Kid: kid, //nolint:gosec // G115: bounded
		}); err != nil {
			return err
		}
		out.Size, out.Added = newSize, len(leaves)
		return nil
	})
	var ie *IntegrityError
	if errors.As(err, &ie) {
		s.fail(ctx, ie.Code, "", 0)
	}
	if err == nil && out.Added > 0 {
		s.log().InfoContext(ctx, "evidence.global_log_appended", slog.Uint64("size", out.Size), slog.Int("added", out.Added))
	}
	return out, err
}

// fail logs and audits a failure of the log or a witness (codes and names
// only, never a response).
func (s *Service) fail(ctx context.Context, code, witnessName string, size uint64) {
	attrs := []any{slog.String("code", code)}
	details := map[string]string{"code": code}
	if witnessName != "" {
		attrs = append(attrs, slog.String("witness", witnessName))
		details["witness"] = witnessName
	}
	if size > 0 {
		attrs = append(attrs, slog.Uint64("size", size))
		details["size"] = fmt.Sprint(size)
	}
	s.log().WarnContext(ctx, "evidence.global_log_failed", attrs...)
	kind := auditkind.EvidenceGlobalLogFailed
	if witnessName != "" {
		kind = auditkind.EvidenceWitnessFailed
	}
	if code == CodeThresholdNotMet {
		kind = auditkind.EvidenceWitnessThresholdNotMet
	}
	err := s.Pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: kind, Actor: Actor, Outcome: audit.Failure, ReasonCode: code,
			Object: &audit.Object{Type: "global_log", ID: s.Origin()}, Details: details,
		})
		return err
	})
	if err != nil {
		s.log().ErrorContext(ctx, "evidence.global_log_audit_failed", slog.String("error", err.Error()))
	}
}

// latest returns the newest checkpoint.
func (s *Service) latest(ctx context.Context) (dbq.PcGlobalCheckpoint, bool, error) {
	var cp dbq.PcGlobalCheckpoint
	err := s.Pool.InGlobalTx(ctx, db.GlobalLog, func(ctx context.Context, tx db.GlobalTx) error {
		var err error
		cp, err = dbq.New(tx).LatestGlobalCheckpoint(ctx)
		return err
	}, db.ReadOnly())
	if db.IsNoRows(err) {
		return cp, false, nil
	}
	return cp, err == nil, err
}

// proof returns the consistency proof from size old to size n.
func (s *Service) proof(ctx context.Context, old, n uint64) ([]merkle.Hash, error) {
	if old == 0 || old == n {
		return nil, nil
	}
	var p []merkle.Hash
	err := s.Pool.InGlobalTx(ctx, db.GlobalLog, func(ctx context.Context, tx db.GlobalTx) error {
		var err error
		p, err = merkle.ConsistencyProof(ctx, Tiles{Q: dbq.New(tx)}, old, n)
		return err
	}, db.ReadOnly())
	return p, err
}

// Witness asks every configured witness to cosign the newest checkpoint,
// keeps the verified cosignatures, and reports when fewer than the
// threshold have cosigned it. Only the root log's checkpoint is ever sent
// (HR-782).
func (s *Service) Witness(ctx context.Context) error {
	if len(s.Witnesses) == 0 {
		return nil
	}
	cp, ok, err := s.latest(ctx)
	if err != nil || !ok {
		return err
	}
	size := uint64(cp.TreeSize) //nolint:gosec // G115: > 0
	n, err := note.Parse(cp.Note)
	if err != nil {
		return err
	}
	for _, w := range s.Witnesses {
		if err := s.witnessOne(ctx, w, cp.Note, n.Text, size); err != nil {
			return err
		}
	}
	var count int
	err = s.Pool.InGlobalTx(ctx, db.GlobalLog, func(ctx context.Context, tx db.GlobalTx) error {
		rows, err := dbq.New(tx).GlobalCosignatures(ctx, cp.TreeSize)
		count = len(rows)
		return err
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	if s.Threshold > 0 && count < s.Threshold {
		s.fail(ctx, CodeThresholdNotMet, "", size)
	}
	return nil
}

// witnessOne exchanges one checkpoint with one witness. Witness failures
// are outcomes (logged and audited); errors are storage failures only.
func (s *Service) witnessOne(ctx context.Context, w *witness.Client, signed []byte, text string, size uint64) error {
	var last uint64
	err := s.Pool.InGlobalTx(ctx, db.GlobalLog, func(ctx context.Context, tx db.GlobalTx) error {
		v, err := dbq.New(tx).LastWitnessedSize(ctx, w.Name)
		if db.IsNoRows(err) {
			return nil
		}
		last = uint64(v) //nolint:gosec // G115: > 0
		return err
	}, db.ReadOnly())
	if err != nil || last >= size {
		return err
	}
	old := last
	var cosigs []witness.Cosignature
	for attempt := 0; ; attempt++ {
		proof, err := s.proof(ctx, old, size)
		if err != nil {
			return err
		}
		wctx, cancel := context.WithTimeout(ctx, witnessTimeout)
		cosigs, err = w.AddCheckpoint(wctx, witness.Request{OldSize: old, Proof: proof, Note: signed}, text)
		cancel()
		var conflict *witness.ConflictError
		switch {
		case err == nil:
		case errors.As(err, &conflict) && conflict.Size > size:
			s.fail(ctx, CodeWitnessAhead, w.Name, size)
			return nil
		case errors.As(err, &conflict) && attempt < maxConflictRetries && conflict.Size != old:
			old = conflict.Size
			continue
		case errors.Is(err, witness.ErrUnknownLog):
			s.fail(ctx, CodeWitnessUnknown, w.Name, size)
			return nil
		case errors.Is(err, witness.ErrRefused), errors.Is(err, witness.ErrConflict):
			s.fail(ctx, CodeWitnessRefused, w.Name, size)
			return nil
		case errors.Is(err, note.ErrInvalidSignature), errors.Is(err, note.ErrUnverified), errors.Is(err, note.ErrMalformed):
			s.fail(ctx, CodeWitnessInvalid, w.Name, size)
			return nil
		default:
			s.fail(ctx, CodeWitnessFailed, w.Name, size)
			return nil
		}
		break
	}
	return s.Pool.InGlobalTx(ctx, db.GlobalLog, func(ctx context.Context, tx db.GlobalTx) error {
		q := dbq.New(tx)
		for _, c := range cosigs {
			if err := q.InsertGlobalCosignature(ctx, dbq.InsertGlobalCosignatureParams{
				TreeSize: int64(size), Witness: w.Name, KeyID: int64(c.KeyID), SignedAt: c.Time, Line: c.Line, //nolint:gosec // G115: bounded
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// Tick appends new anchors, then has the newest checkpoint witnessed.
func (s *Service) Tick(ctx context.Context) error {
	if _, err := s.Append(ctx); err != nil {
		var ie *IntegrityError
		if !errors.As(err, &ie) {
			return err
		}
		s.log().ErrorContext(ctx, "evidence.global_log_append_failed", slog.String("code", ie.Code))
	}
	return s.Witness(ctx)
}

// Published is the newest checkpoint with every kept cosignature line.
type Published struct {
	Size uint64
	// Note is the signed checkpoint with the witnesses' lines appended.
	Note []byte
	// Cosignatures counts the witness lines.
	Cosignatures int
}

// Latest returns the newest checkpoint with its cosignatures, read through
// q (a global or a tenant transaction's), or false when there is none.
func Latest(ctx context.Context, q *dbq.Queries) (Published, bool, error) {
	cp, err := q.LatestGlobalCheckpoint(ctx)
	if db.IsNoRows(err) {
		return Published{}, false, nil
	} else if err != nil {
		return Published{}, false, err
	}
	rows, err := q.GlobalCosignatures(ctx, cp.TreeSize)
	if err != nil {
		return Published{}, false, err
	}
	lines := make([]string, len(rows))
	for i, r := range rows {
		lines[i] = r.Line
	}
	return Published{Size: uint64(cp.TreeSize), Note: witness.AppendLines(cp.Note, lines), Cosignatures: len(rows)}, true, nil //nolint:gosec // G115: > 0
}
