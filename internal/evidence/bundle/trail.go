// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
	"github.com/katocxl/pantherclaw/internal/evidence/receiptsig"
	"github.com/katocxl/pantherclaw/internal/evidence/witness"
)

// GlobalLog proves that the bundle's anchor is in the deployment-wide root
// log (G0 M35 D1041): the log's signed checkpoint, origin
// "<log origin>/global", with the witnesses' cosignature/v1 lines appended,
// and the inclusion proof of the anchor's global root at leaf Index.
type GlobalLog struct {
	Checkpoint string   `json:"checkpoint"`
	Index      uint64   `json:"index"`
	Proof      [][]byte `json:"proof"`
}

// ReceiptSigs is the PAP-1 §9.4 sigs[] of one of the bundle's receipts,
// named by the hex SHA-256 of its compact JWS (G0 M35 D1042).
type ReceiptSigs struct {
	Receipt string         `json:"receipt_sha256"`
	Sigs    jsontext.Value `json:"sigs"`
}

// Limits of the Trail parts.
const (
	maxGlobalNoteBytes = 32 << 10
	maxReceiptSigBytes = 32 << 10
)

func (b *Bundle) checkTrail() error {
	if g := b.Global; g != nil {
		if g.Checkpoint == "" || len(g.Checkpoint) > maxGlobalNoteBytes || len(g.Proof) > maxProofHashes || !hashes(g.Proof) {
			return invalid("malformed root log proof")
		}
	}
	if len(b.ReceiptSigs) > len(b.Receipts) {
		return invalid("more receipt co-signatures than receipts")
	}
	for _, s := range b.ReceiptSigs {
		if len(s.Receipt) != 2*sha256.Size || len(s.Sigs) == 0 || len(s.Sigs) > maxReceiptSigBytes {
			return invalid("malformed receipt co-signature")
		}
	}
	return nil
}

// globalLog checks the root log's checkpoint signature, the anchor's
// inclusion in it, and the witnesses' cosignatures.
func (v *verifier) globalLog() {
	g := v.b.Global
	if g == nil {
		v.r.add("global.checkpoint", "", NotAvailable, "the bundle has no root log checkpoint")
		return
	}
	origin := v.o.Trust.LogOrigin + "/global"
	var ks []noteKey
	for _, k := range v.o.Trust.keys(PurposeGlobalLog) {
		if nv, err := note.NewEd25519Verifier(origin, k.ed); err == nil {
			ks = append(ks, noteKey{k, nv})
		}
	}
	raw := []byte(g.Checkpoint)
	c, verified, err := note.OpenCheckpoint(raw, origin, verifiers(ks)...)
	k := signer(ks, verified)
	switch {
	case errors.Is(err, note.ErrUnverified) || (err == nil && k == nil):
		v.r.add("global.checkpoint", "", Failed, "not signed by a global_log key in your trust file")
		return
	case err != nil:
		v.r.add("global.checkpoint", "", Failed, "%v", err)
		return
	case k.State == StateRevoked:
		v.r.add("global.checkpoint", "", Failed, "signed by global_log key %s, which is revoked", k.KID)
		return
	}
	subject := fmt.Sprintf("size %d", c.Size)
	v.r.add("global.checkpoint", subject, Passed, "Ed25519 signature by global_log key %s", k.KID)
	if v.b.Anchor == nil {
		v.r.add("global.inclusion", subject, Failed, "the bundle has a root log checkpoint but no anchor")
	} else if s, err := anchor.ParseStatement(v.b.Anchor.Statement); err != nil {
		v.r.add("global.inclusion", subject, Failed, "the anchor's statement does not parse")
	} else if err := merkle.VerifyInclusion(merkle.LeafHash(s.Root[:]), g.Index, c.Size, toHashes(g.Proof), c.Root); err != nil {
		v.r.add("global.inclusion", subject, Failed, "the anchor's global root is not leaf %d of the root log: %v", g.Index, err)
	} else {
		v.r.add("global.inclusion", subject, Passed, "the anchor's global root is leaf %d of the root log", g.Index)
	}
	v.witnesses(subject, raw)
}

// witnesses counts the cosignatures of the witnesses the user named.
func (v *verifier) witnesses(subject string, raw []byte) {
	if len(v.o.Witnesses) == 0 {
		v.r.add("global.witnesses", subject, NotAvailable, "no witness keys given (--witnesses)")
		return
	}
	threshold := max(v.o.WitnessThreshold, 1)
	names, err := witness.Count(raw, v.o.Witnesses)
	switch {
	case err != nil:
		v.r.add("global.witnesses", subject, Failed, "a cosignature of a witness you named does not verify: %v", err)
	case len(names) >= threshold:
		v.r.add("global.witnesses", subject, Passed, "cosigned by %d of the witnesses you named (threshold %d)", len(names), threshold)
	default:
		v.r.add("global.witnesses", subject, Failed, "cosigned by %d of the witnesses you named, fewer than the threshold %d", len(names), threshold)
	}
}

// receiptCosignature checks a verified receipt's sigs[] against the pinned
// receipts_pq keys.
func (v *verifier) receiptCosignature(subject, compact string) {
	sum := sha256.Sum256([]byte(compact))
	digest := hex.EncodeToString(sum[:])
	var raw jsontext.Value
	for _, s := range v.b.ReceiptSigs {
		if s.Receipt == digest {
			raw = s.Sigs
			break
		}
	}
	pinned := v.o.Trust.keys(PurposeReceiptsPQ)
	switch {
	case raw == nil:
		v.r.add("receipt.cosignature", subject, NotAvailable, "no ML-DSA-65 co-signature")
		return
	case len(pinned) == 0:
		v.r.add("receipt.cosignature", subject, NotAvailable, "no receipts_pq key in your trust file")
		return
	}
	sigs, err := receiptsig.Parse(raw)
	if err != nil {
		v.r.add("receipt.cosignature", subject, Failed, "%v", err)
		return
	}
	for _, s := range sigs {
		k := v.o.Trust.key(PurposeReceiptsPQ, s.Kid)
		if k == nil {
			continue
		}
		if err := receiptsig.Verify(compact, s, k.mldsa); err != nil {
			v.r.add("receipt.cosignature", subject, Failed, "ML-DSA-65 co-signature by %s: %v", k.KID, err)
			return
		}
		if k.State == StateRevoked {
			v.r.add("receipt.cosignature", subject, Failed, "ML-DSA-65 key %s is revoked", k.KID)
			return
		}
		v.r.add("receipt.cosignature", subject, Passed, "ML-DSA-65 co-signature by %s", k.KID)
		return
	}
	v.r.add("receipt.cosignature", subject, NotAvailable, "no ML-DSA-65 co-signature from a pinned key")
}
