// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package globallog

import (
	"context"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// CheckpointPath serves the root log's newest checkpoint (G0 M35 D1041).
const CheckpointPath = "/.well-known/pantherclaw/evidence/global-checkpoint"

// cacheTTL bounds how often a public request reaches the database.
const cacheTTL = 30 * time.Second

// Handler serves the newest checkpoint of the root log with its witnesses'
// cosignatures: public, and showing nothing but the log's total size and
// root (it counts anchoring periods, not orgs or their activity).
//
//	GET CheckpointPath                    → text/plain: the signed note
//	GET CheckpointPath?consistency=<old>  → application/json:
//	    {"checkpoint": <note>, "size": n, "from": old, "proof": [<base64>…]}
type Handler struct {
	Pool *db.Pool
	Log  *slog.Logger

	mu     sync.Mutex
	cached []byte
	size   uint64
	at     time.Time
}

func (h *Handler) log() *slog.Logger {
	if h.Log == nil {
		return pclog.Discard()
	}
	return h.Log
}

// Mount adds the route to mux.
func (h *Handler) Mount(mux *http.ServeMux) { mux.HandleFunc("GET "+CheckpointPath, h.serve) }

func (h *Handler) latest(ctx context.Context) ([]byte, uint64, bool, error) {
	h.mu.Lock()
	if h.cached != nil && time.Since(h.at) < cacheTTL {
		b, n := h.cached, h.size
		h.mu.Unlock()
		return b, n, true, nil
	}
	h.mu.Unlock()
	var p Published
	var ok bool
	err := h.Pool.InGlobalTx(ctx, db.GlobalLog, func(ctx context.Context, tx db.GlobalTx) error {
		var err error
		p, ok, err = Latest(ctx, dbq.New(tx))
		return err
	}, db.ReadOnly())
	if err != nil || !ok {
		return nil, 0, false, err
	}
	h.mu.Lock()
	h.cached, h.size, h.at = p.Note, p.Size, time.Now()
	h.mu.Unlock()
	return p.Note, p.Size, true, nil
}

type consistencyDoc struct {
	Checkpoint string   `json:"checkpoint"`
	Size       uint64   `json:"size"`
	From       uint64   `json:"from"`
	Proof      [][]byte `json:"proof"`
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	signed, size, ok, err := h.latest(ctx)
	if err != nil {
		h.log().ErrorContext(ctx, "evidence.global_checkpoint_read_failed", slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "no global checkpoint yet", http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=30")
	raw, has := r.URL.Query()["consistency"]
	if !has {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(signed)
		return
	}
	from, err := strconv.ParseUint(firstOf(raw), 10, 64)
	if err != nil || from < 1 || from > size {
		http.Error(w, "consistency must be a tree size from 1 to the checkpoint's size", http.StatusBadRequest)
		return
	}
	var proof []merkle.Hash
	if from < size {
		err = h.Pool.InGlobalTx(ctx, db.GlobalLog, func(ctx context.Context, tx db.GlobalTx) error {
			var err error
			proof, err = merkle.ConsistencyProof(ctx, Tiles{Q: dbq.New(tx)}, from, size)
			return err
		}, db.ReadOnly())
		if err != nil {
			h.log().ErrorContext(ctx, "evidence.global_consistency_failed", slog.String("error", err.Error()))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	doc := consistencyDoc{Checkpoint: string(signed), Size: size, From: from, Proof: make([][]byte, len(proof))}
	for i, p := range proof {
		doc.Proof[i] = append([]byte(nil), p[:]...)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func firstOf(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
