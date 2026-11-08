// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package federationkeys

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The public federation routes (D1020, D1021): the org's document, and a
// peer's confirmation and revocation. They are rate limited per client
// address; a refusal says nothing about which check failed.

// PublicRateLimit is how many requests one client address may make a
// minute to each route.
const PublicRateLimit = 60

// Mount serves the public routes on mux.
func (s *Service) Mount(mux *http.ServeMux, clientIP httpx.ClientIPFunc) {
	docs := httpx.NewLimiter(PublicRateLimit, time.Minute, nil).WithClientIP(clientIP)
	peers := httpx.NewLimiter(PublicRateLimit, time.Minute, nil).WithClientIP(clientIP)
	mux.HandleFunc("GET /.well-known/pantherclaw/orgs/{org}/federation.json", func(w http.ResponseWriter, r *http.Request) {
		if !docs.AllowRequest(r) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		org, err := ids.Parse[ids.Org](r.PathValue("org"))
		if err != nil || org == ids.PlatformOrg {
			http.NotFound(w, r)
			return
		}
		b, err := s.PublicDocument(r.Context(), org)
		if err != nil {
			if pcerr.CodeOf(err) == pcerr.Internal || pcerr.CodeOf(err) == "" {
				s.log.ErrorContext(r.Context(), "federation.document_failed", slog.String("org", org.String()), slog.Any("error", err))
			}
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/jose+json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(b) //nolint:gosec // G705: b is the server-built signed document, not request input
	})
	peer := func(handle func(r *http.Request, compact string) error) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !peers.AllowRequest(r) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			raw, err := io.ReadAll(io.LimitReader(r.Body, MaxPeerMessageBytes+1))
			if err != nil || len(raw) > MaxPeerMessageBytes {
				http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
				return
			}
			if err := handle(r, strings.TrimSpace(string(raw))); err != nil {
				var pe *pcerr.Error
				if !errors.As(err, &pe) {
					s.log.ErrorContext(r.Context(), "federation.peer_message_failed", slog.Any("error", err))
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				http.Error(w, "refused", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		}
	}
	mux.HandleFunc("POST "+PathPeerConfirmations, peer(func(r *http.Request, c string) error { return s.ReceiveConfirm(r.Context(), c) }))
	mux.HandleFunc("POST "+PathPeerRevocations, peer(func(r *http.Request, c string) error { return s.ReceiveRevoke(r.Context(), c) }))
}
