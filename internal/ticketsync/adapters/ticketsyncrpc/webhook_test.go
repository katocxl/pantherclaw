// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ticketsyncrpc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestT227_TheWebhookRouteIsRateLimited: past the limit a sender gets a 429
// before any org is touched (D277).
//
// Covers: F545
func TestT227_TheWebhookRouteIsRateLimited(t *testing.T) {
	mux := http.NewServeMux()
	Webhooks{Limiter: httpx.NewLimiter(0, time.Minute, nil)}.Mount(mux)
	r := httptest.NewRequest(http.MethodPost, WebhookPath+ids.New[ids.Org]().String()+"/"+ids.NewV7().String(), strings.NewReader("{}"))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
}
