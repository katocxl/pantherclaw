// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"context"
	"net/http"
)

type clientIPKey struct{}

// WithClientIP returns ctx carrying the request's client address, as the
// trusted-proxy-aware Limiter.ClientIP found it (G0 UI D85).
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// ClientIPFrom returns the client address WithClientIP stored, or "".
func ClientIPFrom(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKey{}).(string)
	return ip
}

// ClientIPMiddleware stores each request's client address (f) in its
// context, for code below a protocol layer that has no request (the
// Connect API's rate limits). A nil f stores nothing.
func ClientIPMiddleware(next http.Handler, f ClientIPFunc) http.Handler {
	if f == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(WithClientIP(r.Context(), f(r))))
	})
}
