// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"net/http"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
)

// Bound reports whether a request URL's host may receive the credential
// (domain.HostBound).
func Bound(allowedHosts []string, rawHost, defaultPort string) bool {
	return domain.HostBound(allowedHosts, rawHost, defaultPort)
}

// Place sets the credential on the request: "Header: [Scheme ]secret".
// It refuses a request whose host the credential is not bound to, before
// anything is sent (HR-060).
func Place(r *http.Request, allowedHosts []string, header, scheme string, secret []byte) error {
	port := "443"
	if r.URL.Scheme == "http" {
		port = "80"
	}
	if !Bound(allowedHosts, r.URL.Host, port) {
		return ErrNotBound
	}
	v := string(secret)
	if scheme != "" {
		v = scheme + " " + v
	}
	r.Header.Set(header, v)
	return nil
}
