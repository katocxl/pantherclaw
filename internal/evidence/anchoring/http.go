// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchoring

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// ErrHostNotAllowed reports a request to a host other than the configured
// one.
var ErrHostNotAllowed = errors.New("anchoring: request to a host that is not configured")

// HostOnly is a Doer that sends requests only over https to one configured
// host (and port); everything else is refused before it leaves (HR-195:
// "to the configured hosts only").
type HostOnly struct {
	Host string // url.URL.Host of the configured endpoint
	Next anchor.Doer
}

// Do implements anchor.Doer.
func (h HostOnly) Do(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Host, h.Host) || h.Next == nil {
		return nil, ErrHostNotAllowed
	}
	return h.Next.Do(req)
}

// EgressDoer returns the M1 egress client (HR-070..072: no redirects, the
// connected address checked after DNS, no proxies) limited to the host of
// endpoint, with timeout per request.
func EgressDoer(endpoint string, timeout time.Duration) (anchor.Doer, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("anchoring: %q is not an https URL", endpoint)
	}
	return HostOnly{Host: u.Host, Next: httpx.NewEgressClient(httpx.EgressConfig{Timeout: timeout})}, nil
}
