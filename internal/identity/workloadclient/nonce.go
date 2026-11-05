// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadclient

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// issueTokenPath is WorkloadService.IssueToken.
const issueTokenPath = "/pantherclaw.v1.WorkloadService/IssueToken"

// FetchNonce asks server for org's current nonce before a request whose
// L3 attestation must bind it (PAP-1 §3.3, G0 M35 D1030). It sends one
// IssueToken request for an instance that doesn't exist, with a key-only
// proof and no nonce: the server refuses it with use_nonce before it reads
// anything else and returns org's nonce in PAP-Nonce. It is never retried,
// and the Transport keeps the nonce for the request that follows.
func (t *Transport) FetchNonce(ctx context.Context, server string, org ids.OrgID) (string, error) {
	if org.IsZero() {
		return "", errors.New("the org is unknown")
	}
	probe := pap.Instance{Org: org, Agent: ids.NewV7(), Instance: ids.NewV7()}
	body, err := json.Marshal(map[string]string{"identifier": probe.String()})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(server, "/")+issueTokenPath, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	t.mu.Lock()
	t.nonce = ""
	t.mu.Unlock()
	resp, err := t.send(req, body)
	if err != nil {
		return "", err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	n := t.Nonce()
	if n == "" {
		return "", errors.New("the server sent no nonce")
	}
	return n, nil
}
