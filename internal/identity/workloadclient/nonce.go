// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
)

// Challenge sends the request a workload is about to make (its exact URL
// and Connect JSON body) once with a key-only proof and no nonce, the
// standard use_nonce pattern of PAP-1 §4: the server refuses it with
// use_nonce before it reads anything else and returns the org's current
// nonce in PAP-Nonce. It is never retried. An L3 attestation then binds
// that nonce, and the Transport keeps it for the real request that follows
// (PAP-1 §3.3, G0 M35 D1030a).
func (t *Transport) Challenge(ctx context.Context, url string, body []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
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
