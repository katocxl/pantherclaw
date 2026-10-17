// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2a

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
)

// ErrFetch reports a card that could not be read.
var ErrFetch = errors.New("a2a: agent card could not be read")

// ErrDrift reports a card whose digest is not the pinned one (HR-322).
var ErrDrift = errors.New("a2a: agent card changed since it was pinned")

// FetchCard reads the agent card at url with client: one GET, no
// redirect followed, a JSON answer of at most MaxCardBytes. The client is
// the caller's, with its own egress checks (the gateway's dial-time checks,
// the server's outbound HTTPS checks).
func FetchCard(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	req.Header.Set("Accept", "application/json")
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrFetch, resp.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || (mt != "application/json" && mt != ContentType) {
		return nil, fmt.Errorf("%w: content type", ErrFetch)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxCardBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	if len(raw) > MaxCardBytes {
		return nil, fmt.Errorf("%w: too large", ErrFetch)
	}
	return bytes.TrimSpace(raw), nil
}

// PinRequest is what an Org Admin asks to pin (D30).
type PinRequest struct {
	CardURL string
	// Binding and URL are the interface the gateway will call.
	Binding, URL string
	// Keys is the optional pinned JWKS.
	Keys   []byte
	Skills []string
}

// Pinned is a card as pinned: the document as fetched and its digest.
type Pinned struct {
	Card   []byte
	Digest [32]byte
}

// Pin reads the card and checks it against the request: signatures by
// the pinned keys, the interface and the skills (D30). Nothing about the
// card is taken on trust beyond what the caller then stores.
func Pin(ctx context.Context, client *http.Client, p PinRequest) (Pinned, error) {
	keys, err := ParseKeys(p.Keys)
	if err != nil {
		return Pinned{}, err
	}
	raw, err := FetchCard(ctx, client, p.CardURL)
	if err != nil {
		return Pinned{}, err
	}
	d, err := CheckPin(raw, keys, p.Binding, p.URL, p.Skills)
	if err != nil {
		return Pinned{}, err
	}
	return Pinned{Card: raw, Digest: d}, nil
}

// Recheck reads the card again and compares it with the pinned digest: a
// different document is drift (HR-322), as is one whose signatures no
// longer verify. The observed digest is returned for the drift report.
func Recheck(ctx context.Context, client *http.Client, cardURL string, pinned, keys []byte) ([32]byte, error) {
	raw, err := FetchCard(ctx, client, cardURL)
	if err != nil {
		return [32]byte{}, err
	}
	d, err := Digest(raw)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %w", ErrDrift, err)
	}
	if len(pinned) != len(d) || subtle.ConstantTimeCompare(pinned, d[:]) != 1 {
		return d, ErrDrift
	}
	k, err := ParseKeys(keys)
	if err != nil {
		return d, err
	}
	if err := VerifySignatures(raw, k); err != nil {
		return d, fmt.Errorf("%w: %w", ErrDrift, err)
	}
	return d, nil
}
