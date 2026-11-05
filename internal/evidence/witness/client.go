// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package witness

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
)

// Doer sends HTTP requests (the M1 egress client in production).
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Errors of an add-checkpoint request (c2sp.org/tlog-witness).
var (
	// ErrConflict: the witness holds another size for the log; Conflict.Size
	// is the size it holds.
	ErrConflict = errors.New("witness: the witness holds another tree size")
	// ErrUnknownLog: the witness does not know the log (404).
	ErrUnknownLog = errors.New("witness: the witness does not know this log")
	// ErrRefused: the witness refused the checkpoint (403: no verifiable log
	// signature; 422: an invalid consistency proof; other statuses).
	ErrRefused = errors.New("witness: the witness refused the checkpoint")
)

// ConflictError carries the size a witness reported with 409 Conflict.
type ConflictError struct{ Size uint64 }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("witness: the witness holds tree size %d", e.Size)
}

// Unwrap makes errors.Is(err, ErrConflict) true.
func (e *ConflictError) Unwrap() error { return ErrConflict }

// Limits of a witness exchange.
const (
	maxResponseBytes = 16 << 10
	maxProofHashes   = 128
)

// Client asks one witness to cosign checkpoints of one log.
type Client struct {
	// Name is the operator's name for the witness (evidence.witnesses[].name).
	Name string
	// URL is the witness's https submission prefix; requests go to
	// URL + "/add-checkpoint".
	URL  string
	Key  *Verifier
	HTTP Doer
}

// Request is the body of an add-checkpoint request: the size the witness
// last cosigned (0 for none), the consistency proof from it to the
// checkpoint, and the signed checkpoint note.
type Request struct {
	OldSize uint64
	Proof   []merkle.Hash
	Note    []byte
}

// Encode returns the request body:
//
//	old <size>
//	<base64 proof hash>…
//	<empty line>
//	<signed checkpoint note>
func (r Request) Encode() ([]byte, error) {
	if len(r.Proof) > maxProofHashes {
		return nil, errors.New("witness: consistency proof too long")
	}
	if r.OldSize == 0 && len(r.Proof) > 0 {
		return nil, errors.New("witness: a proof from size 0")
	}
	var b bytes.Buffer
	b.WriteString("old " + strconv.FormatUint(r.OldSize, 10) + "\n")
	for _, h := range r.Proof {
		b.WriteString(base64.StdEncoding.EncodeToString(h[:]) + "\n")
	}
	b.WriteString("\n")
	b.Write(r.Note)
	return b.Bytes(), nil
}

// AddCheckpoint submits the request and returns the witness's verified
// cosignatures on the checkpoint, whose body is text. A 409 is a
// *ConflictError with the size the witness holds; the caller retries from
// it with a matching proof.
func (c *Client) AddCheckpoint(ctx context.Context, r Request, text string) ([]Cosignature, error) {
	if c.Key == nil || c.HTTP == nil {
		return nil, errors.New("witness: client without a key or HTTP client")
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("witness %s: the URL is not https", c.Name)
	}
	body, err := r.Encode()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.URL, "/")+"/add-checkpoint", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("witness %s: %w", c.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("witness %s: %w", c.Name, err)
	}
	if len(raw) > maxResponseBytes {
		return nil, fmt.Errorf("witness %s: response larger than %d bytes", c.Name, maxResponseBytes)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return ParseCosignatures(raw, text, c.Key)
	case http.StatusConflict:
		s := strings.TrimSpace(string(raw))
		size, err := strconv.ParseUint(s, 10, 64)
		if err != nil || strconv.FormatUint(size, 10) != s {
			return nil, fmt.Errorf("witness %s: %w (unreadable size)", c.Name, ErrConflict)
		}
		return nil, &ConflictError{Size: size}
	case http.StatusNotFound:
		return nil, fmt.Errorf("witness %s: %w", c.Name, ErrUnknownLog)
	default:
		return nil, fmt.Errorf("witness %s: %w (status %d)", c.Name, ErrRefused, resp.StatusCode)
	}
}

// Count opens a cosigned checkpoint note (the log's signature lines plus
// witness lines) against the witnesses and returns the names of those whose
// cosignature verified. A witness line that fails rejects the note, as the
// signed-note spec asks of a known key; lines of other keys are ignored.
func Count(signed []byte, witnesses []*Verifier) ([]string, error) {
	if len(witnesses) == 0 {
		return nil, nil
	}
	known := make([]note.Verifier, len(witnesses))
	for i, w := range witnesses {
		known[i] = w
	}
	_, verified, err := note.Open(signed, known...)
	if errors.Is(err, note.ErrUnverified) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var names []string
	for _, s := range verified {
		names = append(names, s.Name)
	}
	return names, nil
}
