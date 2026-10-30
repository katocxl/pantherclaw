// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
)

// Limits of what a destination answers.
const (
	maxAnswerBytes = 1 << 20
	maxETagBytes   = 256
)

// sent is what a destination answered about an object or a part.
type sent struct {
	Number int
	ETag   string
	SHA256 []byte
	Status int
}

// transport carries one destination's objects. Parts of a large object go
// through Begin, Part and Complete; Abort removes what a failed upload left
// and succeeds when nothing is left. Delete removes one object; a missing
// one is already gone.
type transport interface {
	Put(ctx context.Context, key string, body []byte) (sent, error)
	Delete(ctx context.Context, key string) error
	Begin(ctx context.Context, key string) (string, error)
	Part(ctx context.Context, key, upload string, number int, body []byte) (sent, error)
	Complete(ctx context.Context, key, upload string, parts []sent) (sent, error)
	Abort(ctx context.Context, key, upload string, parts int) error
}

// pushError is a refused or failed request. Only its code and status are
// recorded: a destination's answer is never stored or logged.
type pushError struct {
	Code   string
	Status int
	// Final says a retry cannot change the outcome.
	Final bool
}

func (e pushError) Error() string {
	if e.Status != 0 {
		return "exports: " + e.Code + " (HTTP " + strconv.Itoa(e.Status) + ")"
	}
	return "exports: " + e.Code
}

// failureOf returns the code and status a receipt records for err.
func failureOf(err error) (string, int) {
	var p pushError
	switch {
	case errors.As(err, &p):
		return p.Code, p.Status
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout", 0
	}
	return "push_failed", 0
}

// timedOut says a destination did not answer in time.
func timedOut(err error) bool {
	code, _ := failureOf(err)
	return code == "timeout"
}

func statusError(status int) error {
	return pushError{Code: "http_" + strconv.Itoa(status/100) + "xx", Status: status}
}

// objectURL is base's URL of key, each segment escaped once.
func objectURL(base *url.URL, key string) *url.URL {
	u := *base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + key
	u.RawPath = ""
	return &u
}

// answer is what a destination said; the response itself is closed.
type answer struct {
	Status int
	Header http.Header
	Body   []byte
}

func do(c *http.Client, req *http.Request) (answer, error) {
	res, err := c.Do(req)
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return answer{}, pushError{Code: "timeout"}
		}
		return answer{}, pushError{Code: "connection"}
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxAnswerBytes))
	if err != nil {
		return answer{}, pushError{Code: "connection", Status: res.StatusCode}
	}
	return answer{Status: res.StatusCode, Header: res.Header, Body: body}, nil
}

func etagOf(res answer) string {
	e := res.Header.Get("ETag")
	if len(e) > maxETagBytes {
		return ""
	}
	return e
}

// s3Transport speaks the S3 API, signed with SigV4. The real SHA-256 of
// every body is signed, so the destination refuses bytes that differ, and
// is sent as x-amz-checksum-sha256 too (HR-514).
type s3Transport struct {
	client *http.Client
	base   *url.URL
	signer sigv4.Signer
	creds  sigv4.Credentials
	now    func() time.Time
}

const s3ChecksumHeader = "X-Amz-Checksum-Sha256"

func (t *s3Transport) request(ctx context.Context, method, key, query string, body, sum []byte, headers map[string]string) (answer, error) {
	u := objectURL(t.base, key)
	u.RawQuery = query
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return answer{}, err
	}
	req.ContentLength = int64(len(body))
	if len(body) == 0 {
		req.Body, req.GetBody = http.NoBody, nil
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if sum != nil {
		req.Header.Set(s3ChecksumHeader, base64.StdEncoding.EncodeToString(sum))
	}
	if err := t.signer.Sign(req, t.creds, hex.EncodeToString(digest(sum, body)), t.now()); err != nil {
		return answer{}, err
	}
	return do(t.client, req)
}

// digest is the body's SHA-256: sum when it was already computed.
func digest(sum, body []byte) []byte {
	if sum != nil {
		return sum
	}
	h := sha256.Sum256(body)
	return h[:]
}

// checkEcho compares a checksum the destination echoes with what was sent.
// A destination that echoes none has still checked the signed hash.
func checkEcho(res answer, sum []byte) error {
	echo := res.Header.Get(s3ChecksumHeader)
	if echo == "" || echo == base64.StdEncoding.EncodeToString(sum) {
		return nil
	}
	return pushError{Code: "checksum_mismatch", Status: res.Status}
}

func (t *s3Transport) Put(ctx context.Context, key string, body []byte) (sent, error) {
	sum := digest(nil, body)
	res, err := t.request(ctx, http.MethodPut, key, "", body, sum, nil)
	if err != nil {
		return sent{}, err
	}
	if res.Status/100 != 2 {
		return sent{}, statusError(res.Status)
	}
	if err := checkEcho(res, sum); err != nil {
		return sent{}, err
	}
	return sent{ETag: etagOf(res), SHA256: sum, Status: res.Status}, nil
}

func (t *s3Transport) Delete(ctx context.Context, key string) error {
	res, err := t.request(ctx, http.MethodDelete, key, "", nil, nil, nil)
	if err != nil {
		return err
	}
	if res.Status/100 != 2 && res.Status != http.StatusNotFound {
		return statusError(res.Status)
	}
	return nil
}

func (t *s3Transport) Begin(ctx context.Context, key string) (string, error) {
	res, err := t.request(ctx, http.MethodPost, key, "uploads=", nil, nil, map[string]string{"X-Amz-Checksum-Algorithm": "SHA256"})
	if err != nil {
		return "", err
	}
	if res.Status/100 != 2 {
		return "", statusError(res.Status)
	}
	var out struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		UploadID string   `xml:"UploadId"`
	}
	if err := xml.Unmarshal(res.Body, &out); err != nil || out.UploadID == "" || len(out.UploadID) > 1024 {
		return "", pushError{Code: "bad_answer", Status: res.Status}
	}
	return out.UploadID, nil
}

func uploadQuery(upload string) string { return "uploadId=" + url.QueryEscape(upload) }

func (t *s3Transport) Part(ctx context.Context, key, upload string, number int, body []byte) (sent, error) {
	sum := digest(nil, body)
	query := "partNumber=" + strconv.Itoa(number) + "&" + uploadQuery(upload)
	res, err := t.request(ctx, http.MethodPut, key, query, body, sum, nil)
	if err != nil {
		return sent{}, err
	}
	if res.Status/100 != 2 {
		return sent{}, statusError(res.Status)
	}
	if err := checkEcho(res, sum); err != nil {
		return sent{}, err
	}
	etag := etagOf(res)
	if etag == "" {
		return sent{}, pushError{Code: "bad_answer", Status: res.Status}
	}
	return sent{Number: number, ETag: etag, SHA256: sum, Status: res.Status}, nil
}

type s3CompletedPart struct {
	PartNumber     int    `xml:"PartNumber"`
	ETag           string `xml:"ETag"`
	ChecksumSHA256 string `xml:"ChecksumSHA256"`
}

type s3Complete struct {
	XMLName xml.Name          `xml:"CompleteMultipartUpload"`
	Parts   []s3CompletedPart `xml:"Part"`
}

// Complete finishes the upload. S3 answers 200 before it knows the outcome
// and reports a failure in the body, so the body decides.
func (t *s3Transport) Complete(ctx context.Context, key, upload string, parts []sent) (sent, error) {
	in := s3Complete{}
	for _, p := range parts {
		in.Parts = append(in.Parts, s3CompletedPart{PartNumber: p.Number, ETag: p.ETag, ChecksumSHA256: base64.StdEncoding.EncodeToString(p.SHA256)})
	}
	body, err := xml.Marshal(in)
	if err != nil {
		return sent{}, err
	}
	res, err := t.request(ctx, http.MethodPost, key, uploadQuery(upload), body, nil, map[string]string{"Content-Type": "application/xml"})
	if err != nil {
		return sent{}, err
	}
	if res.Status/100 != 2 {
		return sent{}, statusError(res.Status)
	}
	var out struct {
		XMLName xml.Name
		ETag    string `xml:"ETag"`
	}
	if err := xml.Unmarshal(res.Body, &out); err != nil || out.XMLName.Local != "CompleteMultipartUploadResult" {
		return sent{}, pushError{Code: "complete_refused", Status: res.Status}
	}
	if len(out.ETag) > maxETagBytes {
		out.ETag = ""
	}
	return sent{ETag: out.ETag, Status: res.Status}, nil
}

// Abort ends the upload; one that is already gone needs nothing more.
func (t *s3Transport) Abort(ctx context.Context, key, upload string, _ int) error {
	res, err := t.request(ctx, http.MethodDelete, key, uploadQuery(upload), nil, nil, nil)
	if err != nil {
		return err
	}
	if res.Status/100 != 2 && res.Status != http.StatusNotFound {
		return statusError(res.Status)
	}
	return nil
}

// putTransport PUTs objects to an HTTPS target with a bearer token. A large
// object goes as numbered chunk objects and an index naming them, written
// last: a target without the index never saw a whole object.
type putTransport struct {
	client *http.Client
	base   *url.URL
	token  string
}

// ContentSHA256Header carries a PUT body's SHA-256 in hex.
const ContentSHA256Header = "X-PantherClaw-Content-SHA256"

func (t *putTransport) send(ctx context.Context, method, key string, body, sum []byte) (answer, error) {
	req, err := http.NewRequestWithContext(ctx, method, objectURL(t.base, key).String(), bytes.NewReader(body))
	if err != nil {
		return answer{}, err
	}
	req.ContentLength = int64(len(body))
	if len(body) == 0 {
		req.Body, req.GetBody = http.NoBody, nil
	}
	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("Content-Type", "application/octet-stream")
	if sum != nil {
		req.Header.Set(ContentSHA256Header, hex.EncodeToString(sum))
	}
	return do(t.client, req)
}

func (t *putTransport) Put(ctx context.Context, key string, body []byte) (sent, error) {
	sum := digest(nil, body)
	res, err := t.send(ctx, http.MethodPut, key, body, sum)
	if err != nil {
		return sent{}, err
	}
	if res.Status/100 != 2 {
		return sent{}, statusError(res.Status)
	}
	return sent{ETag: etagOf(res), SHA256: sum, Status: res.Status}, nil
}

func (t *putTransport) Delete(ctx context.Context, key string) error {
	res, err := t.send(ctx, http.MethodDelete, key, nil, nil)
	if err != nil {
		return err
	}
	if res.Status/100 != 2 && res.Status != http.StatusNotFound {
		return statusError(res.Status)
	}
	return nil
}

func chunkKey(key string, number int) string { return fmt.Sprintf("%s.chunk-%06d", key, number) }

// Begin needs nothing from the target: the receipt's id names the upload.
func (t *putTransport) Begin(context.Context, string) (string, error) { return "chunks", nil }

func (t *putTransport) Part(ctx context.Context, key, _ string, number int, body []byte) (sent, error) {
	s, err := t.Put(ctx, chunkKey(key, number), body)
	s.Number = number
	return s, err
}

type chunkEntry struct {
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
}

// Complete writes the index at the object's own key.
func (t *putTransport) Complete(ctx context.Context, key, _ string, parts []sent) (sent, error) {
	index := struct {
		Format string       `json:"format"`
		Chunks []chunkEntry `json:"chunks"`
	}{Format: "pantherclaw.chunks/v1"}
	for _, p := range parts {
		index.Chunks = append(index.Chunks, chunkEntry{Key: chunkKey(key, p.Number), SHA256: hex.EncodeToString(p.SHA256)})
	}
	body, err := json.Marshal(index)
	if err != nil {
		return sent{}, err
	}
	return t.Put(ctx, key, body)
}

// Abort deletes every chunk begun. An earlier abort may have deleted some,
// so a 404 says only that this chunk is gone, never that the rest are. A
// target that refuses DELETE keeps them, and the abort stays pending.
func (t *putTransport) Abort(ctx context.Context, key, _ string, parts int) error {
	for n := 1; n <= parts; n++ {
		if err := t.Delete(ctx, chunkKey(key, n)); err != nil {
			return err
		}
	}
	return nil
}
