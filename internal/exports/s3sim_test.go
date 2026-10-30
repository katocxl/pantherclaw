// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exports

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// s3Sim is an S3-compatible server small enough to read: PutObject and the
// multipart calls, which refuse a body that differs from its signed hash as
// S3 does. The fail fields inject the failures the tests need.
type s3Sim struct {
	mu      sync.Mutex
	objects map[string][]byte
	uploads map[string]*simUpload
	aborted []string
	deletes []string
	next    int
	// failPart answers 500 to this part number.
	failPart int
	// failPut answers 500 to every whole-object PUT.
	failPut bool
	// failAborts answers 500 to this many aborts.
	failAborts int
	// completeError answers 200 with an <Error> body, as S3 may.
	completeError bool
	// badEcho echoes a wrong checksum.
	badEcho bool
	// failSuffix answers 500 to a whole-object PUT of a key ending so.
	failSuffix string
	// hangBucket does not answer requests for this bucket until release
	// closes or the client leaves.
	hangBucket string
	release    chan struct{}
}

type simUpload struct {
	key   string
	parts map[int][]byte
}

func newS3Sim() *s3Sim {
	return &s3Sim{objects: map[string][]byte{}, uploads: map[string]*simUpload{}}
}

func (s *s3Sim) object(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objects[key]
	return b, ok
}

func (s *s3Sim) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.objects))
	for k := range s.objects {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (s *s3Sim) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if b := s.hangBucket; b != "" && strings.HasPrefix(r.URL.Path, "/"+b+"/") {
		release := s.release
		s.mu.Unlock()
		// Go's server notices a client that left only once the body is read.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-release:
		}
		return
	}
	defer s.mu.Unlock()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	sum := sha256.Sum256(body)
	if r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(sum[:]) {
		http.Error(w, "<Error><Code>XAmzContentSHA256Mismatch</Code></Error>", http.StatusBadRequest)
		return
	}
	if c := r.Header.Get(s3ChecksumHeader); c != "" && c != base64.StdEncoding.EncodeToString(sum[:]) {
		http.Error(w, "<Error><Code>BadDigest</Code></Error>", http.StatusBadRequest)
		return
	}
	echo := func() {
		v := base64.StdEncoding.EncodeToString(sum[:])
		if s.badEcho {
			v = "bad"
		}
		w.Header().Set(s3ChecksumHeader, v)
	}
	key := strings.TrimPrefix(r.URL.Path, "/")
	q := r.URL.Query()
	id := q.Get("uploadId")
	_, uploads := q["uploads"]
	switch {
	case r.Method == http.MethodPut && id == "":
		if s.failPut || (s.failSuffix != "" && strings.HasSuffix(key, s.failSuffix)) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		s.objects[key] = body
		echo()
		w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:16])+`"`)
	case r.Method == http.MethodPost && uploads:
		s.next++
		id := "upload-" + strconv.Itoa(s.next)
		s.uploads[id] = &simUpload{key: key, parts: map[int][]byte{}}
		fmt.Fprintf(w, "<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>", id)
	case r.Method == http.MethodPut:
		n, _ := strconv.Atoi(q.Get("partNumber"))
		u := s.uploads[id]
		if u == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if n == s.failPart {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		u.parts[n] = body
		echo()
		w.Header().Set("ETag", `"part-`+strconv.Itoa(n)+`"`)
	case r.Method == http.MethodPost:
		u := s.uploads[id]
		if u == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if s.completeError {
			fmt.Fprint(w, "<Error><Code>InternalError</Code></Error>")
			return
		}
		var in s3Complete
		if err := xml.Unmarshal(body, &in); err != nil || len(in.Parts) != len(u.parts) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var whole bytes.Buffer
		for _, p := range in.Parts {
			whole.Write(u.parts[p.PartNumber])
		}
		s.objects[key] = whole.Bytes()
		delete(s.uploads, id)
		fmt.Fprint(w, `<CompleteMultipartUploadResult><ETag>"whole-etag"</ETag></CompleteMultipartUploadResult>`)
	case r.Method == http.MethodDelete && id != "":
		if s.failAborts > 0 {
			s.failAborts--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if s.uploads[id] == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(s.uploads, id)
		s.aborted = append(s.aborted, id)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete:
		s.deletes = append(s.deletes, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
