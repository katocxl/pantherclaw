// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package siemforward

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// Sink receives the lines of one verified batch.
type Sink interface {
	// Append writes p whole or not at all; a file sink also syncs it to
	// disk before returning nil.
	Append(p []byte) error
	Close() error
}

// file is what FileSink needs of an *os.File (a seam for tests).
type file interface {
	io.WriteCloser
	Seek(offset int64, whence int) (int64, error)
	Truncate(size int64) error
	Sync() error
}

// FileSink appends to a file a SIEM agent reads: Azure Monitor Agent's
// custom text log, Wazuh's `localfile`.
type FileSink struct {
	f file
	// broken is set when a failed write could not be cut back: the file
	// may end in a partial line, so nothing more is appended to it.
	broken error
}

// OpenFile opens path for appending, creating it with mode 0600. An
// existing file is kept and appended to.
func OpenFile(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600) //nolint:gosec // G304: the output file the operator names
	if err != nil {
		return nil, err
	}
	return &FileSink{f: f}, nil
}

// Append writes p at the end of the file and syncs it. On any failure the
// file is cut back to where p started, so no partial line stays behind.
func (s *FileSink) Append(p []byte) error {
	if s.broken != nil {
		return s.broken
	}
	off, err := s.f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	n, err := s.f.Write(p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = s.f.Sync()
	}
	if err == nil {
		return nil
	}
	if terr := s.f.Truncate(off); terr != nil {
		s.broken = fmt.Errorf("the output file could not be cut back after a failed write; restart the forwarder once it is fixed: %w", terr)
		return errors.Join(err, s.broken)
	}
	_ = s.f.Sync()
	return err
}

// Close closes the file.
func (s *FileSink) Close() error { return s.f.Close() }

// WriterSink writes to a stream such as stdout (`--out -`) in one Write per
// batch. A stream cannot be synced or cut back.
type WriterSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriterSink returns a sink writing to w.
func NewWriterSink(w io.Writer) *WriterSink { return &WriterSink{w: w} }

// Append writes p in one call.
func (s *WriterSink) Append(p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.w.Write(p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	return err
}

// Close does nothing: the stream belongs to the caller.
func (*WriterSink) Close() error { return nil }
