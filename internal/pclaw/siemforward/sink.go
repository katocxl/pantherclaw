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
	// broken is set when the file can no longer be trusted to end on a
	// whole line, or to hold what it was told: nothing more is appended.
	broken error
}

// OpenFile opens path for appending. A new file is created for the
// forwarder's user only: mode 0600, or on Windows an access list of its
// own (that user, SYSTEM and Administrators, nothing inherited). An
// existing file keeps its permissions and content; if it does not end in a
// newline (a fragment left by a crash or a power loss), one is added, so
// the fragment stays a line of its own and never takes the next event
// with it.
func OpenFile(path string) (*FileSink, error) {
	f, err := openOutput(path)
	if err != nil {
		return nil, err
	}
	if err := endWithNewline(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &FileSink{f: f}, nil
}

// endWithNewline appends "\n" to a non-empty file that doesn't end in one.
func endWithNewline(f *os.File) error {
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return err
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, st.Size()-1); err != nil {
		return err
	}
	if last[0] == '\n' {
		return nil
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	if _, err := f.Write([]byte{'\n'}); err != nil {
		return err
	}
	return f.Sync()
}

// Append writes p at the end of the file and syncs it. A write that fails
// part way is cut back to where p started, so no partial line stays. A
// sync that fails after a whole write keeps the lines (cutting them would
// make the agents tailing the file read it again from the start), answers
// the error and stops the sink: what is on disk is no longer known.
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
	if err != nil {
		if terr := s.f.Truncate(off); terr != nil {
			s.broken = fmt.Errorf("the output file could not be cut back after a failed write; restart the forwarder once it is fixed: %w", terr)
			return errors.Join(err, s.broken)
		}
		_ = s.f.Sync()
		return err
	}
	if err := s.f.Sync(); err != nil {
		s.broken = fmt.Errorf("the output file could not be synced; restart the forwarder once it is fixed: %w", err)
		return s.broken
	}
	return nil
}

// Close closes the file.
func (s *FileSink) Close() error { return s.f.Close() }

// WriterSink writes to a stream such as stdout (`--out -`) in one Write per
// batch. A stream cannot be synced or cut back, so once a write fails part
// way the sink stops: the next batch would be glued to the fragment.
type WriterSink struct {
	mu     sync.Mutex
	w      io.Writer
	broken error
}

// NewWriterSink returns a sink writing to w.
func NewWriterSink(w io.Writer) *WriterSink { return &WriterSink{w: w} }

// Append writes p in one call.
func (s *WriterSink) Append(p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return s.broken
	}
	n, err := s.w.Write(p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	if err != nil && n > 0 {
		s.broken = fmt.Errorf("the output stream ends in a partial line; restart the forwarder once it is fixed: %w", err)
		return s.broken
	}
	return err
}

// Close does nothing: the stream belongs to the caller.
func (*WriterSink) Close() error { return nil }
