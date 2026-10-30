// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package blobtest is an in-memory blob.Store for tests only (D172). It
// keeps the port's contract: org-scoped, content-addressed, size-bounded.
package blobtest

import (
	"context"
	"sync"

	"github.com/katocxl/pantherclaw/internal/platform/blob"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Store is an in-memory blob.Store.
type Store struct {
	mu    sync.Mutex
	blobs map[blob.Ref][]byte
}

var _ blob.Store = (*Store)(nil)

// New returns an empty Store.
func New() *Store { return &Store{blobs: map[blob.Ref][]byte{}} }

// Put implements blob.Store.
func (s *Store) Put(_ context.Context, org ids.OrgID, kind string, content []byte) (blob.Ref, error) {
	if len(content) > blob.MaxSize {
		return blob.Ref{}, blob.ErrTooLarge
	}
	r := blob.RefFor(org, kind, content)
	if err := r.Validate(); err != nil {
		return blob.Ref{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[r] = append([]byte(nil), content...)
	return r, nil
}

// Get implements blob.Store.
func (s *Store) Get(_ context.Context, r blob.Ref) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.blobs[r]
	if !ok {
		return nil, blob.ErrNotFound
	}
	return append([]byte(nil), b...), nil
}

// Delete implements blob.Store.
func (s *Store) Delete(_ context.Context, r blob.Ref) error {
	if err := r.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.blobs, r)
	return nil
}
