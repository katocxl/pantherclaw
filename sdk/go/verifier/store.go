// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package verifier

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Spend is one token id to record as used.
type Spend struct {
	// Audience is the token's aud, the target's connection id, and ID its
	// jti: a store records the pair, so one store can serve several
	// targets (HR-202).
	Audience, ID string
	// IssuedAt is the token's iat; Now the verifier's clock.
	IssuedAt, Now time.Time
	// Until is how long the id must be kept: the token's exp plus the
	// clock skew.
	Until time.Time
}

// ReplayStore spends action token ids (HR-202). Use records the id until
// Until and reports whether this was its first use. It must return an
// error, never true, when it cannot record: unreachable, full, or unable
// to keep the id that long. Shared reports whether every replica of the
// target uses the same store.
type ReplayStore interface {
	Use(ctx context.Context, s Spend) (bool, error)
	Shared() bool
}

// Errors of the stores.
var (
	ErrStoreFull = errors.New("verifier: replay store full")
	// ErrStoreRestarted: the token was issued before the store began
	// recording, so it may have been spent before a restart.
	ErrStoreRestarted = errors.New("verifier: replay store began recording after the token was issued")
)

// MemoryStore is a ReplayStore for one replica (Shared is false): a token
// spent at one replica would be accepted again at another. It never evicts
// an id before Until; when full it refuses new tokens instead.
type MemoryStore struct {
	capacity int
	started  time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

// NewMemoryStore returns a store that holds at most capacity ids (100,000
// when 0) and began recording at started (zero: at its first use). A
// process that restarted has lost the ids it recorded before, so tokens
// issued before started plus the skew are refused: one issued up to Skew
// after started, by the Authority's clock, may have been spent before it.
// The store fails closed for those few seconds.
func NewMemoryStore(capacity int, started time.Time) *MemoryStore {
	if capacity <= 0 {
		capacity = 100_000
	}
	return &MemoryStore{capacity: capacity, started: started, seen: map[string]time.Time{}}
}

// Shared implements ReplayStore: a memory store serves one replica.
func (*MemoryStore) Shared() bool { return false }

// Use implements ReplayStore.
func (m *MemoryStore) Use(_ context.Context, s Spend) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started.IsZero() {
		m.started = s.Now
	}
	if s.IssuedAt.Before(m.started.Add(Skew)) {
		return false, ErrStoreRestarted
	}
	if m.seen == nil {
		m.seen = map[string]time.Time{}
	}
	if m.capacity <= 0 {
		m.capacity = 100_000
	}
	id := s.Audience + "\x00" + s.ID
	if _, used := m.seen[id]; used {
		return false, nil
	}
	if len(m.seen) >= m.capacity {
		for id, until := range m.seen {
			if s.Now.After(until) {
				delete(m.seen, id)
			}
		}
		if len(m.seen) >= m.capacity {
			return false, ErrStoreFull
		}
	}
	m.seen[id] = s.Until
	return true, nil
}
