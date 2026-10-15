// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package audit

import (
	"container/list"
	"sync"
	"time"
)

// Once remembers recently audited keys so a repeated refusal is audited
// once per window: a looping caller cannot grow the ledger (G0 M10 D67,
// D74). It keeps at most OnceEntries keys, dropping the least recent. The
// zero value is ready to use and safe for concurrent use.
type Once struct {
	// Window is how long a key stays deduplicated (default one minute).
	Window time.Duration
	// Now is the clock (default time.Now).
	Now func() time.Time

	mu    sync.Mutex
	order *list.List
	seen  map[string]*list.Element
}

// OnceEntries bounds the keys a Once remembers.
const OnceEntries = 10_000

type onceEntry struct {
	key string
	at  time.Time
}

// First reports whether key was not seen within the window, and remembers
// it.
func (o *Once) First(key string) bool {
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	window := o.Window
	if window <= 0 {
		window = time.Minute
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.seen == nil {
		o.seen, o.order = map[string]*list.Element{}, list.New()
	}
	if el, ok := o.seen[key]; ok {
		e := el.Value.(*onceEntry) //nolint:forcetypeassert // only onceEntry is stored
		if now.Sub(e.at) < window {
			return false
		}
		e.at = now
		o.order.MoveToFront(el)
		return true
	}
	o.seen[key] = o.order.PushFront(&onceEntry{key: key, at: now})
	for o.order.Len() > OnceEntries {
		last := o.order.Back()
		o.order.Remove(last)
		delete(o.seen, last.Value.(*onceEntry).key) //nolint:forcetypeassert // only onceEntry is stored
	}
	return true
}
