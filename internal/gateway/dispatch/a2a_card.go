// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"sync"
	"time"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
)

// Card drift (G0 M14 D30, HR-322): the gateway reads each a2a connection's
// card again on every configuration load and every 10 minutes. A card
// whose digest is not the pinned one, or whose signatures no longer verify
// with the pinned keys, is drift: the gateway refuses the connection at
// once (A2A_CARD_DRIFT, nothing sent) until a new pin arrives, and reports
// it. A card that cannot be read is not drift; the next read decides.

// CodeA2ACardDrift: the peer's card is not the pinned one.
const CodeA2ACardDrift = "a2a_card_drift"

// A2ADriftTool names a card in a drift report.
const A2ADriftTool = "a2a.card"

// a2aDrifted are the (engine, connection, pinned digest) whose card a read
// found changed. A new pin is a new key, so it is served again.
var a2aDrifted sync.Map // a2aDriftKey → struct{}

type a2aDriftKey struct {
	e      *Engine
	conn   string
	digest string
}

func driftKey(e *Engine, conn *control.Connection) a2aDriftKey {
	return a2aDriftKey{e: e, conn: conn.GetId(), digest: hex.EncodeToString(conn.GetA2A().GetCardDigest())}
}

// A2ACardDrifted reports whether a read found the connection's card
// changed since its current pin.
func (e *Engine) A2ACardDrifted(conn *control.Connection) bool {
	_, ok := a2aDrifted.Load(driftKey(e, conn))
	return ok
}

// CheckA2ACard reads an a2a connection's card and compares it with the
// pin. It returns a Drift when the card changed (and from then on refuses
// the connection), nil when it is the pinned one, and an error when it
// could not be read.
func (e *Engine) CheckA2ACard(ctx context.Context, conn *control.Connection) (*Drift, error) {
	c := conn.GetA2A()
	if conn.GetKind() != "a2a" || c == nil || len(c.GetCardDigest()) != 32 {
		return nil, nil
	}
	if code := e.simulatorRefusal(ctx, conn); code != "" {
		return nil, fmt.Errorf("dispatch: card not read: %s", code)
	}
	client, err := egress.NewClient(c.GetCardUrl(), 10*time.Second, wire.MaxCardBytes, e.allowed)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.GetCardUrl(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	pinned := c.GetCardDigest()
	key := driftKey(e, conn)
	res, err := client.Do(req)
	if err != nil || res.Status != http.StatusOK {
		// Unreadable is not drift at once, but a card that stays unreadable
		// cannot keep a stale pin serving (D96 L2).
		if n := a2aUnreadable(key, true); n >= MaxA2AUnreadable {
			a2aDrifted.Store(key, struct{}{})
			return &Drift{Tool: A2ADriftTool, Expected: hex.EncodeToString(pinned), Observed: "unreadable"}, nil
		}
		if err == nil {
			err = fmt.Errorf("dispatch: card not read: status %d", res.Status)
		}
		return nil, err
	}
	a2aUnreadable(key, false)
	mt, _, _ := mime.ParseMediaType(res.ContentType)
	raw := bytes.TrimSpace(res.Body)
	observed, err := wire.Digest(raw)
	drift := &Drift{Tool: A2ADriftTool, Expected: hex.EncodeToString(pinned), Observed: hex.EncodeToString(observed[:])}
	switch {
	case res.Truncated, mt != "application/json" && mt != wire.ContentType:
		// An oversize card, or one served as something else, is not the
		// pinned one (D96 L2).
		drift.Observed = "invalid"
	case err != nil:
		drift.Observed = "invalid"
	case !bytes.Equal(observed[:], pinned):
	default:
		keys, kerr := wire.ParseKeys(c.GetCardKeys())
		if kerr == nil {
			kerr = wire.VerifySignatures(raw, keys)
		}
		if kerr == nil {
			// The pinned card again: a mark from an earlier read is cleared;
			// the server keeps a drifted connection quarantined until a new
			// pin is confirmed (D86).
			a2aDrifted.Delete(key)
			return nil, nil
		}
		if errors.Is(kerr, wire.ErrKeysInvalid) {
			return nil, kerr
		}
		drift.Observed = "signature"
	}
	a2aDrifted.Store(key, struct{}{})
	return drift, nil
}

// MaxA2AUnreadable is how many reads in a row may fail before an a2a card
// counts as drifted (at the 10-minute re-read, about an hour).
const MaxA2AUnreadable = 6

var a2aFailures sync.Map // a2aDriftKey → int

// a2aUnreadable counts a failed read of key (failed) or clears the count,
// and returns the count.
func a2aUnreadable(key a2aDriftKey, failed bool) int {
	if !failed {
		a2aFailures.Delete(key)
		return 0
	}
	n := 1
	if v, ok := a2aFailures.Load(key); ok {
		n += v.(int) //nolint:forcetypeassert // only ints are stored
	}
	a2aFailures.Store(key, n)
	return n
}
