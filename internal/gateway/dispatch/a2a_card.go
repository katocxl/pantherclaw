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
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	mt, _, _ := mime.ParseMediaType(res.ContentType)
	if res.Status != http.StatusOK || res.Truncated || (mt != "application/json" && mt != wire.ContentType) {
		return nil, fmt.Errorf("dispatch: card not read: status %d", res.Status)
	}
	raw := bytes.TrimSpace(res.Body)
	observed, err := wire.Digest(raw)
	pinned := c.GetCardDigest()
	drift := &Drift{Tool: A2ADriftTool, Expected: hex.EncodeToString(pinned), Observed: hex.EncodeToString(observed[:])}
	switch {
	case err != nil:
		drift.Observed = "invalid"
	case !bytes.Equal(observed[:], pinned):
	default:
		keys, kerr := wire.ParseKeys(c.GetCardKeys())
		if kerr == nil {
			kerr = wire.VerifySignatures(raw, keys)
		}
		if kerr == nil {
			return nil, nil
		}
		if errors.Is(kerr, wire.ErrKeysInvalid) {
			return nil, kerr
		}
		drift.Observed = "signature"
	}
	a2aDrifted.Store(driftKey(e, conn), struct{}{})
	return drift, nil
}
