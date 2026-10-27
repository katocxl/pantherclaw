// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"slices"
)

// Post-quantum TLS (G0 M13 D35, PN-019.2). Listeners that third parties
// reach keep Go's defaults (CurvePreferences nil: hybrid post-quantum
// first, classical groups still accepted). Links between PantherClaw
// components — the gateway's control client and the server's gateway
// listener, and the sandbox edge's client to the gateway — accept only a
// hybrid post-quantum key exchange, on both ends where both ends are
// PantherClaw's, so traffic recorded today cannot be decrypted later by a
// quantum computer (HR-395, T-178).

// ErrClassicalKeyExchange reports a component link that negotiated a key
// exchange without a post-quantum part.
var ErrClassicalKeyExchange = errors.New("httpx: a link between PantherClaw components negotiated a classical key exchange")

// ComponentLinkGroups are the hybrid post-quantum key exchanges a link
// between PantherClaw components may use.
func ComponentLinkGroups() []tls.CurveID {
	return []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}
}

// ComponentLinkTLS restricts c, one end of a link between PantherClaw
// components, to TLS 1.3 and the hybrid post-quantum groups, refuses any
// connection that negotiated another group, and logs the negotiated group
// of each connection (tls.link) when log is set. link names the link in the
// log line. Any VerifyConnection already on c still runs. It returns c.
func ComponentLinkTLS(c *tls.Config, link string, log *slog.Logger) *tls.Config {
	c.MinVersion = tls.VersionTLS13
	c.CurvePreferences = ComponentLinkGroups()
	next := c.VerifyConnection
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if !slices.Contains(ComponentLinkGroups(), cs.CurveID) {
			if log != nil {
				log.Warn("tls.link_refused", slog.String("link", link), slog.String("group", cs.CurveID.String()))
			}
			return fmt.Errorf("%w (%s)", ErrClassicalKeyExchange, cs.CurveID)
		}
		if next != nil {
			if err := next(cs); err != nil {
				return err
			}
		}
		if log != nil {
			log.Info("tls.link", slog.String("link", link), slog.String("group", cs.CurveID.String()))
		}
		return nil
	}
	return c
}
