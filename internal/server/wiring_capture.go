// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/evidence/capture"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// captureServices seal and open restricted payload captures with each
// org's payload_captures key (G0 M7 design decision 10, HR-199, HR-062).
type captureServices struct {
	env      *pccrypto.Envelope
	recorder *capture.Recorder
}

// newCaptures builds the capture envelope (the org's current
// payload_captures DEK cached like the replay inputs') and the recorder
// the Authority hands the captures of each outcome to.
func newCaptures(pool *db.Pool, kp keys.KeyProvider, log *slog.Logger) *captureServices {
	deks := keystore.NewCurrentCache(keystore.NewDEKStore(pool, kp), currentDEKTTL, clock.System{})
	env := pccrypto.NewEnvelope(deks)
	return &captureServices{env: env, recorder: &capture.Recorder{Pool: pool, Env: env, Log: log}}
}

// service returns the capture use cases; without the envelope a capture
// cannot be read.
func (c *captureServices) service(pool *db.Pool) *capture.Service {
	s := &capture.Service{Pool: pool}
	if c != nil {
		s.Env = c.env
	}
	return s
}
