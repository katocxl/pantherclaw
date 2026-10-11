// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// currentDEKTTL is how long the Authority reuses an org's current
// evaluation_inputs DEK before reading it again.
const currentDEKTTL = time.Minute

// replayInputs is the sealer of every evaluation's inputs (G0 M7 design
// decision 11): the org's evaluation_inputs DEK, its current version cached
// so that Authorize does not read it in a transaction of its own each time.
func replayInputs(pool *db.Pool, kp keys.KeyProvider) *recording.Sealer {
	deks := keystore.NewCurrentCache(keystore.NewDEKStore(pool, kp), currentDEKTTL, clock.System{})
	return recording.NewSealer(pccrypto.NewEnvelope(deks))
}

// replayEngine is ReplayDecision's engine (G0 M7 design decision 11,
// HR-197): read ports only. Its source reads in READ ONLY transactions and
// its opener only reads the DEK version a row was sealed with.
func replayEngine(pool *db.Pool, kp keys.KeyProvider) *replay.Engine {
	return &replay.Engine{
		Source: &pgauthority.ReplaySource{Pool: pool, Definitions: &defspg.Store{Pool: pool}, FactStore: &factspg.Store{Pool: pool}},
		Inputs: recording.NewSealer(pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp))),
	}
}
