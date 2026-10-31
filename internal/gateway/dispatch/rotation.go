// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"sync"
	"time"

	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// Rotation lease purposes (G0 M20 S20c, D253, D259).
const (
	PurposeRotationTest    = "credential_rotation_test"
	PurposeRotationConfirm = "credential_rotation_confirm"
)

// ErrRotationLease refuses a rotation lease the gateway cannot use: a
// malformed request, a credential that is not this connection's GitHub App
// key, or one for another installation. Nothing is sent.
var ErrRotationLease = errors.New("dispatch: the rotation lease names no GitHub App key of this connection")

// ProbeRotation runs a rotation lease (HR-060, HR-517): the lease carries
// the sealed credential, the candidate to test or the old key to confirm
// dead, which never enters the gateway's configuration. It opens only here,
// with the binding rebuilt from this gateway's own view, for the same
// installation as the connection, and is cleared when the probe ends. A
// test asks GitHub who the App is (GET /app) and reads the installation; a
// confirmation asks GET /app with the old key and, at the same moment, with
// the active key (D274): GitHub must refuse the first and accept the second.
// Neither mints a token.
func (e *Engine) ProbeRotation(ctx context.Context, conn *control.Connection, l Lease) (Observation, error) {
	if _, class, _ := e.contained(conn); class != "" {
		return Observation{}, ErrContained
	}
	if l.Purpose != PurposeRotationTest && l.Purpose != PurposeRotationConfirm {
		return Observation{}, ErrRotationLease
	}
	var req credentials.RotationLease
	if err := json.Unmarshal(l.Request, &req, json.RejectUnknownMembers(true)); err != nil {
		return Observation{}, fmt.Errorf("%w: request", ErrRotationLease)
	}
	cred := req.Credential
	if cred.Kind != credentials.KindGitHubApp || cred.Header != credentials.GitHubAppHeader || cred.Scheme != credentials.GitHubAppScheme {
		return Observation{}, ErrRotationLease
	}
	if e.broker == nil {
		return Observation{}, broker.ErrNoBroker
	}
	plain, err := e.broker.Open(e.org, conn.GetId(), conn.GetAllowedHosts(), broker.Sealed{
		Version: cred.Version, BrokerKey: cred.BrokerKey, Blob: cred.Sealed, Header: cred.Header, Scheme: cred.Scheme, Kind: cred.Kind,
	})
	if err != nil {
		return Observation{}, err
	}
	app, err := credentials.DecodeGitHubApp(plain)
	clear(plain)
	if err != nil {
		return Observation{}, fmt.Errorf("%w: %w", ErrRotationLease, err)
	}
	defer app.Clear()
	if !installed(conn, app) {
		return Observation{}, fmt.Errorf("%w: %w", ErrRotationLease, errInstallation)
	}
	base, c, err := e.gitHubAPI(conn)
	if err != nil {
		return Observation{}, err
	}
	hosts := conn.GetAllowedHosts()
	var p credentials.Probe
	if l.Purpose == PurposeRotationConfirm {
		// A controlled comparison (D274): GET /app with the old key and,
		// at the same moment, with the active key from the configuration,
		// which must be the rotation's new key. Only "old refused, active
		// accepted" tells a deleted key from a JWT GitHub refuses for any
		// other reason, such as a skewed clock.
		if cur := conn.Credential; cur == nil || req.Active == "" || cur.GetId() != req.Active || cur.GetKind() != credentials.KindGitHubApp {
			return Observation{}, fmt.Errorf("%w: the active credential is not the rotation's new key", ErrRotationLease)
		}
		active, err := e.openApp(conn)
		if err != nil {
			return Observation{}, err
		}
		defer active.Clear()
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.ActiveStatus, p.ActiveMatches, _ = broker.ProbeApp(ctx, c, base, hosts, active, time.Now())
		}()
		p.AppStatus, p.AppMatches, _ = broker.ProbeApp(ctx, c, base, hosts, app, time.Now())
		wg.Wait()
		return Observation{HTTPStatus: p.AppStatus, Found: p.AppStatus != 0, Complete: true, Fields: p.Fields()}, nil
	}
	status, matches, err := broker.ProbeApp(ctx, c, base, hosts, app, time.Now())
	if err != nil {
		// No answer proves nothing: the server keeps the rotation where it is.
		e.log.InfoContext(ctx, "gateway.rotation_probe_unanswered")
	}
	p.AppStatus, p.AppMatches = status, matches
	if p.AppStatus != 0 {
		if p.InstallationStatus, err = broker.ProbeInstallation(ctx, c, base, hosts, app, time.Now()); err != nil {
			e.log.InfoContext(ctx, "gateway.rotation_probe_unanswered")
		}
	}
	return Observation{HTTPStatus: p.AppStatus, Found: p.AppStatus != 0, Complete: true, Fields: p.Fields()}, nil
}
