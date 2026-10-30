// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// errAWSAccount refuses an action whose target names another AWS account
// than the role every session assumes (HR-525, T-225).
var errAWSAccount = errors.New("dispatch: the target is in another AWS account than the connection's role")

// awsSession opens the connection's AWS credential and assumes its role for
// one dispatch of def (G0 M20 D254, HR-525): a session narrowed to exactly
// the one action the package fixes for def, for 15 minutes, through an
// egress client pinned to the STS host, which the seal must bind. A target
// that names an account must name the role's. The base secret is cleared
// as soon as AssumeRole is signed; the caller clears the session.
func (e *Engine) awsSession(ctx context.Context, conn *control.Connection, def *defs.Definition, target actionir.Target) (*broker.AWSSession, error) {
	action, ok := def.AWSAction()
	if !ok {
		return nil, broker.ErrAWSAction
	}
	plain, err := e.openCredential(conn)
	if err != nil {
		return nil, err
	}
	a, err := credentials.DecodeAWSSigV4(plain)
	clear(plain)
	if err != nil {
		return nil, err
	}
	defer a.Clear()
	if def.Target.Account != defs.PresenceNone && target.Account != "" && target.Account != a.Account() {
		return nil, errAWSAccount
	}
	policy, err := broker.SessionPolicy(a.Service, action)
	if err != nil {
		return nil, err
	}
	c, err := e.tokenClient(conn, a.STSURL)
	if err != nil {
		return nil, err
	}
	return broker.AssumeRole(ctx, c, conn.Credential.GetAllowedHosts(), a, policy, time.Now())
}

// signAWS assumes a session for def and signs req with it: the body it
// signs is the one req will send.
func (e *Engine) signAWS(ctx context.Context, conn *control.Connection, def *defs.Definition, target actionir.Target, req *http.Request) (*broker.AWSSession, error) {
	s, err := e.awsSession(ctx, conn, def, target)
	if err != nil {
		return nil, err
	}
	var body []byte
	if req.GetBody != nil {
		rc, err := req.GetBody()
		if err == nil {
			body, err = io.ReadAll(rc)
			_ = rc.Close()
		}
		if err != nil {
			s.Clear()
			return nil, err
		}
	}
	if err := s.Sign(req, body, time.Now()); err != nil {
		s.Clear()
		return nil, err
	}
	return s, nil
}
