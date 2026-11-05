// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// Backoff while enrolment or a run start fails: every invocation meanwhile
// is answered with a deny.
const (
	retryMin = 2 * time.Second
	retryMax = 5 * time.Minute
)

// interceptor is one Lambda execution environment's PantherClaw identity:
// its in-memory key, its instance, its workload token and its run.
type interceptor struct {
	c   config
	log *slog.Logger
	key ed25519.PrivateKey

	// keyOnly signs key-only proofs (Enroll, IssueToken); withToken also
	// sends the workload token (the run start and the gateway's face).
	keyOnly, withToken *http.Client

	mu         sync.Mutex
	identifier string
	token      string
	run        string
	wakeup     chan struct{}
}

func newInterceptor(c config, log *slog.Logger) (*interceptor, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader) // in memory only (D995, HR-766)
	if err != nil {
		return nil, err
	}
	ic := &interceptor{c: c, log: log, key: key, wakeup: make(chan struct{}, 1)}
	ic.keyOnly = &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{Key: key}, CheckRedirect: noRedirect}
	ic.withToken = &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{Key: key, Token: ic.Token}, CheckRedirect: noRedirect}
	return ic, nil
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse } // HR-070

// Token returns the current workload token, "" when there is none.
func (ic *interceptor) Token() string {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	return ic.token
}

// Run returns the current run, "" while there is none.
func (ic *interceptor) Run() string {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	return ic.run
}

// RunEnded drops run when it is still the current one, so a new one starts.
func (ic *interceptor) RunEnded(run string) {
	ic.mu.Lock()
	if ic.run != run {
		ic.mu.Unlock()
		return
	}
	ic.run = ""
	ic.mu.Unlock()
	ic.log.Info("interceptor.run_ended", "run", run)
	select {
	case ic.wakeup <- struct{}{}:
	default:
	}
}

func (ic *interceptor) workloadClient() pantherclawv1connect.WorkloadServiceClient {
	return pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(ic.keyOnly, ic.c.server)))
}

// attestation signs a fresh aws_iam attestation with the Lambda role's
// credentials, for the org's audience.
func (ic *interceptor) attestation() (*pantherclawv1.Attestation, error) {
	tok, err := workloadclient.AWSAttestation(ic.c.aws, "pantherclaw:"+ic.c.org.String(), time.Now())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.Attestation{Kind: pantherclawv1.AttestationKind_ATTESTATION_KIND_AWS_IAM, Token: tok}, nil
}

// enroll enrolls the key with an aws_iam attestation. The issuer entry for
// the Lambda role must admit automatically: an instance waiting for
// admission is an error.
func (ic *interceptor) enroll(ctx context.Context) error {
	att, err := ic.attestation()
	if err != nil {
		return err
	}
	pub, _ := ic.key.Public().(ed25519.PublicKey)
	jwk, err := json.Marshal(jws.PublicJWK(pub, ""))
	if err != nil {
		return err
	}
	res, err := ic.workloadClient().Enroll(ctx, &pantherclawv1.EnrollRequest{PublicJwk: string(jwk), Attestation: att})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if res.GetState() != pantherclawv1.InstanceState_INSTANCE_STATE_ADMITTED {
		return fmt.Errorf("instance %s is not admitted (the Lambda role's issuer entry must admit automatically)", res.GetInstanceId())
	}
	ic.mu.Lock()
	ic.identifier = res.GetIdentifier()
	ic.mu.Unlock()
	ic.log.Info("interceptor.enrolled", "instance", res.GetInstanceId(), "attestation_level", res.GetAttestationLevel())
	return nil
}

// issue asks for one workload token with a fresh attestation; a refused
// attestation is retried without one, as pclaw does (HR-143).
func (ic *interceptor) issue(ctx context.Context) (workloadclient.Issued, error) {
	ic.mu.Lock()
	req := &pantherclawv1.IssueTokenRequest{Identifier: ic.identifier}
	ic.mu.Unlock()
	att, err := ic.attestation()
	if err != nil {
		ic.log.Warn("interceptor.renewal", "message", "renewing without an attestation: "+err.Error())
	} else {
		req.Attestation = att
	}
	wc := ic.workloadClient()
	res, err := wc.IssueToken(ctx, req)
	if req.Attestation != nil {
		if code, _ := workloadclient.CodeOf(err); code == pap.CodeAttestationLow || code == pap.CodeInvalidToken {
			ic.log.Warn("interceptor.renewal", "message", "the server refused the attestation ("+string(code)+"); renewing without it")
			req.Attestation = nil
			res, err = wc.IssueToken(ctx, req)
		}
	}
	if err != nil {
		return workloadclient.Issued{}, err
	}
	return workloadclient.Issued{Token: res.GetWorkloadToken(), ExpiresAt: res.GetExpireTime().AsTime(), Level: int(res.GetAttestationLevel())}, nil
}

func (ic *interceptor) deliver(iss workloadclient.Issued) error {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.token = iss.Token
	return nil
}

// dropToken clears the token after a refusal for good: from then on every
// invocation is answered with a deny.
func (ic *interceptor) dropToken() {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.token, ic.run = "", ""
}

// sleep waits d or until ctx ends; false when ctx ended.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// identity enrolls (retrying with backoff), keeps the workload token fresh
// and keeps a run going, until ctx ends or the server refuses the instance
// for good. Until each step is in place, invocations are answered with a
// deny.
func (ic *interceptor) identity(ctx context.Context) {
	wait := time.Duration(0)
	for {
		if wait > 0 && !sleep(ctx, wait) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if err := ic.enroll(ctx); err != nil {
			wait = min(max(2*wait, retryMin), retryMax)
			ic.log.Error("interceptor.enroll_refused", "error", err.Error(), "retry_in", wait.String())
			continue
		}
		break
	}
	renewer := &workloadclient.Renewer{Issue: ic.issue, Deliver: ic.deliver, Report: func(s string) { ic.log.Warn("interceptor.renewal", "message", s) }}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go ic.runs(rctx)
	if err := renewer.Run(rctx); err != nil {
		// A refusal for good: the instance is no longer admitted.
		var refused *workloadclient.RefusalError
		if errors.As(err, &refused) {
			ic.log.Error("interceptor.renewal_refused", "code", string(refused.Code))
		} else {
			ic.log.Error("interceptor.renewal_stopped", "error", err.Error())
		}
		ic.dropToken()
	}
}

// runs keeps one run going (D995): started once a token is in place, and
// again when the gateway says it ended.
func (ic *interceptor) runs(ctx context.Context) {
	wait := time.Duration(0)
	for {
		if wait > 0 && !sleep(ctx, wait) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if ic.Token() == "" {
			wait = retryMin
			continue
		}
		if ic.Run() == "" {
			run, err := ic.startRun(ctx, ic.c.runName)
			if err != nil {
				wait = min(max(2*wait, retryMin), retryMax)
				ic.log.Error("interceptor.run_refused", "name", ic.c.runName, "error", err.Error(), "retry_in", wait.String())
				continue
			}
			ic.mu.Lock()
			ic.run = run
			ic.mu.Unlock()
			ic.log.Info("interceptor.run_started", "name", ic.c.runName, "run", run)
		}
		wait = 0
		select {
		case <-ctx.Done():
			return
		case <-ic.wakeup:
		}
	}
}
