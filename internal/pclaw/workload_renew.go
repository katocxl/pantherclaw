// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// `pclaw workload renew` (G0 M3 workload renewal) keeps a long-running
// service's workload token fresh in an owner-only file that it replaces
// atomically (decision 1). It runs until it is stopped (SIGINT, SIGTERM:
// exit 0, the file stays) or the server refuses renewal for good (the file
// is removed, exit 3; decision 2). It opens no listener, and the token
// never appears in its output (HR-056).

// exitRefused is the exit code of a renewal the server refused for good,
// which a supervisor should not restart (systemd RestartPreventExitStatus).
const exitRefused = 3

func init() {
	commands["workload renew"] = command{
		usage: "workload renew --key-file FILE --out FILE [--github | --kubernetes-token FILE | --gitlab-token-env VAR] [--declared-release sha256:…]",
		run:   workloadRenew,
	}
}

func workloadRenew(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("workload renew", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	keyFile := fs.String("key-file", "", "enrolled workload key file")
	out := fs.String("out", "", "keep the current workload token in this file (0600, replaced atomically)")
	declared := fs.String("declared-release", "", "release digest the workload reports about itself")
	att := declareAttestation(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *out == "" || fs.NArg() != 0 {
		return errUsage
	}
	if err := att.check(); err != nil {
		return err
	}
	kf, err := workloadclient.ReadKeyFile(*keyFile)
	if err != nil {
		return err
	}
	inst, err := pap.ParseInstance(kf.Identifier)
	if err != nil || kf.Server == "" {
		return errors.New("the key file is not enrolled yet: run pclaw workload enroll")
	}
	wc, err := a.workloadClient(kf.Server, kf)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	tr := &tokenRenewal{a: a, wc: wc, identifier: kf.Identifier, org: inst.Org, declared: *declared, att: &att, name: "pclaw workload renew"}
	r := tr.renewer(func(iss workloadclient.Issued) error {
		if err := workloadclient.WriteTokenFile(*out, iss.Token); err != nil {
			return err
		}
		tr.report(fmt.Sprintf("token for instance %s in %s (L%d, valid until %s)", inst.Instance, *out, iss.Level, iss.ExpiresAt.UTC().Format(time.RFC3339)))
		return nil
	})
	err = r.Run(ctx)
	var refusal *workloadclient.RefusalError
	if !errors.As(err, &refusal) {
		return err
	}
	msg := tr.name + ": " + refusalHelp(refusal.Code, inst, *keyFile, kf.Server)
	if rmErr := workloadclient.RemoveTokenFile(*out); rmErr != nil {
		msg += "\n" + tr.name + ": " + rmErr.Error()
	} else {
		msg += " The token file was removed."
	}
	return &exitError{code: exitRefused, msg: msg}
}

// refusalHelp explains a refusal and what to do next.
func refusalHelp(code pap.Code, inst pap.Instance, keyFile, server string) string {
	head := "the server refused renewal (" + string(code) + "): "
	//exhaustive:ignore // only the refusals that end renewal (workloadclient.RefusalError) reach here
	switch code {
	case pap.CodeInstanceNotAdmitted:
		return head + fmt.Sprintf("instance %s was revoked, rejected or never admitted, or its agent %s is suspended or retired. "+
			"The agent's owner can check with: pclaw instance get %s, and pclaw agent get %s.", inst.Instance, inst.Agent, inst.Instance, inst.Agent)
	case pap.CodeKeyMismatch:
		return head + fmt.Sprintf("the key in %s is not the key instance %s enrolled with. A new key must enroll as a new instance (pclaw workload enroll).",
			keyFile, inst.Instance)
	case pap.CodeInvalidToken:
		return head + fmt.Sprintf("%s does not know instance %s. Check that the key file belongs to that server.", server, inst.Instance)
	default:
		return head + "retrying cannot help."
	}
}

// tokenRenewal asks the server for workload tokens on behalf of a
// long-running process (pclaw workload renew, pclaw mcp proxy), re-attests
// when it can, and reports changes of level on stderr.
type tokenRenewal struct {
	a          *app
	wc         pantherclawv1connect.WorkloadServiceClient
	identifier string
	org        ids.OrgID
	declared   string
	// att is nil for a process that never attests (the desktop proxy, L1).
	att  *attestationFlags
	name string

	// seen is the projected service-account token the server last answered
	// for: each is single use (HR-143), so it is sent once.
	seen  [sha256.Size]byte
	level int
}

// renewer returns a Renewer that issues tokens through tr and hands them
// to deliver.
func (tr *tokenRenewal) renewer(deliver func(workloadclient.Issued) error) *workloadclient.Renewer {
	return &workloadclient.Renewer{Issue: tr.issue, Deliver: deliver, Report: tr.report}
}

func (tr *tokenRenewal) report(s string) { _, _ = fmt.Fprintf(tr.a.stderr, "%s: %s\n", tr.name, s) }

// issue asks for one token. It attests with a fresh GitHub token every
// time, and with a projected Kubernetes token or a GitLab ID token only
// while it is one not yet sent (the kubelet rotates the first; a GitLab job
// has one). A refused attestation is reported and the request is sent
// again without one: the server then keeps L2 until the last accepted
// attestation expires, and issues L1 after that (HR-143). A reused
// attestation token is refused as invalid_token, so with an attestation
// that code means the attestation, not the instance.
func (tr *tokenRenewal) issue(ctx context.Context) (workloadclient.Issued, error) {
	req := &pantherclawv1.IssueTokenRequest{Identifier: tr.identifier, DeclaredReleaseDigest: tr.declared}
	var sum [sha256.Size]byte
	if tr.att != nil {
		att, err := tr.att.attestation(ctx, tr.a, tr.org)
		switch {
		case err != nil:
			tr.report(fmt.Sprintf("renewing without an attestation: %v", err))
		case att != nil && att.GetKind() != pantherclawv1.AttestationKind_ATTESTATION_KIND_GITHUB_ACTIONS:
			// A token read from a file or the environment is sent once:
			// the server refuses it again (HR-143).
			if sum = sha256.Sum256([]byte(att.GetToken())); sum != tr.seen {
				req.Attestation = att
			}
		default:
			req.Attestation = att
		}
	}
	res, err := tr.wc.IssueToken(ctx, req)
	if req.Attestation != nil {
		code, _ := workloadclient.CodeOf(err)
		if refused := code == pap.CodeAttestationLow || code == pap.CodeInvalidToken; err == nil || refused {
			tr.seen = sum
			if refused {
				tr.report(fmt.Sprintf("the server refused the attestation (%s: already used, or it does not match the instance's issuer entry); "+
					"renewing without it, so L2 lasts only until the last accepted attestation expires", code))
				req.Attestation = nil
				res, err = tr.wc.IssueToken(ctx, req)
			}
		}
	}
	if err != nil {
		return workloadclient.Issued{}, err
	}
	level := int(res.GetAttestationLevel())
	if tr.level != 0 && level != tr.level {
		tr.report(fmt.Sprintf("attestation level changed from L%d to L%d", tr.level, level))
	}
	tr.level = level
	return workloadclient.Issued{Token: res.GetWorkloadToken(), ExpiresAt: res.GetExpireTime().AsTime(), Level: level}, nil
}
