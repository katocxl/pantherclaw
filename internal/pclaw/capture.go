// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw capture profile create|list|disable and pclaw capture read (G0 M7
// design decision 10, HR-199). A person holding evidence.capture.manage
// (the Records Manager) creates and disables profiles; only a person
// holding evidence.read_restricted (the Auditor) reads a capture, with a
// reason, and the read is audited before the content is returned.

func init() {
	profiles := captureProfileCommands()
	usages := make([]string, 0, len(profiles))
	for _, k := range []string{"create", "list", "disable"} {
		usages = append(usages, profiles[k].usage)
	}
	// "capture profile VERB": one two-word command that dispatches the verb.
	commands["capture profile"] = command{
		usage: strings.Join(usages, "\n  pclaw "),
		run: func(ctx context.Context, a *app, args []string) error {
			if len(args) == 0 {
				return errUsage
			}
			c, ok := profiles[args[0]]
			if !ok {
				return errUsage
			}
			return c.run(ctx, a, args[1:])
		},
	}
	commands["capture read"] = command{
		usage: "capture read TRANSACTION --direction request|response --reason TEXT [--out FILE]",
		run:   captureRead,
	}
}

func captureProfileCommands() map[string]command {
	return map[string]command{
		"create": adminRPC("capture profile create --purpose TEXT --connection ID... --operation OP... "+
			"[--request] [--response] --byte-cap N --retention-days N --expires-in-days N", 0, func(fs *flag.FlagSet) adminCall {
			purpose := fs.String("purpose", "", "why payloads are captured (recorded; required)")
			var conns, ops list
			fs.Var(&conns, "connection", "a connection to capture on (repeatable)")
			fs.Var(&ops, "operation", "an operation to capture, such as payments.refund.create (repeatable)")
			req, resp := fs.Bool("request", false, "capture the outbound body"), fs.Bool("response", false, "capture the target's response")
			byteCap := fs.Int("byte-cap", 0, "bytes kept per body, at most 65536 (required)")
			retention := fs.Int("retention-days", 0, "days a capture is kept, at most 30 (required)")
			expires := fs.Int("expires-in-days", 0, "days until the profile expires, at most 90 (required)")
			return func(ctx context.Context, c pantherclawv1connect.EvidenceAdminServiceClient, _ []string) (proto.Message, error) {
				switch {
				case *purpose == "":
					return nil, errors.New("--purpose is required: say why payloads are captured")
				case !*req && !*resp:
					return nil, errors.New("capture --request, --response or both")
				case *byteCap < 1 || *byteCap > 65536 || *retention < 1 || *retention > 30 || *expires < 1 || *expires > 90:
					return nil, errors.New("--byte-cap must be 1..65536, --retention-days 1..30 and --expires-in-days 1..90")
				}
				return c.CreateCaptureProfile(ctx, &pantherclawv1.CreateCaptureProfileRequest{
					Purpose: *purpose, ConnectionIds: conns, Operations: ops, CaptureRequest: *req, CaptureResponse: *resp,
					ByteCap: int32(*byteCap), RetentionDays: int32(*retention), ExpiresInDays: int32(*expires),
				})
			}
		}),
		"list": adminRPC("capture profile list [--state active|disabled|expired]", 0, func(fs *flag.FlagSet) adminCall {
			state := fs.String("state", "", "active, disabled or expired (default: all)")
			n, tok := paging(fs)
			return func(ctx context.Context, c pantherclawv1connect.EvidenceAdminServiceClient, _ []string) (proto.Message, error) {
				req := &pantherclawv1.ListCaptureProfilesRequest{PageSize: size(n), PageToken: *tok}
				if *state != "" {
					st, err := enumOf[pantherclawv1.CaptureProfileState](pantherclawv1.CaptureProfileState_value, "CAPTURE_PROFILE_STATE_", "state", *state)
					if err != nil {
						return nil, err
					}
					req.State = st
				}
				return c.ListCaptureProfiles(ctx, req)
			}
		}),
		"disable": adminRPC("capture profile disable ID", 1, func(*flag.FlagSet) adminCall {
			return func(ctx context.Context, c pantherclawv1connect.EvidenceAdminServiceClient, a []string) (proto.Message, error) {
				return c.DisableCaptureProfile(ctx, &pantherclawv1.DisableCaptureProfileRequest{Id: a[0]})
			}
		}),
	}
}

// captureRead reads one capture. With --out the content goes to a new file
// (0600) and only its metadata is printed; without it the response is
// printed as JSON (content in base64).
func captureRead(ctx context.Context, a *app, args []string) error {
	if len(args) < 1 {
		return errUsage
	}
	fs := flag.NewFlagSet("capture read", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	direction := fs.String("direction", "", "request or response (required)")
	reason := fs.String("reason", "", "why you read it (recorded in the audit log; required)")
	out := fs.String("out", "", "write the content to this new file instead of printing it")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	if *reason == "" {
		return errors.New("--reason is required: every read is audited with its reason")
	}
	d, err := enumOf[pantherclawv1.CaptureDirection](pantherclawv1.CaptureDirection_value, "CAPTURE_DIRECTION_", "direction", *direction)
	if err != nil {
		return err
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	res, err := pantherclawv1connect.NewEvidenceAdminServiceClient(s.connect()).ReadPayloadCapture(ctx,
		&pantherclawv1.ReadPayloadCaptureRequest{TransactionId: args[0], Direction: d, Reason: *reason})
	if err != nil {
		return err
	}
	if *out == "" {
		return a.print(res)
	}
	if err := writeNew(*out, res.GetContent()); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(a.stderr, "wrote %d bytes to %s\n", len(res.GetContent()), *out)
	res.Content = nil
	return a.print(res)
}
