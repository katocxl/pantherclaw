// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
)

// Credential rotation commands (G0 M22 D5, F831, HR-553). `seal` encrypts the
// new key on this machine, as pclaw seal does. Activating and rolling back
// need a security key, so the server refuses them here and a person uses the
// page; pclaw says which.

type rotationCall func(ctx context.Context, c pantherclawv1connect.CredentialRotationServiceClient, args []string) (proto.Message, error)

// rotationPageHint explains a STEP_UP_REQUIRED refusal: the page does it.
func rotationPageHint(a *app, err error, args []string) error {
	if len(args) > 0 && strings.Contains(err.Error(), "STEP_UP_REQUIRED") {
		_, _ = fmt.Fprintf(a.stderr, "this needs your security key: open /integrations/credential-rotations/%s on the server in a browser\n", args[0])
	}
	return err
}

// rotationRPC is rpc for CredentialRotationService: one id, then flags.
func rotationRPC(usage string, setup func(fs *flag.FlagSet) rotationCall) command {
	return command{usage: usage, run: func(ctx context.Context, a *app, args []string) error {
		if len(args) < 1 {
			return errUsage
		}
		fs := flag.NewFlagSet(usage, flag.ContinueOnError)
		fs.SetOutput(a.stderr)
		fn := setup(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errUsage
		}
		s, err := a.session()
		if err != nil {
			return err
		}
		res, err := fn(ctx, pantherclawv1connect.NewCredentialRotationServiceClient(s.connect()), args[:1])
		if err != nil {
			return rotationPageHint(a, err, args)
		}
		return a.print(res)
	}}
}

func init() {
	commands["credential rotation request"] = rotationRPC("credential rotation request CONNECTION --preview-digest HEX", func(fs *flag.FlagSet) rotationCall {
		digest := fs.String("preview-digest", "", "the digest from the preview of who shares the active credential")
		return func(ctx context.Context, c pantherclawv1connect.CredentialRotationServiceClient, a []string) (proto.Message, error) {
			if *digest == "" {
				return nil, errUsage
			}
			return c.RequestRotation(ctx, &pb.RequestRotationRequest{ConnectionId: a[0], PreviewDigest: *digest})
		}
	})
	commands["credential rotation seal"] = command{
		usage: "credential rotation seal ROTATION --connection ID --from-file FILE|- --github-app ID --installation N --account LOGIN [--fingerprint sha256:HEX]",
		run:   rotationSeal,
	}
	commands["credential rotation test"] = rotationRPC("credential rotation test ROTATION", func(*flag.FlagSet) rotationCall {
		return func(ctx context.Context, c pantherclawv1connect.CredentialRotationServiceClient, a []string) (proto.Message, error) {
			return c.TestRotation(ctx, &pb.TestRotationRequest{Id: a[0]})
		}
	})
	commands["credential rotation activate"] = rotationRPC("credential rotation activate ROTATION", func(*flag.FlagSet) rotationCall {
		return func(ctx context.Context, c pantherclawv1connect.CredentialRotationServiceClient, a []string) (proto.Message, error) {
			return c.ActivateRotation(ctx, &pb.ActivateRotationRequest{Id: a[0]})
		}
	})
	commands["credential rotation rollback"] = rotationRPC("credential rotation rollback ROTATION --reason TEXT", func(fs *flag.FlagSet) rotationCall {
		reason := fs.String("reason", "", "why the old key goes back")
		return func(ctx context.Context, c pantherclawv1connect.CredentialRotationServiceClient, a []string) (proto.Message, error) {
			return c.RollBackRotation(ctx, &pb.RollBackRotationRequest{Id: a[0], Reason: *reason})
		}
	})
	commands["credential rotation confirm"] = rotationRPC("credential rotation confirm ROTATION", func(*flag.FlagSet) rotationCall {
		return func(ctx context.Context, c pantherclawv1connect.CredentialRotationServiceClient, a []string) (proto.Message, error) {
			return c.ConfirmRotation(ctx, &pb.ConfirmRotationRequest{Id: a[0]})
		}
	})
	commands["credential rotation cancel"] = rotationRPC("credential rotation cancel ROTATION --reason TEXT", func(fs *flag.FlagSet) rotationCall {
		reason := fs.String("reason", "", "why the rotation ends")
		return func(ctx context.Context, c pantherclawv1connect.CredentialRotationServiceClient, a []string) (proto.Message, error) {
			return c.CancelRotation(ctx, &pb.CancelRotationRequest{Id: a[0], Reason: *reason})
		}
	})
	commands["credential rotation get"] = rotationRPC("credential rotation get ROTATION", func(*flag.FlagSet) rotationCall {
		return func(ctx context.Context, c pantherclawv1connect.CredentialRotationServiceClient, a []string) (proto.Message, error) {
			return c.GetRotation(ctx, &pb.GetRotationRequest{Id: a[0]})
		}
	})
	commands["credential rotation list"] = rotationRPC("credential rotation list CONNECTION", func(*flag.FlagSet) rotationCall {
		return func(ctx context.Context, c pantherclawv1connect.CredentialRotationServiceClient, a []string) (proto.Message, error) {
			return c.ListRotations(ctx, &pb.ListRotationsRequest{ConnectionId: a[0]})
		}
	})
}

// rotationSeal seals a GitHub App's new private key to the connection's
// gateway and uploads the sealed bytes as the rotation's candidate. The
// plaintext never leaves this machine and is never printed (HR-060).
func rotationSeal(ctx context.Context, a *app, args []string) error {
	if len(args) < 1 {
		return errUsage
	}
	rotation := args[0]
	fs := flag.NewFlagSet("credential rotation seal", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	conn := fs.String("connection", "", "connection id")
	from := fs.String("from-file", "", "file holding the App's new private key (.pem), or - for stdin (never pass it on the command line)")
	expect := fs.String("fingerprint", "", "the broker key fingerprint the gateway's operator gave you; sealing stops if it differs")
	gh := fs.String("github-app", "", "the App's client id (Iv…) or numeric id")
	installation := fs.Int64("installation", 0, "the installation id")
	account := fs.String("account", "", "the account the App is installed on, in lowercase")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *conn == "" || *from == "" || *gh == "" || *installation == 0 || *account == "" {
		return errUsage
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	k, err := c.connections.GetSealingKey(ctx, &pb.GetSealingKeyRequest{ConnectionId: *conn})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(k.GetPublicKey())
	fp := "sha256:" + hex.EncodeToString(sum[:])
	if fp != k.GetFingerprint() {
		return errors.New("the server's broker key does not match its fingerprint; nothing was sealed")
	}
	if *expect != "" && !strings.EqualFold(*expect, fp) {
		return fmt.Errorf("the broker key is %s, not the expected %s; nothing was sealed", fp, *expect)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.GetPublicKey())
	if err != nil {
		return fmt.Errorf("the broker key is not a usable seal key (X-Wing, or MLKEM768-P256 in FIPS mode): %w", err)
	}
	_, _ = fmt.Fprintf(a.stderr, "Sealing version %d for connection %s to broker key %s of gateway %s.\n", k.GetVersion(), k.GetConnectionId(), fp, k.GetGatewayId())
	var key []byte
	if *from == "-" {
		key, _, err = credentialFrom(a.stdin)
	} else {
		key, _, err = readCredential(*from)
	}
	if err != nil {
		return err
	}
	secret, err := gitHubApp(k, *gh, *installation, *account, key)
	if err != nil {
		return err
	}
	b := domain.Binding{
		Org: k.GetOrgId(), Connection: k.GetConnectionId(), Version: k.GetVersion(), AllowedHosts: k.GetAllowedHosts(),
		BrokerKey: k.GetBrokerKeyId(), Header: k.GetHeader(), Scheme: k.GetScheme(), Kind: domain.KindGitHubApp,
	}
	sealed, err := pccrypto.Seal(pub, b.Info(), domain.AAD, secret)
	clear(secret)
	if err != nil {
		return err
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	res, err := pantherclawv1connect.NewCredentialRotationServiceClient(s.connect()).SealRotationCandidate(ctx, &pb.SealRotationCandidateRequest{
		RotationId: rotation,
		Credential: &pb.PutCredentialRequest{
			ConnectionId: k.GetConnectionId(), Version: k.GetVersion(), BrokerKeyId: k.GetBrokerKeyId(), Sealed: sealed,
			AllowedHosts: k.GetAllowedHosts(), Header: k.GetHeader(), Scheme: k.GetScheme(), Kind: domain.KindGitHubApp,
			Github: &pb.GitHubInstallation{AppClientId: *gh, InstallationId: *installation, AccountLogin: *account},
		},
	})
	if err != nil {
		return err
	}
	return a.print(res)
}
