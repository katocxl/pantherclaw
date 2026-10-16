// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
)

// Credential commands (G0 M6 design decision 8, HR-060, HR-182). pclaw seal
// encrypts a target credential on this machine to the broker key of the
// connection's gateway and uploads only the sealed bytes: the plaintext
// never leaves the machine, never reaches PantherClaw's server and is never
// printed.

// maxCredential bounds a credential file.
const maxCredential = 64 << 10

func init() {
	commands["seal"] = command{
		usage: "seal --connection ID --from-file FILE [--fingerprint sha256:HEX] [--github-app ID --installation N --account LOGIN]",
		run:   seal,
	}
	commands["credential list"] = rpc("credential list CONNECTION", 1, func(*flag.FlagSet) call {
		return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
			return c.connections.ListCredentials(ctx, &pb.ListCredentialsRequest{ConnectionId: a[0]})
		}
	})
	commands["credential revoke"] = rpc("credential revoke CONNECTION VERSION", 2, func(*flag.FlagSet) call {
		return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
			var v int32
			if _, err := fmt.Sscanf(a[1], "%d", &v); err != nil || v <= 0 {
				return nil, errors.New("VERSION is a positive number")
			}
			return c.connections.RevokeCredential(ctx, &pb.RevokeCredentialRequest{ConnectionId: a[0], Version: v})
		}
	})
}

// readCredential reads a credential file of at most 64 KiB and reports
// whether it holds a private key. Text (a token) loses one trailing line
// break, which editors add; binary input is never trimmed, since a DER key
// may end in 0x0a or 0x0d. A private key is looked for on the bytes as read
// and on the trimmed bytes, and a match on either counts (HR-204).
func readCredential(path string) (secret []byte, privateKey bool, err error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxCredential+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > maxCredential {
		return nil, false, fmt.Errorf("the credential file is larger than %d bytes", maxCredential)
	}
	trimmed := bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r"))
	privateKey = domain.HoldsPrivateKey(b) || domain.HoldsPrivateKey(trimmed)
	if !binary(b) {
		b = trimmed
	}
	if len(b) == 0 {
		return nil, false, errors.New("the credential file is empty")
	}
	return b, privateKey, nil
}

// binary reports whether b is not text: not UTF-8, or holding a control
// byte other than a tab or a line break.
func binary(b []byte) bool {
	if !utf8.Valid(b) {
		return true
	}
	for _, c := range b {
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return true
		}
	}
	return false
}

func seal(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	conn := fs.String("connection", "", "connection id")
	from := fs.String("from-file", "", "file holding the credential (never pass it on the command line)")
	expect := fs.String("fingerprint", "", "the broker key fingerprint the gateway's operator gave you; sealing stops if it differs")
	app := fs.String("github-app", "", "seal a GitHub App: its client id (Iv…) or numeric id; --from-file is then the App's private key (.pem)")
	installation := fs.Int64("installation", 0, "with --github-app: the installation id")
	account := fs.String("account", "", "with --github-app: the account the App is installed on, in lowercase")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *conn == "" || *from == "" || (*app == "") != (*installation == 0 && *account == "") {
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
		return fmt.Errorf("the broker key is not an X-Wing key: %w", err)
	}
	_, _ = fmt.Fprintf(a.stderr, "Sealing version %d for connection %s to broker key %s of gateway %s.\n"+
		"It will be sent only to %s, in the %s header%s.\n",
		k.GetVersion(), k.GetConnectionId(), fp, k.GetGatewayId(), strings.Join(k.GetAllowedHosts(), ", "), k.GetHeader(),
		map[bool]string{true: " with scheme " + k.GetScheme(), false: ""}[k.GetScheme() != ""])
	secret, privateKey, err := readCredential(*from)
	if err != nil {
		return err
	}
	if *app == "" && privateKey {
		// A static credential goes to the target in a header: a private key
		// must never be one.
		clear(secret)
		return errors.New("the file holds a private key, which is never sent to a target; " +
			"seal a GitHub App's key with --github-app, --installation and --account; nothing was sealed")
	}
	kind := domain.KindStatic
	if *app != "" {
		if secret, err = gitHubApp(k, *app, *installation, *account, secret); err != nil {
			return err
		}
		kind = domain.KindGitHubApp
	}
	b := domain.Binding{
		Org: k.GetOrgId(), Connection: k.GetConnectionId(), Version: k.GetVersion(), AllowedHosts: k.GetAllowedHosts(),
		BrokerKey: k.GetBrokerKeyId(), Header: k.GetHeader(), Scheme: k.GetScheme(), Kind: kind,
	}
	sealed, err := pccrypto.Seal(pub, b.Info(), domain.AAD, secret)
	clear(secret)
	if err != nil {
		return err
	}
	req := &pb.PutCredentialRequest{
		ConnectionId: k.GetConnectionId(), Version: k.GetVersion(), BrokerKeyId: k.GetBrokerKeyId(), Sealed: sealed,
		AllowedHosts: k.GetAllowedHosts(), Header: k.GetHeader(), Scheme: k.GetScheme(), Kind: kind,
	}
	if kind == domain.KindGitHubApp {
		// The installation is configuration, recorded beside the sealed key
		// so that another account's repository is refused (ADR-0021).
		req.Github = &pb.GitHubInstallation{AppClientId: *app, InstallationId: *installation, AccountLogin: *account}
	}
	res, err := c.connections.PutCredential(ctx, req)
	if err != nil {
		return err
	}
	return a.print(res)
}

// gitHubApp turns the App's private key into the content of a GitHub App
// credential (G0 M8 decision 3) and clears the key. The gateway places the
// tokens it mints as Authorization: Bearer, so the connection must already
// use that header and scheme.
func gitHubApp(k *pb.GetSealingKeyResponse, app string, installation int64, account string, key []byte) ([]byte, error) {
	defer clear(key)
	if k.GetHeader() != domain.GitHubAppHeader || k.GetScheme() != domain.GitHubAppScheme {
		return nil, errors.New("a GitHub App's tokens go in Authorization: Bearer; set the connection's credential header and scheme to that first")
	}
	plain, err := domain.GitHubApp{V: 1, Issuer: app, Installation: installation, Account: account, PrivateKey: key}.Encode()
	if err != nil {
		return nil, errors.New("--github-app needs the App's client id or id, --installation, a lowercase --account, " +
			"and the App's RSA private key (at least 2048 bits, PEM) in --from-file")
	}
	return plain, nil
}
