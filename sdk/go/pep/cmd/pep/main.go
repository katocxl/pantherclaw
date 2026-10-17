// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Command pep runs PantherClaw's reference AuthZEN enforcement point in
// front of one target: every request is asked about with the agent's own
// PAP/1 credentials and forwarded only when PantherClaw allows it. It
// prints "pep: listening on ADDRESS" once it accepts connections.
package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/sdk/go/pep"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pep:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("pep", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8480", "address to listen on")
	upstream := fs.String("upstream", "", "the target allowed requests go to")
	server := fs.String("server", "", "PantherClaw's public URL (the decision endpoint is its /access/v1/evaluation)")
	connection := fs.String("connection", "", "the name of the connection this enforcement point fronts")
	publicURL := fs.String("public-url", "", "the connection's base URL, where agents send requests (default http://LISTEN)")
	protocol := fs.String("protocol", "http", "http, or mcp for a JSON-RPC MCP server")
	clientID := fs.String("client-id", "", "the enforcement point's service account client id")
	keyFile := fs.String("key", "", "the service account's private key, PKCS#8 PEM (Ed25519 or P-256)")
	credHeader := fs.String("credential-header", "", "request header carrying the agent's own target credential, forwarded as Authorization")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *upstream == "" || *server == "" || *connection == "" || *clientID == "" || *keyFile == "" {
		return errors.New("-upstream, -server, -connection, -client-id and -key are required")
	}
	key, err := readKey(*keyFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *listen)
	if err != nil {
		return err
	}
	if *publicURL == "" {
		*publicURL = "http://" + ln.Addr().String()
	}
	h, err := pep.New(pep.Config{
		Server: *server, Connection: *connection, Protocol: *protocol, PublicURL: *publicURL, Upstream: *upstream,
		CredentialHeader: *credHeader,
		Tokens:           &pep.ClientCredentials{TokenURL: strings.TrimSuffix(*server, "/") + "/oauth2/token", ClientID: *clientID, Key: key},
	})
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	_, _ = fmt.Fprintf(os.Stdout, "pep: listening on %s\n", ln.Addr())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// readKey reads a PKCS#8 PEM private key.
func readKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the operator chooses the path
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("the key file must hold a PKCS#8 PEM PRIVATE KEY")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("the key cannot sign")
	}
	return s, nil
}
