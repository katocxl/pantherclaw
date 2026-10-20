// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Command pep runs PantherClaw's reference AuthZEN enforcement point in
// front of one target: every request is asked about with the agent's own
// PAP/1 credentials and forwarded only when PantherClaw allows it. It
// prints "pep: listening on ADDRESS" once it accepts connections, logs to
// stderr, and stops on SIGINT or SIGTERM.
package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/katocxl/pantherclaw/sdk/go/pep"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "pep:", err)
		os.Exit(1)
	}
}

// headers is a repeatable flag.
type headers []string

func (h *headers) String() string { return strings.Join(*h, ",") }

func (h *headers) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func run(args []string) error {
	fs := flag.NewFlagSet("pep", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8480", "address to listen on")
	upstream := fs.String("upstream", "", "the target allowed requests go to")
	server := fs.String("server", "", "PantherClaw's public URL (the decision endpoint is its /access/v1/evaluation)")
	connection := fs.String("connection", "", "the name of the connection this enforcement point fronts")
	publicURL := fs.String("public-url", "", "the connection's base URL, where agents send requests (default http://LISTEN on a loopback address)")
	protocol := fs.String("protocol", "http", "http, or mcp for a JSON-RPC MCP server")
	clientID := fs.String("client-id", "", "the enforcement point's service account client id")
	keyFile := fs.String("key", "", "the service account's private key, PKCS#8 PEM (Ed25519 or P-256), readable only by its owner")
	credHeader := fs.String("credential-header", "", "request header carrying the agent's own target credential, forwarded as Authorization")
	insecure := fs.Bool("insecure", false, "accept an http -server that is not a loopback address")
	var forward headers
	fs.Var(&forward, "forward-header", "a request header to forward besides Content-Type (repeatable; default Accept, Accept-Language, User-Agent, X-Request-ID)")
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *listen)
	if err != nil {
		return err
	}
	if *publicURL == "" {
		host, _, _ := net.SplitHostPort(ln.Addr().String())
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			_ = ln.Close()
			return errors.New("-public-url is required unless -listen is a loopback address: agents sign the URL they call")
		}
		*publicURL = "http://" + ln.Addr().String()
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	h, err := pep.New(pep.Config{
		Server: *server, Connection: *connection, Protocol: *protocol, PublicURL: *publicURL, Upstream: *upstream,
		CredentialHeader: *credHeader, ForwardHeaders: forward, AllowInsecure: *insecure, Log: log,
		Tokens: &pep.ClientCredentials{TokenURL: strings.TrimSuffix(*server, "/") + "/oauth2/token", ClientID: *clientID, Key: key},
	})
	if err != nil {
		_ = ln.Close()
		return err
	}
	srv := &http.Server{
		Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 32 << 10, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
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

// readKey reads a PKCS#8 PEM private key; outside Windows the file must
// not be readable by others, as ssh requires.
func readKey(path string) (crypto.Signer, error) {
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s is open to other users (mode %v); run chmod 600 on it", path, info.Mode().Perm())
		}
	}
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
