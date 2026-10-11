// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command agent is a test agent for the sandbox: it reads its workspace and
// writes an answer back, calls a mapped host through the proxy it was
// given, tries a direct connection, and prints what happened.
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	// The repository came in cleaned: no hooks, no host config.
	if _, err := os.Stat("/workspace/.git/hooks"); err == nil {
		fmt.Println("git hooks came in")
	}
	if b, _ := os.ReadFile("/workspace/.git/config"); strings.Contains(string(b), "fsmonitor") || strings.Contains(string(b), "url") {
		fmt.Println("git config came in")
	}
	// A poisoned repository to bring back (it must not reach the host).
	_ = os.MkdirAll("/workspace/.git/hooks", 0o755)
	fmt.Println("plant", os.WriteFile("/workspace/.git/hooks/post-checkout", []byte("#!/bin/sh\necho pwned\n"), 0o755))
	if f, err := os.OpenFile("/workspace/.git/config", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644); err == nil {
		_, _ = fmt.Fprintln(f, "[core]\n\tfsmonitor = /tmp/pwned")
		_ = f.Close()
	}
	in, err := os.ReadFile("/workspace/in.txt")
	fmt.Println("read", strings.TrimSpace(string(in)), err)
	fmt.Println("write", os.WriteFile("/workspace/out.txt", append(in, []byte("answered\n")...), 0o644))
	fmt.Println("uid", os.Getuid())
	res, err := (&http.Client{Timeout: 10 * time.Second}).Get("https://" + os.Args[1] + "/agent/" + os.Args[2])
	if err == nil {
		_ = res.Body.Close()
		fmt.Println("proxied", res.StatusCode)
	} else {
		fmt.Println("proxied error", err)
	}
	if c, err := net.DialTimeout("tcp", "192.0.2.1:443", 2*time.Second); err == nil {
		_ = c.Close()
		fmt.Println("direct reached")
	} else {
		fmt.Println("direct blocked")
	}
	for _, e := range os.Environ() {
		if strings.Contains(strings.ToLower(e), "token") || strings.Contains(strings.ToLower(e), "key") {
			fmt.Println("credential env", strings.SplitN(e, "=", 2)[0])
		}
	}
}
