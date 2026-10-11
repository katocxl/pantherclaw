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
