// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command selfcheck runs inside a test container and prints, one per line,
// what the container lets it do: its uid, whether the root file system and
// /tmp are writable, whether /tmp executes, and whether each address given
// as an argument (host:port) connects. With --listen ADDR it instead
// accepts connections on ADDR until it is stopped: a peer to reach.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--listen" {
		listen(os.Args[2])
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--exit" {
		return
	}
	w := os.Stdout
	fmt.Fprintf(w, "uid %d\n", os.Getuid())
	fmt.Fprintf(w, "root-write %s\n", result(os.WriteFile("/selfcheck", []byte("x"), 0o600)))
	fmt.Fprintf(w, "tmp-write %s\n", result(os.WriteFile("/tmp/selfcheck", []byte("x"), 0o600)))
	fmt.Fprintf(w, "tmp-exec %s\n", result(tmpExec()))
	for _, addr := range os.Args[1:] {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			_ = c.Close()
		}
		fmt.Fprintf(w, "dial %s %s\n", addr, result(err))
	}
}

func result(err error) string {
	if err != nil {
		return "denied"
	}
	return "allowed"
}

// tmpExec copies this binary to /tmp and runs the copy, which exits at
// once.
func tmpExec() error {
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer self.Close()
	f, err := os.OpenFile("/tmp/selfcheck-exec", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, self); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return exec.Command("/tmp/selfcheck-exec", "--exit").Run()
}

// listen accepts and closes connections on addr until it is stopped.
func listen(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}
}
