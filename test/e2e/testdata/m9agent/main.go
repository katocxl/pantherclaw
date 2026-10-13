// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command m9agent is the agent of the M9 exit tests, run by `pclaw sandbox
// run`: it does what a coding agent with a shell might, with nothing but
// the sandbox's proxy, and prints one line per attempt.
//
//	m9agent merge OWNER/REPO NUMBER SHA [N]   N raw PUTs (default 1) to the pull request's merge endpoint, as curl would
//	m9agent push OWNER/REPO               the PAT found in /workspace/.env: a git push over HTTPS, the API with it, and SSH
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// client takes the sandbox's proxy and CA from the environment, as curl
// and git do.
var client = &http.Client{Timeout: 30 * time.Second}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: m9agent merge|push OWNER/REPO ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "merge":
		// An optional count asks again, a second apart (each a new action).
		times := 1
		if len(os.Args) > 5 {
			times, _ = strconv.Atoi(os.Args[5])
		}
		for i := range max(times, 1) {
			if i > 0 {
				time.Sleep(time.Second)
			}
			merge(os.Args[2], os.Args[3], os.Args[4])
		}
	case "push":
		push(os.Args[2])
	}
}

func merge(repo, number, sha string) {
	req, _ := http.NewRequest(http.MethodPut, "https://api.github.com/repos/"+repo+"/pulls/"+number+"/merge", //nolint:noctx // a one-shot agent
		strings.NewReader(`{"sha":"`+sha+`","merge_method":"squash"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	fmt.Println("merge", answer(client.Do(req)))
}

func push(repo string) {
	pat := found()
	if pat == "" {
		fmt.Println("no PAT found")
		return
	}
	// git push over HTTPS with the PAT: github.com is no mapped host.
	req, _ := http.NewRequest(http.MethodGet, "https://github.com/"+repo+".git/info/refs?service=git-receive-pack", nil) //nolint:noctx // a one-shot agent
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+pat)))
	fmt.Println("https-push", answer(client.Do(req)))
	// The same PAT on the API: the edge strips it and reports it.
	req, _ = http.NewRequest(http.MethodGet, "https://api.github.com/repos/"+repo, nil) //nolint:noctx // a one-shot agent
	req.Header.Set("Authorization", "token "+pat)
	fmt.Println("api-with-pat", answer(client.Do(req)))
	// git push over SSH: by name and by GitHub's address.
	for _, addr := range []string{"github.com:22", "140.82.112.3:22"} {
		if c, err := net.DialTimeout("tcp", addr, 5*time.Second); err == nil {
			_ = c.Close()
			fmt.Println("ssh", addr, "reached")
		} else {
			fmt.Println("ssh", addr, "blocked")
		}
	}
}

// found reads the GITHUB_TOKEN a developer left in the workspace's .env.
func found() string {
	f, err := os.Open("/workspace/.env")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "GITHUB_TOKEN="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func answer(res *http.Response, err error) string {
	if err != nil {
		return "error " + strings.ReplaceAll(err.Error(), "\n", " ")
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
	return fmt.Sprintf("%d %s", res.StatusCode, strings.ReplaceAll(string(b), "\n", " "))
}
