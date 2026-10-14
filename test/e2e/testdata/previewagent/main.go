// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command previewagent is the agent of the preview test (three routes, three
// stops), run by `pclaw sandbox run`: it does what a coding agent with a
// shell might, with nothing but the sandbox's proxy, and prints one line per
// attempt.
//
//	previewagent setup OWNER/REPO MAIN_SHA          reads a file, creates a branch, writes a file, opens a pull request
//	previewagent attack OWNER/REPO NUMBER SHA       a raw merge as curl would send it, then a push with the PAT and with the SSH key found in /workspace
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// client takes the sandbox's proxy and CA from the environment, as curl
// and git do.
var client = &http.Client{Timeout: 30 * time.Second}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("usage: previewagent setup|attack OWNER/REPO ...")
		os.Exit(2)
	}
	repo := os.Args[2]
	switch os.Args[1] {
	case "setup":
		setup(repo, os.Args[3])
	case "attack":
		if len(os.Args) < 5 {
			os.Exit(2)
		}
		merge(repo, os.Args[3], os.Args[4])
		push(repo)
	}
}

func call(method, url, body string) string {
	req, _ := http.NewRequest(method, url, strings.NewReader(body)) //nolint:noctx // a one-shot agent
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	return answer(client.Do(req))
}

func setup(repo, main string) {
	api := "https://api.github.com/repos/" + repo
	fmt.Println("read", call(http.MethodGet, api+"/contents/README.md", ""))
	fmt.Println("branch", call(http.MethodPost, api+"/git/refs", `{"ref":"refs/heads/preview/fix","sha":"`+main+`"}`))
	content := base64.StdEncoding.EncodeToString([]byte("the fix\n"))
	fmt.Println("write", call(http.MethodPut, api+"/contents/fix.txt", `{"message":"Fix the parser","content":"`+content+`","branch":"preview/fix"}`))
	fmt.Println("pr", call(http.MethodPost, api+"/pulls", `{"title":"Fix the parser","head":"preview/fix","base":"main"}`))
}

func merge(repo, number, sha string) {
	fmt.Println("merge", call(http.MethodPut, "https://api.github.com/repos/"+repo+"/pulls/"+number+"/merge",
		`{"sha":"`+sha+`","merge_method":"squash"}`))
}

func push(repo string) {
	// git push over HTTPS with the PAT found in the workspace's .env:
	// github.com is no mapped host.
	pat := found("/workspace/.env", "GITHUB_TOKEN=")
	if pat == "" {
		fmt.Println("no PAT found")
		return
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+pat))
	for _, step := range []struct{ name, method, path string }{
		{"https-push-advertise", http.MethodGet, "/info/refs?service=git-receive-pack"},
		{"https-push", http.MethodPost, "/git-receive-pack"},
	} {
		req, _ := http.NewRequest(step.method, "https://github.com/"+repo+".git"+step.path, strings.NewReader("0000")) //nolint:noctx // a one-shot agent
		req.Header.Set("Authorization", auth)
		fmt.Println(step.name, answer(client.Do(req)))
	}
	// git push over SSH with the key found in the workspace: by name and by
	// GitHub's address. The key is read, as ssh would, before dialing.
	fmt.Println("ssh-key found", found("/workspace/.ssh/id_ed25519", "") != "")
	for _, addr := range []string{"github.com:22", "140.82.112.3:22"} {
		if c, err := net.DialTimeout("tcp", addr, 5*time.Second); err == nil {
			_ = c.Close()
			fmt.Println("ssh", addr, "reached")
		} else {
			fmt.Println("ssh", addr, "blocked")
		}
	}
}

// found returns the first line of path that starts with prefix, without it.
func found(path, prefix string) string {
	f, err := os.Open(path) //nolint:gosec // the agent's own workspace
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), prefix); ok {
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
