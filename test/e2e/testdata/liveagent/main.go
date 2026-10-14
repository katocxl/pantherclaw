// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command liveagent is the agent of the live GitHub run (task
// test:github-live), run by `pclaw sandbox run`: it does what a coding agent
// with a shell might against a real sandbox repository, with nothing but the
// sandbox's proxy, and prints one line per attempt.
//
//	liveagent setup OWNER/REPO NONCE BASE BASESHA   read, branch, write and open a pull request
//	liveagent attack OWNER/REPO NUMBER SHA          a raw merge, then a push with the planted PAT and SSH key
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var client = &http.Client{Timeout: 60 * time.Second}

func main() {
	if len(os.Args) < 5 {
		fmt.Println("usage: liveagent setup|attack OWNER/REPO ...")
		os.Exit(2)
	}
	repo := os.Args[2]
	api := "https://api.github.com/repos/" + repo
	if os.Args[1] == "attack" {
		attack(repo, api, os.Args[3], os.Args[4])
		return
	}
	if len(os.Args) != 6 {
		os.Exit(2)
	}
	nonce, base, baseSHA := os.Args[3], os.Args[4], os.Args[5]
	branch := "pv-" + nonce

	// 0. Setup, through the edge: read, branch, write, open a pull request.
	code, _ := call(http.MethodGet, api+"/contents/README.md?ref="+base, "")
	fmt.Println("read", code)
	code, _ = call(http.MethodPost, api+"/git/refs", `{"ref":"refs/heads/`+branch+`","sha":"`+baseSHA+`"}`)
	fmt.Println("branch", code)
	content := base64.StdEncoding.EncodeToString([]byte("written by task test:github-live " + nonce + "\n"))
	code, _ = call(http.MethodPut, api+"/contents/"+branch+".txt", `{"message":"PantherClaw live run `+nonce+`","content":"`+content+`","branch":"`+branch+`"}`)
	fmt.Println("write", code)
	code, body := call(http.MethodPost, api+"/pulls", `{"title":"`+branch+`","head":"`+branch+`","base":"`+base+`"}`)
	var pr struct {
		Number int `json:"number"`
		Head   struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	_ = json.Unmarshal([]byte(body), &pr)
	fmt.Println("pr", code, pr.Number, pr.Head.SHA)
}

func attack(repo, api, number, sha string) {
	// 2. A raw merge, as curl would send it.
	code, body := call(http.MethodPut, api+"/pulls/"+number+"/merge", `{"sha":"`+sha+`","merge_method":"squash"}`)
	fmt.Println("merge", code, strings.ReplaceAll(body, "\n", " "))

	// 3. A push with the credentials found in the workspace.
	_ = os.WriteFile("/workspace/fix.txt", []byte("the fix\n"), 0o644) //nolint:gosec // the agent's own workspace file
	pat := found("/workspace/.env", "GITHUB_TOKEN=")
	req, _ := http.NewRequest(http.MethodGet, "https://github.com/"+repo+".git/info/refs?service=git-receive-pack", nil) //nolint:noctx // a one-shot agent
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+pat)))
	fmt.Println("https-push", answer(client.Do(req)))
	key, _ := os.ReadFile("/workspace/.ssh/id_ed25519")
	fmt.Println("ssh-key", len(key) > 0)
	for _, addr := range []string{"github.com:22", "140.82.112.3:22"} {
		if c, err := net.DialTimeout("tcp", addr, 5*time.Second); err == nil {
			_ = c.Close()
			fmt.Println("ssh", addr, "reached")
		} else {
			fmt.Println("ssh", addr, "blocked")
		}
	}
}

func call(method, url, body string) (int, string) {
	req, _ := http.NewRequest(method, url, strings.NewReader(body)) //nolint:noctx // a one-shot agent
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, string(b)
}

// found reads the value a developer left in a workspace file.
func found(path, prefix string) string {
	f, err := os.Open(path)
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
