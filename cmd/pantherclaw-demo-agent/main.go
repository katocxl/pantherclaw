// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pantherclaw-demo-agent is the demo agent of the v0.1.0 preview,
// run by `pclaw sandbox run` (the quickstart's guided tests and `task
// test:preview`): it does what a coding agent with a shell might, with
// nothing but the sandbox's proxy, and prints one line per attempt. It is a
// test and demo tool, not part of the release.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const usage = `pantherclaw-demo-agent: the demo agent of the PantherClaw preview.

Run it inside a sandbox: pclaw sandbox run ... -- pantherclaw-demo-agent COMMAND ARGS

Commands:
  allowed [--branch NAME] [--file NAME] OWNER/REPO MAIN_SHA
                                   allowed: read a file, create a branch, write a file, open a pull request
  held OWNER/REPO NUMBER SHA       held: a raw merge of the pull request, as curl would send it
  blocked OWNER/REPO               blocked: a push with the PAT found in /workspace/.env over HTTPS, and over SSH
                                   (the key in /workspace/.ssh/id_ed25519, to github.com and GitHub's address)
  attack OWNER/REPO NUMBER SHA     held, then blocked, in one run

Without --branch and --file, allowed names its branch and file with a random suffix, so that it can run again on the same repository; it prints the names it chose.
  help, -h, --help                 this text

One line per attempt: "name STATUS body" for HTTP, "ssh ADDRESS reached|blocked" for SSH.
`

// client takes the sandbox's proxy and CA from the environment, as curl
// and git do.
var client = &http.Client{Timeout: 30 * time.Second}

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		if len(args) == 0 {
			os.Exit(2)
		}
		return
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	suffix := rand.Text()[:8]
	branch := fs.String("branch", "demo/fix-"+suffix, "")
	file := fs.String("file", "fix-"+suffix+".txt", "")
	if cmd == "allowed" {
		if err := fs.Parse(args); err != nil {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		args = fs.Args()
	}
	need := map[string]int{"allowed": 2, "held": 3, "blocked": 1, "attack": 3}[cmd]
	if need == 0 || len(args) < need {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	repo := args[0]
	switch cmd {
	case "allowed":
		setup(repo, args[1], *branch, *file)
	case "held":
		merge(repo, args[1], args[2])
	case "blocked":
		push(repo)
	case "attack":
		merge(repo, args[1], args[2])
		push(repo)
	}
}

func call(method, url, body string) string {
	req, _ := http.NewRequest(method, url, strings.NewReader(body)) //nolint:noctx // a one-shot agent
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	return answer(client.Do(req))
}

func setup(repo, main, branch, file string) {
	api := "https://api.github.com/repos/" + repo
	fmt.Println("branch name", branch, "file name", file)
	fmt.Println("read", call(http.MethodGet, api+"/contents/README.md", ""))
	fmt.Println("branch", call(http.MethodPost, api+"/git/refs", `{"ref":"refs/heads/`+branch+`","sha":"`+main+`"}`))
	content := base64.StdEncoding.EncodeToString([]byte("the fix\n"))
	fmt.Println("write", call(http.MethodPut, api+"/contents/"+file, `{"message":"Fix the parser","content":"`+content+`","branch":"`+branch+`"}`))
	fmt.Println("pr", call(http.MethodPost, api+"/pulls", `{"title":"Fix the parser","head":"`+branch+`","base":"main"}`))
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
