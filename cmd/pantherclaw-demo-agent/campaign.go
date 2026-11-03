// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// script is what `pclaw redteam campaign run --scripted` writes into the
// workspace (internal/redteam/campaign.Script).
type script struct {
	Campaign  string `json:"campaign"`
	ModelHost string `json:"model_host"`
	Steps     []struct {
		Attempt string            `json:"attempt"`
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Body    string            `json:"body"`
		Headers map[string]string `json:"headers"`
	} `json:"steps"`
}

// campaign is the scripted stand-in of an attack campaign (G0 M25 D310): it
// asks the model host once, as an agent would, with the placeholder key it
// was given, and then makes each attempt of the script, printing one line per
// call. It never decides anything: the script is the attack.
func campaign(path string) int {
	raw, err := os.ReadFile(path) //nolint:gosec // the agent's own workspace
	if err != nil {
		say("no campaign script:", err)
		return 2
	}
	var s script
	if err := json.Unmarshal(raw, &s); err != nil {
		say("bad campaign script:", err)
		return 2
	}
	say("campaign", s.Campaign)
	if s.ModelHost != "" {
		task, _ := json.Marshal(os.Getenv("PC_CAMPAIGN_TASK"))
		body := `{"model":"stand-in","max_tokens":64,"messages":[{"role":"user","content":` + string(task) + `}]}`
		req, _ := http.NewRequest(http.MethodPost, "https://"+s.ModelHost+"/v1/messages", strings.NewReader(body)) //nolint:noctx // a one-shot agent: the run's model host, through the sandbox proxy
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Anthropic-Version", "2023-06-01")
		req.Header.Set("X-Api-Key", os.Getenv("ANTHROPIC_API_KEY"))
		say("model", do(req))
	}
	for _, st := range s.Steps {
		req, err := http.NewRequest(st.Method, st.URL, strings.NewReader(st.Body)) //nolint:noctx // a one-shot agent: the script's attempt, through the sandbox proxy
		if err != nil {
			say(st.Attempt, "error", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/vnd.github+json")
		for k, v := range st.Headers {
			req.Header.Set(k, v)
		}
		say(fmt.Sprintf("attempt %s", st.Attempt), do(req))
	}
	return 0
}
