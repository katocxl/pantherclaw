// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package parse

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/url"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
)

// ChatGPT Enterprise lists a workspace's custom GPTs through OpenAI's
// Compliance API. Its reference is behind an enterprise sign-in, so these
// names could not be checked against it. OpenAI's public pages say only that
// the API covers GPT configuration and metadata. The field names below come
// from vendors' summaries and are recorded as uncertain in the fixture's
// header (testdata/chatgpt_enterprise.synthetic.json). A shape that does not
// match is reported as not scanned, never guessed at, and a real capture must
// confirm them (F801).
//
// Fields never read: instructions, description, conversation_starters, files
// and anything of a conversation.

// GPTRecord is the part of a GPT discovery keeps.
type GPTRecord struct {
	ID        string         `json:"id"`
	CreatedAt jsontext.Value `json:"created_at"`
	OwnerID   string         `json:"owner_id"`
	Sharing   *struct {
		Visibility string `json:"visibility"`
	} `json:"sharing"`
	// Name is at the top level, or on the latest configuration.
	Name   string `json:"name"`
	Latest *struct {
		Data []gptConfig `json:"data"`
	} `json:"latest_config"`
}

// gptConfig is the part of a GPT's configuration discovery keeps. Tools is
// raw because its shape is uncertain.
type gptConfig struct {
	Name  string         `json:"name"`
	Tools jsontext.Value `json:"tools"`
}

// gptTool is one tool: its kind, and for an action the host it calls.
type gptTool struct {
	Type   string `json:"type"`
	Domain string `json:"domain"`
}

// gptList is one page of the list, cursor-paged.
type gptList struct {
	Data    *[]GPTRecord `json:"data"`
	HasMore bool         `json:"has_more"`
	LastID  string       `json:"last_id"`
}

// chatGPTDoc is a recording: the workspace and its list.
type chatGPTDoc struct {
	Workspace string   `json:"workspace_id"`
	GPTs      *gptList `json:"gpts"`
}

// chatGPTRecording parses a recording of a workspace's GPT list.
func chatGPTRecording(raw []byte) (*domain.Report, error) {
	var d chatGPTDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, ErrShape
	}
	if d.GPTs == nil || d.GPTs.Data == nil {
		return nil, ErrShape
	}
	if !domain.TenantOK(d.Workspace) {
		return nil, ErrTenant
	}
	r := domain.NewReport(domain.SourceChatGPTEnterprise, d.Workspace)
	r.Read(domain.ReadGPTConfigs) // with the list; a record it could not read is marked on its own
	if d.GPTs.HasMore {
		r.Note(domain.ReadGPTs, "the recording stops with more pages to read")
	} else {
		r.Read(domain.ReadGPTs)
	}
	ChatGPTFindings(r, *d.GPTs.Data)
	return r, nil
}

// ChatGPTPage decodes one page of the list, with the cursor of the next page
// ("" for the last).
func ChatGPTPage(raw []byte) ([]GPTRecord, string, error) {
	var p gptList
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, "", ErrShape
	}
	if p.Data == nil {
		return nil, "", ErrShape
	}
	if !p.HasMore {
		return *p.Data, "", nil
	}
	if p.LastID == "" {
		return nil, "", ErrShape // more pages and no way to them
	}
	return *p.Data, p.LastID, nil
}

// ChatGPTFindings adds a finding to r for each GPT. One whose tools have a
// shape this parser does not know is kept, marked tools_incomplete and unread
// on its own (AttrUnread), so what was recorded of its tools stands and every
// other GPT's change is still recorded; the report counts it
// (CountRecordsUnread). One whose tool list was cut at the attribute's bound
// was read: it is marked tools_incomplete only.
func ChatGPTFindings(r *domain.Report, gpts []GPTRecord) {
	refused, unread := 0, 0
	for i, g := range gpts {
		if i == MaxRecords {
			r.Note(domain.ReadGPTs, "only the first "+strconv.Itoa(MaxRecords)+" GPTs were kept")
			break
		}
		if !idRe.MatchString(g.ID) {
			refused++
			continue
		}
		attrs := map[string]string{"tenant": r.Tenant, "agent_id": g.ID}
		name := g.Name
		var tools jsontext.Value
		if g.Latest != nil && len(g.Latest.Data) > 0 {
			if name == "" {
				name = g.Latest.Data[0].Name
			}
			tools = g.Latest.Data[0].Tools
		}
		put(attrs, "name", name)
		put(attrs, "owner_ref", g.OwnerID)
		put(attrs, "created_at", strings.Trim(string(g.CreatedAt), `"`))
		if g.Sharing != nil {
			put(attrs, "visibility", word(g.Sharing.Visibility))
		}
		switch read, whole := gptTools(attrs, tools); {
		case !read:
			unread++
			attrs["tools_incomplete"] = "true"
			attrs[domain.AttrUnread] = domain.ReadGPTConfigs
		case !whole:
			attrs["tools_incomplete"] = "true"
		}
		r.Findings = append(r.Findings, domain.Finding{
			Kind: domain.KindCustomGPT, Key: domain.Key(domain.SourceChatGPTEnterprise, r.Tenant, g.ID), Attributes: attrs,
		})
	}
	r.Counts[domain.CountAgents] = int64(len(r.Findings))
	if refused > 0 {
		r.Note(domain.NoteRecords, strconv.Itoa(refused)+" GPTs with no usable id were not read")
	}
	if unread > 0 {
		r.Counts[domain.CountRecordsUnread] = int64(unread)
	}
}

// word is a short vendor word: anything else reads "unknown", so a long or
// odd value never takes a vocabulary field's place.
func word(s string) string {
	if s == "" {
		return ""
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '_' && r != '-' {
			return "unknown"
		}
	}
	if len(s) > 32 {
		return "unknown"
	}
	return strings.ToLower(s)
}

// gptTools keeps a GPT's tool kinds and action hosts, and reports whether it
// read them, and whether whole (not cut at the attribute's bound). No tools at
// all is not read: a GPT's configuration was absent.
func gptTools(attrs map[string]string, raw jsontext.Value) (read, whole bool) {
	if len(raw) == 0 {
		return false, false
	}
	var list []gptTool
	if json.Unmarshal(raw, &list) != nil {
		var wrapped struct {
			Data *[]gptTool `json:"data"`
		}
		if json.Unmarshal(raw, &wrapped) != nil || wrapped.Data == nil {
			return false, false
		}
		list = *wrapped.Data
	}
	var kinds, hosts []string
	for _, t := range list {
		if w := word(t.Type); w != "" {
			kinds = append(kinds, w)
		}
		if h := hostOf(t.Domain); h != "" {
			hosts = append(hosts, h)
		}
	}
	k, overK := joined(kinds)
	h, overH := joined(hosts)
	put(attrs, "tool_kinds", k)
	put(attrs, "action_domains", h)
	return true, overK == 0 && overH == 0
}

// hostOf is the host of an action's domain or URL, and nothing of its path,
// query or credentials.
func hostOf(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
