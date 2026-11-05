// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package parse

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
)

// The cloud agent runtimes (G0 M34 D997): the agents deployed in Amazon
// Bedrock AgentCore (ListAgentRuntimes), Vertex AI Agent Engine
// (reasoningEngines.list) and Azure AI Foundry (the project's agents). Each
// record keeps its id, name, times and status only. Never decoded: an
// agent's container or code, its role, environment, instructions, tools or
// description (HR-635). Foundry's shape is unconfirmed until the live
// checks (R-85); a shape that does not match is reported as not scanned.

// AgentCoreRuntime is the part of an AgentCore runtime discovery keeps.
type AgentCoreRuntime struct {
	ID        string         `json:"agentRuntimeId"`
	Name      string         `json:"agentRuntimeName"`
	Status    string         `json:"status"`
	CreatedAt jsontext.Value `json:"createdAt"`
	UpdatedAt jsontext.Value `json:"lastUpdatedAt"`
}

type agentCoreList struct {
	Runtimes  *[]AgentCoreRuntime `json:"agentRuntimes"`
	NextToken string              `json:"nextToken"`
}

// AgentCorePage decodes one ListAgentRuntimes page and its next token.
func AgentCorePage(raw []byte) ([]AgentCoreRuntime, string, error) {
	var p agentCoreList
	if json.Unmarshal(raw, &p) != nil || p.Runtimes == nil {
		return nil, "", ErrShape
	}
	return *p.Runtimes, p.NextToken, nil
}

// AgentCoreFindings adds a finding to r, whose tenant is the account, for
// each runtime in region.
func AgentCoreFindings(r *domain.Report, region string, runtimes []AgentCoreRuntime) {
	refused := 0
	for i, rt := range runtimes {
		if i == MaxRecords {
			r.Note(domain.ReadRuntimes, "only the first "+strconv.Itoa(MaxRecords)+" runtimes were kept")
			break
		}
		if !idRe.MatchString(rt.ID) {
			refused++
			continue
		}
		attrs := map[string]string{"tenant": r.Tenant, "agent_id": rt.ID}
		put(attrs, "name", rt.Name)
		put(attrs, "region", region)
		put(attrs, "status", word(rt.Status))
		put(attrs, "created_at", when(rt.CreatedAt))
		put(attrs, "updated_at", when(rt.UpdatedAt))
		r.Findings = append(r.Findings, domain.Finding{
			Kind: domain.KindAgentCoreRuntime, Key: domain.Key(domain.SourceAWSAgentCore, r.Tenant, rt.ID), Attributes: attrs,
		})
	}
	finish(r, refused, "runtimes")
}

// VertexEngine is the part of a reasoning engine discovery keeps.
type VertexEngine struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	CreateTime  string `json:"createTime"`
	UpdateTime  string `json:"updateTime"`
	State       string `json:"state"`
}

type vertexList struct {
	Engines   *[]VertexEngine `json:"reasoningEngines"`
	NextToken string          `json:"nextPageToken"`
}

// VertexPage decodes one reasoningEngines.list page and its next token. A
// project with no engines answers {}, which is an empty page.
func VertexPage(raw []byte) ([]VertexEngine, string, error) {
	var p vertexList
	if json.Unmarshal(raw, &p) != nil {
		return nil, "", ErrShape
	}
	if p.Engines == nil {
		return nil, p.NextToken, nil
	}
	return *p.Engines, p.NextToken, nil
}

// VertexFindings adds a finding to r, whose tenant is <project>/<location>,
// for each engine of that project and location. One named elsewhere is
// refused.
func VertexFindings(r *domain.Report, engines []VertexEngine) {
	project, location, _ := domain.VertexTenant(r.Tenant)
	prefix := "projects/" + project + "/locations/" + location + "/reasoningEngines/"
	refused := 0
	for i, e := range engines {
		if i == MaxRecords {
			r.Note(domain.ReadReasoningEngines, "only the first "+strconv.Itoa(MaxRecords)+" reasoning engines were kept")
			break
		}
		id, ok := strings.CutPrefix(e.Name, prefix)
		if !ok || project == "" || !idRe.MatchString(id) {
			refused++
			continue
		}
		attrs := map[string]string{"tenant": r.Tenant, "agent_id": id}
		put(attrs, "name", e.DisplayName)
		put(attrs, "location", location)
		put(attrs, "status", word(e.State))
		put(attrs, "created_at", e.CreateTime)
		put(attrs, "updated_at", e.UpdateTime)
		r.Findings = append(r.Findings, domain.Finding{
			Kind: domain.KindVertexReasoningEngine, Key: domain.Key(domain.SourceVertexAgentEngine, r.Tenant, id), Attributes: attrs,
		})
	}
	finish(r, refused, "reasoning engines")
}

// FoundryAgent is the part of a Foundry agent discovery keeps.
type FoundryAgent struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	CreatedAt jsontext.Value `json:"created_at"`
	UpdatedAt jsontext.Value `json:"updated_at"`
	Status    string         `json:"status"`
}

type foundryList struct {
	Data    *[]FoundryAgent `json:"data"`
	HasMore bool            `json:"has_more"`
	LastID  string          `json:"last_id"`
}

// FoundryPage decodes one page of a project's agents, cursor-paged, with
// the cursor of the next page ("" for the last).
func FoundryPage(raw []byte) ([]FoundryAgent, string, error) {
	var p foundryList
	if json.Unmarshal(raw, &p) != nil || p.Data == nil {
		return nil, "", ErrShape
	}
	if !p.HasMore {
		return *p.Data, "", nil
	}
	if p.LastID == "" {
		return nil, "", ErrShape
	}
	return *p.Data, p.LastID, nil
}

// FoundryFindings adds a finding to r, whose tenant is the project, for each
// agent.
func FoundryFindings(r *domain.Report, agents []FoundryAgent) {
	refused := 0
	for i, a := range agents {
		if i == MaxRecords {
			r.Note(domain.ReadAgents, "only the first "+strconv.Itoa(MaxRecords)+" agents were kept")
			break
		}
		if !idRe.MatchString(a.ID) {
			refused++
			continue
		}
		attrs := map[string]string{"tenant": r.Tenant, "agent_id": a.ID}
		put(attrs, "name", a.Name)
		put(attrs, "status", word(a.Status))
		put(attrs, "created_at", when(a.CreatedAt))
		put(attrs, "updated_at", when(a.UpdatedAt))
		r.Findings = append(r.Findings, domain.Finding{
			Kind: domain.KindFoundryAgent, Key: domain.Key(domain.SourceAzureFoundry, r.Tenant, a.ID), Attributes: attrs,
		})
	}
	finish(r, refused, "agents")
}

// finish counts the findings and notes the records refused.
func finish(r *domain.Report, refused int, what string) {
	r.Counts[domain.CountAgents] = int64(len(r.Findings))
	if refused > 0 {
		r.Note(domain.NoteRecords, strconv.Itoa(refused)+" "+what+" with no usable id were not read")
	}
}

// when is a vendor time: epoch seconds as a number become RFC 3339; a string
// stays as it is.
func when(v jsontext.Value) string {
	s := strings.TrimSpace(string(v))
	if s == "" || s == "null" {
		return ""
	}
	if strings.HasPrefix(s, `"`) {
		return strings.Trim(s, `"`)
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 || f > 1e11 {
		return ""
	}
	return time.Unix(int64(f), 0).UTC().Format(time.RFC3339)
}

// Recordings of the runtimes: what an admin exported with the vendor's own
// tools, the first list page as the vendor answers it beside the tenant.
type (
	agentCoreDoc struct {
		Account string         `json:"account_id"`
		Region  string         `json:"region"`
		List    *agentCoreList `json:"runtimes"`
	}
	vertexDoc struct {
		Project  string      `json:"project"`
		Location string      `json:"location"`
		List     *vertexList `json:"reasoning_engines"`
	}
	foundryDoc struct {
		Project string       `json:"project"`
		List    *foundryList `json:"agents"`
	}
)

// runtimeRecording parses a recording of one of the runtimes.
func runtimeRecording(source string, raw []byte) (*domain.Report, error) {
	var tenant string
	var more bool
	var add func(*domain.Report)
	switch source {
	case domain.SourceAWSAgentCore:
		var d agentCoreDoc
		if json.Unmarshal(raw, &d) != nil || d.List == nil || d.List.Runtimes == nil {
			return nil, ErrShape
		}
		tenant, more = d.Account, d.List.NextToken != ""
		add = func(r *domain.Report) { AgentCoreFindings(r, d.Region, *d.List.Runtimes) }
	case domain.SourceVertexAgentEngine:
		var d vertexDoc
		if json.Unmarshal(raw, &d) != nil || d.List == nil {
			return nil, ErrShape
		}
		tenant, more = d.Project+"/"+d.Location, d.List.NextToken != ""
		var engines []VertexEngine
		if d.List.Engines != nil {
			engines = *d.List.Engines
		}
		add = func(r *domain.Report) { VertexFindings(r, engines) }
	case domain.SourceAzureFoundry:
		var d foundryDoc
		if json.Unmarshal(raw, &d) != nil || d.List == nil || d.List.Data == nil {
			return nil, ErrShape
		}
		tenant, more = d.Project, d.List.HasMore
		add = func(r *domain.Report) { FoundryFindings(r, *d.List.Data) }
	default:
		return nil, ErrSource
	}
	if !domain.SourceTenantOK(source, tenant) {
		return nil, ErrTenant
	}
	r := domain.NewReport(source, tenant)
	read := domain.Reads(source)[0]
	if more {
		r.Note(read, "the recording stops with more pages to read")
	} else {
		r.Read(read)
	}
	add(r)
	return r, nil
}
