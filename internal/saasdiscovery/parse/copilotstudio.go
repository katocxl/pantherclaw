// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package parse

import (
	"encoding/json/v2"
	"regexp"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
)

// Copilot Studio keeps its agents in Dataverse: the tables bot and
// botcomponent, read through the Web API as OData collections. Names and
// choice values are Microsoft's published table reference
// (learn.microsoft.com/power-apps/developer/data-platform/reference/entities/bot
// and .../botcomponent, read 2026-11-01).
//
// Columns never read: on bot, configuration, authenticationconfiguration,
// applicationmanifestinformation, synchronizationstatus and iconbase64; on
// botcomponent, content, data, description, dependencies and filedata. The
// conversationtranscript table is never touched.

// BotSelect and ComponentSelect are the only columns a collector asks for.
const (
	BotSelect = "botid,name,schemaname,statecode,statuscode,authenticationmode,authenticationtrigger,accesscontrolpolicy," +
		"publishedon,createdon,modifiedon,_ownerid_value"
	ComponentSelect = "botcomponentid,name,componenttype,_parentbotid_value"
)

// BotRecord is the part of a bot row discovery keeps. Choice columns are
// pointers: 0 is a value, and a missing one is not it.
type BotRecord struct {
	ID           string `json:"botid"`
	Name         string `json:"name"`
	SchemaName   string `json:"schemaname"`
	State        *int   `json:"statecode"`
	Status       *int   `json:"statuscode"`
	AuthMode     *int   `json:"authenticationmode"`
	AuthTrigger  *int   `json:"authenticationtrigger"`
	AccessPolicy *int   `json:"accesscontrolpolicy"`
	PublishedOn  string `json:"publishedon"`
	CreatedOn    string `json:"createdon"`
	ModifiedOn   string `json:"modifiedon"`
	OwnerID      string `json:"_ownerid_value"`
}

// ComponentRecord is the part of a botcomponent row discovery keeps.
type ComponentRecord struct {
	ID     string `json:"botcomponentid"`
	Name   string `json:"name"`
	Type   *int   `json:"componenttype"`
	Parent string `json:"_parentbotid_value"`
}

// odata is one OData collection page.
type odata[T any] struct {
	Value *[]T   `json:"value"`
	Next  string `json:"@odata.nextLink"`
}

// copilotDoc is a recording: the organization and the two collections.
type copilotDoc struct {
	Environment string                  `json:"environment"`
	Bots        *odata[BotRecord]       `json:"bots"`
	Components  *odata[ComponentRecord] `json:"botcomponents"`
}

// Dataverse choice values (the table reference's option sets).
var (
	botStates   = map[int]string{0: "active", 1: "inactive"}
	botStatuses = map[int]string{1: "provisioned", 2: "deprovisioned", 3: "provisioning", 4: "provision_failed", 5: "missing_license"}
	authModes   = map[int]string{0: "unspecified", 1: "none", 2: "integrated", 3: "custom_entra_id", 4: "generic_oauth2"}
	authTrigger = map[int]string{0: "as_needed", 1: "always"}
	accessRules = map[int]string{0: "any", 1: "agent_readers", 2: "group_membership", 3: "any_multitenant"}
)

// Component types that say what an agent can reach (botcomponent_componenttype).
const (
	componentSkill     = 1
	componentSkillV2   = 13
	componentKnowledge = 16
)

var guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// choice is a choice value's fixed word: a number outside the published set
// reads "unknown", so vendor data never picks the text.
func choice(set map[int]string, v *int) string {
	if v == nil {
		return ""
	}
	if s, ok := set[*v]; ok {
		return s
	}
	return "unknown"
}

// copilotRecording parses a recording of the bot and botcomponent collections.
func copilotRecording(raw []byte) (*domain.Report, error) {
	var d copilotDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, ErrShape
	}
	if d.Bots == nil || d.Bots.Value == nil {
		return nil, ErrShape
	}
	if !domain.TenantOK(d.Environment) {
		return nil, ErrTenant
	}
	r := domain.NewReport(domain.SourceCopilotStudio, d.Environment)
	var comps []ComponentRecord
	if d.Components != nil && d.Components.Value != nil {
		comps = *d.Components.Value
		if d.Components.Next == "" {
			r.Read(domain.ReadBotComponents)
		} else {
			r.Note(domain.ReadBotComponents, "the recording stops at a next page")
		}
	}
	if d.Bots.Next == "" {
		r.Read(domain.ReadBots)
	} else {
		r.Note(domain.ReadBots, "the recording stops at a next page")
	}
	CopilotFindings(r, *d.Bots.Value, comps)
	return r, nil
}

// CopilotBots decodes one OData page of bots, with the next page's link.
func CopilotBots(raw []byte) ([]BotRecord, string, error) { return page[BotRecord](raw) }

// CopilotComponents decodes one OData page of components, with the next
// page's link.
func CopilotComponents(raw []byte) ([]ComponentRecord, string, error) {
	return page[ComponentRecord](raw)
}

func page[T any](raw []byte) ([]T, string, error) {
	var p odata[T]
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, "", ErrShape
	}
	if p.Value == nil {
		return nil, "", ErrShape
	}
	return *p.Value, p.Next, nil
}

// CopilotFindings adds a finding to r for each bot, with what comps say of it.
// A bot with no usable id is refused and noted; one over MaxRecords is noted.
func CopilotFindings(r *domain.Report, bots []BotRecord, comps []ComponentRecord) {
	skills, knowledge := map[string][]string{}, map[string]int{}
	// Only a full read of the components can say what an agent reaches: a
	// partial one would read as agents losing skills.
	_, partial := r.NotScanned[domain.ReadBotComponents]
	for _, c := range comps {
		if c.Type == nil {
			continue
		}
		switch *c.Type {
		case componentSkill, componentSkillV2:
			skills[c.Parent] = append(skills[c.Parent], c.Name)
		case componentKnowledge:
			knowledge[c.Parent]++
		}
	}
	refused := 0
	for i, b := range bots {
		if i == MaxRecords {
			r.Note(domain.ReadBots, "only the first "+strconv.Itoa(MaxRecords)+" agents were kept")
			break
		}
		if !guidRe.MatchString(b.ID) {
			refused++
			continue
		}
		attrs := map[string]string{"tenant": r.Tenant, "agent_id": b.ID}
		put(attrs, "name", b.Name)
		put(attrs, "schema_name", b.SchemaName)
		put(attrs, "state", choice(botStates, b.State))
		put(attrs, "status", choice(botStatuses, b.Status))
		put(attrs, "auth_mode", choice(authModes, b.AuthMode))
		put(attrs, "auth_trigger", choice(authTrigger, b.AuthTrigger))
		put(attrs, "access_policy", choice(accessRules, b.AccessPolicy))
		put(attrs, "published_at", b.PublishedOn)
		put(attrs, "created_at", b.CreatedOn)
		put(attrs, "modified_at", b.ModifiedOn)
		put(attrs, "owner_ref", b.OwnerID)
		if !partial {
			// Names past the attribute's bound are left out; the count stands
			// whole, so a cut list is read, not unread.
			list, _ := joined(skills[b.ID])
			put(attrs, "skills", list)
			attrs["skill_count"], attrs["knowledge_count"] = count(len(skills[b.ID])), count(knowledge[b.ID])
		}
		r.Findings = append(r.Findings, domain.Finding{
			Kind: domain.KindCopilotAgent, Key: domain.Key(domain.SourceCopilotStudio, r.Tenant, b.ID), Attributes: attrs,
		})
	}
	r.Counts[domain.CountAgents] = int64(len(r.Findings))
	if refused > 0 {
		r.Note(domain.NoteRecords, strconv.Itoa(refused)+" agents with no usable id were not read")
	}
}
