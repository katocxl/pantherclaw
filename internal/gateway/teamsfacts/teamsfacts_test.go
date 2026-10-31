// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package teamsfacts

import (
	"testing"
)

const (
	host    = "5a1e0000-0000-4000-8000-000000000001"
	partner = "5a1e0000-0000-4000-8000-000000000002"
)

func member(tenant, role string) string {
	return `{"id":"29:x","name":"n","tenantId":"` + tenant + `","userRole":"` + role + `"}`
}

func read(t *testing.T, tenant string, pages ...string) map[string]any {
	t.Helper()
	var tally Tally
	for i, p := range pages {
		next, why := tally.Page(200, []byte(p), tenant)
		if why != "" {
			return Unread(why)
		}
		if (next == "") != (i == len(pages)-1) {
			t.Fatalf("page %d: continuation %q", i, next)
		}
	}
	return tally.Value()
}

// TestHR524_AnExternalChannelIsOneThatAdmitsOutsiders: a channel is
// external when a member belongs to another tenant, is a guest or is
// anonymous, or when its members span tenants; anything unreadable is
// unread, never internal (HR-160).
// Covers: HR-524
func TestHR524_AnExternalChannelIsOneThatAdmitsOutsiders(t *testing.T) {
	internal := read(t, host, `{"members":[`+member(host, "user")+`,`+member(host, "user")+`]}`)
	if internal["external"] != false || internal["members"] != 2 {
		t.Fatalf("internal: %v", internal)
	}
	for name, v := range map[string]map[string]any{
		"other tenant":   read(t, host, `{"members":[`+member(host, "user")+`,`+member(partner, "user")+`]}`),
		"guest":          read(t, host, `{"members":[`+member(host, "guest")+`]}`),
		"anonymous":      read(t, host, `{"members":[`+member(host, "anonymous")+`]}`),
		"claimed tenant": read(t, partner, `{"members":[`+member(host, "user")+`]}`),
		"second page": read(t, host, `{"members":[`+member(host, "user")+`],"continuationToken":"p2"}`,
			`{"members":[`+member(partner, "user")+`]}`),
	} {
		if v["external"] != true {
			t.Errorf("%s: %v", name, v)
		}
	}
	for name, body := range map[string]string{
		"no members":  `{}`,
		"empty":       `{"members":[]}`,
		"no tenant":   `{"members":[{"id":"29:x","userRole":"user"}]}`,
		"no role":     `{"members":[{"id":"29:x","tenantId":"` + host + `"}]}`,
		"bad role":    `{"members":[` + member(host, "owner") + `]}`,
		"not json":    `<html>`,
		"bad cont":    `{"members":[` + member(host, "user") + `],"continuationToken":"a b"}`,
		"bad tenant":  `{"members":[` + member("botframework.com", "user") + `]}`,
		"null member": `{"members":null}`,
	} {
		if v := read(t, host, body); v["unread"] == nil {
			t.Errorf("%s: %v", name, v)
		}
	}
	var tally Tally
	if _, why := tally.Page(403, nil, host); why != "Teams answered HTTP 403" {
		t.Errorf("403: %q", why)
	}
}
