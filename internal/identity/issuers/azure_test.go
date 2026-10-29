// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers_test

import (
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
)

const (
	azTenant = "aaaabbbb-0000-cccc-1111-dddd2222eeee"
	azApp    = "00001111-aaaa-2222-bbbb-3333cccc4444"
	azObject = "11112222-bbbb-3333-cccc-4444dddd5555"
)

func azBinding() issuers.AzureMIBinding {
	return issuers.AzureMIBinding{TenantID: azTenant, AppID: azApp, ObjectID: azObject}
}

func azClaims(t *testing.T, mutate func(*string)) issuers.AzureClaims {
	t.Helper()
	payload := `{"iss":"https://sts.windows.net/` + azTenant + `/","aud":"` + azApp + `","tid":"` + azTenant + `",
		"oid":"` + azObject + `","sub":"` + azObject + `","idtyp":"app","uti":"AbCd",
		"appid":"99990000-aaaa-bbbb-cccc-ddddeeeeffff","ver":"1.0"}`
	if mutate != nil {
		mutate(&payload)
	}
	c, err := issuers.ParseAzureClaims([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAzureMIMatchesThePinnedIdentity(t *testing.T) {
	for name, mutate := range map[string]func(*string){
		"v1 token":        nil,
		"v2 token":        replace(`"https://sts.windows.net/`+azTenant+`/"`, `"https://login.microsoftonline.com/`+azTenant+`/v2.0"`),
		"api:// audience": replace(`"aud":"`+azApp+`"`, `"aud":"api://`+azApp+`"`),
		"no idtyp":        replace(`"idtyp":"app",`, ``),
	} {
		m, err := issuers.MatchAzureMI(azBinding(), azClaims(t, mutate))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !m.Binding.Equal(issuers.Binding{"tenant_id": azTenant, "object_id": azObject}) {
			t.Fatalf("%s: match = %+v", name, m)
		}
	}
}

// TestHR469_AzureMIPresetRules: the pinned tenant's issuer and tid, the
// pinned app as exact audience (never pantherclaw:<org>), the pinned
// object and an app-only token — whatever the entry says.
// Covers: PN-002.3
func TestHR469_AzureMIPresetRules(t *testing.T) {
	for name, mutate := range map[string]func(*string){
		"other tenant issuer":  replace(`"https://sts.windows.net/`+azTenant+`/"`, `"https://sts.windows.net/bbbbcccc-0000-cccc-1111-dddd2222eeee/"`),
		"common issuer":        replace(`"https://sts.windows.net/`+azTenant+`/"`, `"https://login.microsoftonline.com/common/v2.0"`),
		"other tid":            replace(`"tid":"`+azTenant+`"`, `"tid":"bbbbcccc-0000-cccc-1111-dddd2222eeee"`),
		"other app":            replace(`"aud":"`+azApp+`"`, `"aud":"00001111-aaaa-2222-bbbb-3333cccc4445"`),
		"pantherclaw audience": replace(`"aud":"`+azApp+`"`, `"aud":"pantherclaw:`+org.String()+`"`),
		"app id URI with path": replace(`"aud":"`+azApp+`"`, `"aud":"api://`+azApp+`/x"`),
		"trailing slash":       replace(`"aud":"`+azApp+`"`, `"aud":"api://`+azApp+`/"`),
		"other object":         replace(`"oid":"`+azObject+`"`, `"oid":"11112222-bbbb-3333-cccc-4444dddd5556"`),
		"user token":           replace(`"idtyp":"app"`, `"idtyp":"user"`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := issuers.MatchAzureMI(azBinding(), azClaims(t, mutate)); !errors.Is(err, issuers.ErrRejected) {
				t.Fatalf("err = %v, want rejection", err)
			}
		})
	}
	for name, b := range map[string]issuers.AzureMIBinding{
		"upper-case tenant": {TenantID: "AAAABBBB-0000-CCCC-1111-DDDD2222EEEE", AppID: azApp, ObjectID: azObject},
		"no object":         {TenantID: azTenant, AppID: azApp},
		"app id URI":        {TenantID: azTenant, AppID: "api://" + azApp, ObjectID: azObject},
	} {
		if err := b.Validate(); !errors.Is(err, issuers.ErrInvalidEntry) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
	prev, moved := azBinding(), azBinding()
	moved.ObjectID = "11112222-bbbb-3333-cccc-4444dddd5556"
	if w := moved.Widening(&prev); len(w) == 0 {
		t.Error("pinning another managed identity must need activation")
	}
	if w := prev.Widening(&prev); len(w) != 0 {
		t.Errorf("the same binding widens: %v", w)
	}
}

// TestHR469_AzureTokensAttestAtMostAnHour: a token may live up to a day,
// but the window it attests starts at the attestation and lasts at most an
// hour; the uti is its single-use key.
// Covers: PN-002.3
func TestHR469_AzureTokensAttestAtMostAnHour(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	day := issuers.Window{IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(22 * time.Hour)}
	w, err := issuers.AzureWindow(day, "AbCd", now)
	if err != nil {
		t.Fatal(err)
	}
	if !w.IssuedAt.Equal(now) || !w.ExpiresAt.Equal(now.Add(time.Hour)) || w.JTI != "AbCd" {
		t.Fatalf("window = %+v", w)
	}
	short := issuers.Window{IssuedAt: now.Add(-23 * time.Hour), ExpiresAt: now.Add(10 * time.Minute)}
	if w, err := issuers.AzureWindow(short, "", now); err != nil || !w.ExpiresAt.Equal(short.ExpiresAt) {
		t.Errorf("token expiring sooner: %+v, %v", w, err)
	}
	for name, tw := range map[string]issuers.Window{
		"over a day": {IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour)},
		"expired":    {IssuedAt: now.Add(-25 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
		"future":     {IssuedAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour)},
		"no iat":     {ExpiresAt: now.Add(time.Hour)},
		"not yet":    {IssuedAt: now, NotBefore: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour)},
	} {
		if _, err := issuers.AzureWindow(tw, "", now); !errors.Is(err, issuers.ErrRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Every other preset keeps the one-hour token lifetime (HR-143).
	if err := day.Check(now); !errors.Is(err, issuers.ErrRejected) {
		t.Errorf("a day-long token passed the HR-143 lifetime check: %v", err)
	}
}

const azAgent = "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb"

func agentClaims(t *testing.T, mutate func(*string)) issuers.EntraAgentClaims {
	t.Helper()
	payload := `{"iss":"https://sts.windows.net/` + azTenant + `/","aud":"` + azApp + `","tid":"` + azTenant + `",
		"oid":"` + azAgent + `","sub":"bbbbbbbb-1111-2222-3333-cccccccccccc","idtyp":"app","uti":"m5RaaRnoFUyp2TbSCAAAAA",
		"appid":"11112222-bbbb-3333-cccc-4444dddd5555","xms_act_fct":"3 9 11","xms_sub_fct":"9 3 11","xms_tnt_fct":"3 9",
		"xms_idrel":"7 10","xms_par_app_azp":"30cf4c22-9985-4ef7-8756-91cc888176bd","ver":"1.0"}`
	if mutate != nil {
		mutate(&payload)
	}
	c, err := issuers.ParseEntraAgentClaims([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestHR469_EntraAgentPresetRules: an agent identity acting autonomously
// as itself (idtyp app, facet 11 for both subject and actor), in the pinned
// tenant, for the pinned app, with the pinned object id. Agents acting for
// a user or as their user account never match.
// Covers: PN-002.3
func TestHR469_EntraAgentPresetRules(t *testing.T) {
	b := issuers.EntraAgentBinding{TenantID: azTenant, AppID: azApp, ObjectID: azAgent}
	m, err := issuers.MatchEntraAgent(b, agentClaims(t, nil))
	if err != nil || !m.Binding.Equal(issuers.Binding{"tenant_id": azTenant, "object_id": azAgent}) {
		t.Fatalf("autonomous agent: %+v, %v", m, err)
	}
	for name, mutate := range map[string]func(*string){
		"on behalf of a user":  replace(`"idtyp":"app"`, `"idtyp":"user"`),
		"no idtyp":             replace(`"idtyp":"app",`, ``),
		"agent user account":   replace(`"xms_sub_fct":"9 3 11"`, `"xms_sub_fct":"13"`),
		"subject not an agent": replace(`"xms_sub_fct":"9 3 11"`, `"xms_sub_fct":"9 3"`),
		"no subject facets":    replace(`"xms_sub_fct":"9 3 11",`, ``),
		"actor not an agent":   replace(`"xms_act_fct":"3 9 11"`, `"xms_act_fct":"3 9"`),
		"facet as a substring": replace(`"xms_sub_fct":"9 3 11"`, `"xms_sub_fct":"111"`),
		"other agent":          replace(`"oid":"`+azAgent+`"`, `"oid":"aaaaaaaa-0000-1111-2222-bbbbbbbbbbbc"`),
		"other tenant":         replace(`"tid":"`+azTenant+`"`, `"tid":"bbbbcccc-0000-cccc-1111-dddd2222eeee"`),
		"first-party issuer":   replace(`"https://sts.windows.net/`+azTenant+`/"`, `"https://sts.windows.net/00000001-0000-0ff1-ce00-000000000000/"`),
		"other app":            replace(`"aud":"`+azApp+`"`, `"aud":"00001111-aaaa-2222-bbbb-3333cccc4445"`),
		"pantherclaw audience": replace(`"aud":"`+azApp+`"`, `"aud":"pantherclaw:`+org.String()+`"`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := issuers.MatchEntraAgent(b, agentClaims(t, mutate)); !errors.Is(err, issuers.ErrRejected) {
				t.Fatalf("err = %v, want rejection", err)
			}
		})
	}
	// A managed identity entry never matches an agent token's identity, nor
	// an agent entry a managed identity token (no facets).
	if _, err := issuers.MatchEntraAgent(issuers.EntraAgentBinding{TenantID: azTenant, AppID: azApp, ObjectID: azObject},
		issuers.EntraAgentClaims{AzureClaims: azClaims(t, nil)}); !errors.Is(err, issuers.ErrRejected) {
		t.Errorf("managed identity token matched an agent entry: %v", err)
	}
	if err := (issuers.EntraAgentBinding{TenantID: azTenant, AppID: azApp}).Validate(); !errors.Is(err, issuers.ErrInvalidEntry) {
		t.Errorf("no object id: %v", err)
	}
}
