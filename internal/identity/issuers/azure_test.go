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
	azMIRID  = "/subscriptions/0000/resourcegroups/agents/providers/Microsoft.ManagedIdentity/userAssignedIdentities/runner"
)

func azBinding() issuers.AzureMIBinding {
	return issuers.AzureMIBinding{TenantID: azTenant, AppID: azApp, ObjectID: azObject, ResourceID: azMIRID}
}

func azClaims(t *testing.T, mutate func(*string)) issuers.AzureClaims {
	t.Helper()
	payload := `{"iss":"https://sts.windows.net/` + azTenant + `/","aud":"` + azApp + `","tid":"` + azTenant + `",
		"oid":"` + azObject + `","sub":"` + azObject + `","idtyp":"app","xms_mirid":"` + azMIRID + `","uti":"AbCd",
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
// object, an app-only token and the pinned resource id — whatever the
// entry says.
// Covers: PN-002.3
func TestHR469_AzureMIPresetRules(t *testing.T) {
	for name, mutate := range map[string]func(*string){
		"other tenant issuer":    replace(`"https://sts.windows.net/`+azTenant+`/"`, `"https://sts.windows.net/bbbbcccc-0000-cccc-1111-dddd2222eeee/"`),
		"common issuer":          replace(`"https://sts.windows.net/`+azTenant+`/"`, `"https://login.microsoftonline.com/common/v2.0"`),
		"other tid":              replace(`"tid":"`+azTenant+`"`, `"tid":"bbbbcccc-0000-cccc-1111-dddd2222eeee"`),
		"other app":              replace(`"aud":"`+azApp+`"`, `"aud":"00001111-aaaa-2222-bbbb-3333cccc4445"`),
		"pantherclaw audience":   replace(`"aud":"`+azApp+`"`, `"aud":"pantherclaw:`+org.String()+`"`),
		"app id URI with path":   replace(`"aud":"`+azApp+`"`, `"aud":"api://`+azApp+`/x"`),
		"trailing slash":         replace(`"aud":"`+azApp+`"`, `"aud":"api://`+azApp+`/"`),
		"other object":           replace(`"oid":"`+azObject+`"`, `"oid":"11112222-bbbb-3333-cccc-4444dddd5556"`),
		"user token":             replace(`"idtyp":"app"`, `"idtyp":"user"`),
		"other managed identity": replace(azMIRID, azMIRID+"2"),
		"resource id missing":    replace(`"xms_mirid":"`+azMIRID+`",`, ``),
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
		"bad resource":      {TenantID: azTenant, AppID: azApp, ObjectID: azObject, ResourceID: "runner"},
	} {
		if err := b.Validate(); !errors.Is(err, issuers.ErrInvalidEntry) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
	prev, unpinned := azBinding(), azBinding()
	unpinned.ResourceID = ""
	if w := unpinned.Widening(&prev); len(w) == 0 {
		t.Error("removing the resource pin must need activation")
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
