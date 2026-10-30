// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"strings"
	"testing"
)

func validAWS() AWSSigV4 {
	return AWSSigV4{
		V: 1, AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		RoleARN: "arn:aws:iam::111122223333:role/pantherclaw-deploy", STSURL: "https://sts.amazonaws.com", STSRegion: "us-east-1",
		Region: "us-east-1", Service: "iam",
	}
}

// TestHR525_AnAWSCredentialIsCheckedWhole: every field is checked, the
// role's account is read from its ARN, and an unknown member is refused.
// Covers: HR-525
func TestHR525_AnAWSCredentialIsCheckedWhole(t *testing.T) {
	plain, err := validAWS().Encode()
	if err != nil {
		t.Fatal(err)
	}
	a, err := DecodeAWSSigV4(plain)
	if err != nil || a.Account() != "111122223333" {
		t.Fatalf("%v %q", err, a.Account())
	}
	a.Clear()
	if strings.Trim(string(a.SecretAccessKey), "\x00") != "" {
		t.Fatal("secret not cleared")
	}
	gov := validAWS()
	gov.RoleARN, gov.STSRegion, gov.Region = "arn:aws-us-gov:iam::111122223333:role/x", "us-gov-west-1", "us-gov-west-1"
	if err := gov.Validate(); err != nil {
		t.Fatalf("GovCloud: %v", err)
	}
	for name, mut := range map[string]func(*AWSSigV4){
		"version":       func(a *AWSSigV4) { a.V = 0 },
		"key id":        func(a *AWSSigV4) { a.AccessKeyID = "akia" },
		"short secret":  func(a *AWSSigV4) { a.SecretAccessKey = []byte("short") },
		"user arn":      func(a *AWSSigV4) { a.RoleARN = "arn:aws:iam::111122223333:user/x" },
		"short account": func(a *AWSSigV4) { a.RoleARN = "arn:aws:iam::1111:role/x" },
		"external id":   func(a *AWSSigV4) { a.ExternalID = "a b" },
		"long ext id":   func(a *AWSSigV4) { a.ExternalID = strings.Repeat("a", 1225) },
		"sts query":     func(a *AWSSigV4) { a.STSURL = "https://sts.amazonaws.com/?Action=x" },
		"sts path":      func(a *AWSSigV4) { a.STSURL = "https://sts.amazonaws.com/x" },
		"sts userinfo":  func(a *AWSSigV4) { a.STSURL = "https://u@sts.amazonaws.com" },
		"region":        func(a *AWSSigV4) { a.Region = "US-EAST-1" },
		"sts region":    func(a *AWSSigV4) { a.STSRegion = "" },
		"service":       func(a *AWSSigV4) { a.Service = "IAM" },
	} {
		a := validAWS()
		mut(&a)
		if _, err := a.Encode(); !errors.Is(err, ErrAWSSigV4) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := DecodeAWSSigV4([]byte(`{"v":1,"extra":true}`)); err == nil {
		t.Error("unknown member accepted")
	}
	if !ValidKind(KindAWSSigV4) || !Minted(KindAWSSigV4) {
		t.Error("kind")
	}
}
