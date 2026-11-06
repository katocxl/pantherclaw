// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"errors"
	"testing"
)

// TestHR525_ASessionPolicyNamesOneActionOnExactResources: a session policy
// of several resources allows one action on exactly those distinct ARNs, in
// order (G0 M34 D993a item 3, FQ34-4); one resource is SessionPolicy's;
// none, more than 1+3, a wildcard, "*", a repeat, or a value that is no ARN
// is refused.
func TestHR525_ASessionPolicyNamesOneActionOnExactResources(t *testing.T) {
	inst := "arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0"
	doc := "arn:aws:ssm:us-east-1::document/AWS-RunShellScript"
	got, err := SessionPolicyResources("ssm", "SendCommand", []string{inst, doc})
	want := `{"Statement":[{"Action":"ssm:SendCommand","Effect":"Allow","Resource":["` + inst + `","` + doc + `"]}],"Version":"2012-10-17"}`
	if err != nil || got != want {
		t.Fatalf("two ARNs = %s %v\nwant %s", got, err, want)
	}
	one, err := SessionPolicyResources("ssm", "SendCommand", []string{inst})
	single, _ := SessionPolicy("ssm", "SendCommand", inst)
	if err != nil || one != single {
		t.Fatalf("one ARN = %s %v", one, err)
	}
	if _, err := SessionPolicyResources("ssm", "SendCommand", []string{inst, doc, doc + "2", doc + "3"}); err != nil {
		t.Fatalf("four ARNs: %v", err)
	}
	for name, res := range map[string][]string{
		"none":      nil,
		"five":      {inst, doc, doc + "2", doc + "3", doc + "4"},
		"wildcard":  {inst, "arn:aws:ssm:us-east-1::document/*"},
		"star":      {inst, "*"},
		"repeat":    {inst, inst},
		"not ARN":   {inst, "document/AWS-RunShellScript"},
		"star only": {"*", doc},
	} {
		if _, err := SessionPolicyResources("ssm", "SendCommand", res); !errors.Is(err, ErrAWSAction) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, sa := range map[string][2]string{"action wildcard": {"ssm", "Send*"}, "service": {"ssm*", "SendCommand"}} {
		if _, err := SessionPolicyResources(sa[0], sa[1], []string{inst, doc}); !errors.Is(err, ErrAWSAction) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
