// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package log

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestHR203_GitHubTokensNeverReachALog: a GitHub token anywhere in a
// string, an error or a structured value is redacted, including a
// stateless installation token of about 520 characters, under keys that
// do not look sensitive.
func TestHR203_GitHubTokensNeverReachALog(t *testing.T) {
	installation := "ghs_" + strings.Repeat("Ab9_", 129) // 520 characters
	tokens := []string{installation, "ghp_" + strings.Repeat("x", 36), "github_pat_" + strings.Repeat("Y1", 40), "gho_" + strings.Repeat("z", 36)}
	var buf bytes.Buffer
	l := newTestLogger(&buf)
	for _, tok := range tokens {
		l.Info("test.event",
			"detail", "GitHub answered for "+tok+" with 401",
			"cause", errors.New("mint: "+tok),
			"raw", []byte(tok),
			"body", map[string]string{"note": tok},
		)
	}
	out := buf.String()
	for _, tok := range tokens {
		if strings.Contains(out, tok[:20]) {
			t.Fatalf("a token reached the log: %s", out)
		}
	}
	if strings.Count(out, Redacted) < 4*len(tokens) {
		t.Fatalf("not every token was redacted: %s", out)
	}
	// Short look-alikes and ordinary words stay.
	buf.Reset()
	l.Info("test.event", "detail", fmt.Sprintf("ghs_short %s", "github_patterns"))
	if !strings.Contains(buf.String(), "ghs_short github_patterns") {
		t.Fatalf("over-redacted: %s", buf.String())
	}
}
