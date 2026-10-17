// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

func m14Mapper(t testing.TB) *Mapper {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "m14-format.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return mapperFor(t, raw)
}

// TestHR300_FormParserIsStrict: the one form parser reads the Stripe
// bracket syntax into the input a JSON mapping sees, and refuses anything
// a target could read another way: another media type, a scalar key twice,
// a name used as a value and an object or a list, a key deeper than three
// levels, an index-like name, an oversize body, too many pairs, an empty
// pair, a pair without "=", a bad escape, invalid UTF-8 and control
// characters (G0 M14 D8).
func TestHR300_FormParserIsStrict(t *testing.T) {
	got, err := DecodeForm("application/x-www-form-urlencoded; charset=UTF-8",
		[]byte("amount=8550&currency=usd&metadata[order]=A%2B1&metadata[note]=two+words&expand[]=charge&expand[]=customer&a[b][c]=deep"))
	want := map[string]any{
		"amount": "8550", "currency": "usd", "metadata": map[string]any{"order": "A+1", "note": "two words"},
		"expand": []any{"charge", "customer"}, "a": map[string]any{"b": map[string]any{"c": "deep"}},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded %#v, %v", got, err)
	}
	if got, err := DecodeForm(FormContentType, nil); err != nil || len(got) != 0 {
		t.Fatalf("empty body: %v %v", got, err)
	}
	for name, c := range map[string]struct{ ct, body string }{
		"json content type":      {"application/json", "a=1"},
		"multipart":              {"multipart/form-data; boundary=x", "a=1"},
		"latin-1":                {"application/x-www-form-urlencoded; charset=iso-8859-1", "a=1"},
		"extra parameter":        {"application/x-www-form-urlencoded; x=y", "a=1"},
		"no content type":        {"", "a=1"},
		"duplicate key":          {FormContentType, "a=1&a=2"},
		"duplicate nested key":   {FormContentType, "m[k]=1&m[k]=2"},
		"depth four":             {FormContentType, "a[b][c][d]=1"},
		"depth four list":        {FormContentType, "a[b][c][]=1"},
		"value then object":      {FormContentType, "a=1&a[b]=2"},
		"object then value":      {FormContentType, "a[b]=2&a=1"},
		"list then value":        {FormContentType, "a[]=1&a=2"},
		"value then list":        {FormContentType, "a=2&a[]=1"},
		"list then object":       {FormContentType, "a[]=1&a[b]=2"},
		"nested value and list":  {FormContentType, "a[b]=1&a[b][]=2"},
		"index":                  {FormContentType, "a[0]=1"},
		"unclosed bracket":       {FormContentType, "a[b=1"},
		"text after bracket":     {FormContentType, "a[b]c=1"},
		"bracket after list":     {FormContentType, "a[][b]=1"},
		"root not a name":        {FormContentType, "1a=1"},
		"empty key":              {FormContentType, "=1"},
		"empty pair":             {FormContentType, "a=1&&b=2"},
		"trailing ampersand":     {FormContentType, "a=1&"},
		"pair without equals":    {FormContentType, "a=1&b"},
		"bad escape":             {FormContentType, "a=%zz"},
		"invalid utf-8":          {FormContentType, "a=%ff"},
		"control character":      {FormContentType, "a=%00"},
		"line break":             {FormContentType, "a=x%0Ay"},
		"escaped bracket in key": {FormContentType, "a%5B0%5D=1"},
		"oversize":               {FormContentType, "a=" + strings.Repeat("x", 64<<10)},
		"too many pairs":         {FormContentType, strings.TrimSuffix(strings.Repeat("k[]=1&", 257), "&")},
	} {
		if got, err := DecodeForm(c.ct, []byte(c.body)); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
}

// TestHR300_FormMappingNeedsAFormBody: a form mapping reads only a form
// body with its media type; the same body without one, or JSON, maps
// nothing (G0 M14 D8).
func TestHR300_FormMappingNeedsAFormBody(t *testing.T) {
	m := m14Mapper(t)
	ctx := context.Background()
	body := []byte("payment_intent=pi_0123456789&amount=8550&currency=USD")
	if _, err := m.HTTPRequest(ctx, tc, "POST", "/v1/refunds", "", FormContentType, body); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() error{
		"no content type": func() error { _, err := m.HTTP(ctx, tc, "POST", "/v1/refunds", "", body); return err },
		"json body": func() error {
			_, err := m.HTTPRequest(ctx, tc, "POST", "/v1/refunds", "", "application/json", []byte(`{"payment_intent":"pi_0123456789","amount":"8550","currency":"USD"}`))
			return err
		},
		"an unmapped field": func() error {
			_, err := m.HTTPRequest(ctx, tc, "POST", "/v1/refunds", "", FormContentType, append(body, "&customer=cus_1"...))
			return err
		},
		"a fraction of a cent": func() error {
			_, err := m.HTTPRequest(ctx, tc, "POST", "/v1/refunds", "", FormContentType, []byte("charge=ch_0123456789&amount=85.5&currency=USD"))
			return err
		},
		"a currency without minor units here": func() error {
			_, err := m.HTTPRequest(ctx, tc, "POST", "/v1/refunds", "", FormContentType, []byte("charge=ch_0123456789&amount=1&currency=KWD"))
			return err
		},
	} {
		if err := run(); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR124_M14FormatMappingGolden pins the ActionIR the M14 format
// mappings produce: a form body, money in minor units (two digits for USD,
// none for JPY), the same refund through MCP, and an A2A message mapped by
// method (G0 M14 D8, D9).
func TestHR124_M14FormatMappingGolden(t *testing.T) {
	m := m14Mapper(t)
	ctx := context.Background()
	var out bytes.Buffer
	for _, c := range []struct {
		name string
		run  func() (actionir.Parsed, error)
	}{
		{"http form POST /v1/refunds USD", func() (actionir.Parsed, error) {
			return m.HTTPRequest(ctx, tc, "POST", "/v1/refunds", "", FormContentType,
				[]byte("payment_intent=pi_0123456789&amount=8550&currency=USD&reason=duplicate"))
		}},
		{"http form POST /v1/refunds JPY", func() (actionir.Parsed, error) {
			return m.HTTPRequest(ctx, tc, "POST", "/v1/refunds", "", FormContentType+"; charset=utf-8",
				[]byte("charge=ch_0123456789&amount=1200&currency=JPY"))
		}},
		{"mcp create_refund", func() (actionir.Parsed, error) {
			return m.MCP(ctx, tc, "create_refund", []byte(`{"payment":"pi_0123456789","amount":8550,"currency":"USD","reason":"duplicate"}`))
		}},
		{"a2a SendMessage", func() (actionir.Parsed, error) {
			return m.A2A(ctx, tc, "SendMessage", []byte(`{"message":{"contextId":"ctx-1","metadata":{"skill":"refunds"}}}`))
		}},
	} {
		p, err := c.run()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		fmt.Fprintf(&out, "%s %s\n%s\n", c.name, p.HashHex(), p.Canonical)
	}
	path := filepath.Join("testdata", "m14-format.actionir")
	if *update {
		if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("ActionIR changed; review and rerun with -update:\n%s", out.Bytes())
	}
	if _, err := m.A2A(ctx, tc, "GetTask", []byte(`{}`)); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("an unmapped method: %v", err)
	}
}
