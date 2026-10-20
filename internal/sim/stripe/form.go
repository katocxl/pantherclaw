// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stripe

import (
	"crypto/sha256"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// maxBody is the largest request body the simulator reads.
const maxBody = 64 << 10

// form is a request's parameters as Stripe reads them: scalars by name,
// lists ("name[]") by their bare name, and metadata ("metadata[key]") apart.
type form struct {
	scalars  map[string]string
	lists    map[string][]string
	metadata map[string]string
	// digest identifies the parameters for idempotency, independent of
	// their order on the wire.
	digest [32]byte
}

var (
	scalarKey   = regexp.MustCompile(`^[a-z_]{1,64}$`)
	listKey     = regexp.MustCompile(`^([a-z_]{1,64})\[\]$`)
	metadataKey = regexp.MustCompile(`^metadata\[([A-Za-z0-9_.-]{1,40})\]$`)
	nestedKey   = regexp.MustCompile(`^([a-z_]{1,64})\[([a-z_]{1,64})\]$`)
)

// readForm reads a POST's form-encoded body (Stripe is form-encoded; any
// other content type is refused) and checks every key against allowed:
// a name, "name[]" for a list, "metadata" for metadata[...] keys, or
// "parent[child]" for a nested scalar.
func readForm(r *http.Request, allowed []string) (*form, *apiError) {
	if r.ContentLength != 0 {
		ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || ct != "application/x-www-form-urlencoded" {
			return nil, invalid("", "Invalid request: the body must be application/x-www-form-urlencoded.")
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return nil, invalid("", "Invalid request: the body is unreadable or too large.")
	}
	return parseForm(string(body), allowed)
}

// queryForm reads a GET's query string with the same rules.
func queryForm(r *http.Request, allowed []string) (*form, *apiError) {
	return parseForm(r.URL.RawQuery, allowed)
}

func parseForm(raw string, allowed []string) (*form, *apiError) {
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return nil, invalid("", "Invalid request: the parameters could not be parsed.")
	}
	f := &form{scalars: map[string]string{}, lists: map[string][]string{}, metadata: map[string]string{}}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	h := sha256.New()
	for _, k := range keys {
		vs := vals[k]
		switch {
		case listKey.MatchString(k):
			name := listKey.FindStringSubmatch(k)[1]
			if !slices.Contains(allowed, name+"[]") {
				return nil, unknownParam(k)
			}
			if len(vs) > 100 {
				return nil, invalid(k, "Invalid array: too many values for "+k+".")
			}
			f.lists[name] = vs
		case metadataKey.MatchString(k):
			if !slices.Contains(allowed, "metadata") {
				return nil, unknownParam(k)
			}
			if len(vs) != 1 || len(vs[0]) > 500 {
				return nil, invalid(k, "Invalid metadata value for "+k+".")
			}
			if len(f.metadata) == 50 {
				return nil, invalid("metadata", "Invalid metadata: at most 50 keys.")
			}
			f.metadata[metadataKey.FindStringSubmatch(k)[1]] = vs[0]
		case scalarKey.MatchString(k) || nestedKey.MatchString(k):
			if !slices.Contains(allowed, k) {
				return nil, unknownParam(k)
			}
			if len(vs) != 1 {
				return nil, invalid(k, "Invalid request: "+k+" is given more than once.")
			}
			f.scalars[k] = vs[0]
		default:
			return nil, unknownParam(k)
		}
		for _, v := range vs {
			_, _ = io.WriteString(h, strconv.Quote(k)+"="+strconv.Quote(v)+"\n")
		}
	}
	copy(f.digest[:], h.Sum(nil))
	return f, nil
}

// get returns a scalar parameter.
func (f *form) get(k string) string { return f.scalars[k] }

// amount reads a positive integer amount in minor units.
func (f *form) amount(k string, required bool) (int64, bool, *apiError) {
	v, ok := f.scalars[k]
	if !ok {
		if required {
			return 0, false, missing(k)
		}
		return 0, false, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 || n > 99999999 || strings.HasPrefix(v, "0") || strings.HasPrefix(v, "+") {
		return 0, false, invalid(k, "Invalid integer: "+v)
	}
	return n, true, nil
}

// flag reads an optional boolean parameter ("true" or "false").
func (f *form) flag(k string) (bool, *apiError) {
	switch f.scalars[k] {
	case "":
		return false, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, invalid(k, "Invalid boolean: "+f.scalars[k])
}

// currencies are the currencies the simulator accepts (the minor-unit
// table of the M14 tracker D8), lowercase as Stripe writes them.
var currencies = []string{"usd", "eur", "gbp", "cad", "aud", "nzd", "chf", "sek", "nok", "dkk", "sgd", "hkd", "jpy", "krw"}

// currency reads a required currency.
func (f *form) currency() (string, *apiError) {
	c, ok := f.scalars["currency"]
	if !ok {
		return "", missing("currency")
	}
	c = strings.ToLower(c) // Stripe reads currency codes without regard to case
	if !slices.Contains(currencies, c) {
		return "", invalid("currency", "Invalid currency: "+c)
	}
	return c, nil
}
