// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package extension

import (
	"errors"
	"net/http"
	"testing"
	"testing/fstest"
)

// Covers: F918. Compose runs every Validate, mounts every route in order and
// keeps the one console; two consoles stop the server (D405).
func TestCompose(t *testing.T) {
	route := func(p string) Route {
		return Route{Pattern: p, Handler: http.NotFoundHandler()}
	}
	console := fstest.MapFS{"index.html": {Data: []byte("x")}}
	var ran []string
	a := Set{
		Console:  console,
		Validate: func(Deps) error { ran = append(ran, "a"); return nil },
		Mount:    func(Deps) ([]Route, error) { return []Route{route("/v1/ext/a")}, nil },
	}
	b := Set{
		Validate: func(Deps) error { ran = append(ran, "b"); return nil },
		Mount:    func(Deps) ([]Route, error) { return []Route{route("/v1/ext/b")}, nil },
	}
	s := Compose(a, Set{}, b)
	if s.Console == nil {
		t.Fatal("the console was lost")
	}
	if err := s.Validate(Deps{}); err != nil || len(ran) != 2 || ran[0] != "a" || ran[1] != "b" {
		t.Fatalf("Validate = %v, ran %v", err, ran)
	}
	rs, err := s.Mount(Deps{})
	if err != nil || len(rs) != 2 || rs[0].Pattern != "/v1/ext/a" || rs[1].Pattern != "/v1/ext/b" {
		t.Fatalf("Mount = %v, %v", rs, err)
	}

	boom := errors.New("boom")
	bad := Compose(b, Set{Validate: func(Deps) error { return boom }, Mount: func(Deps) ([]Route, error) { return nil, boom }})
	if err := bad.Validate(Deps{}); !errors.Is(err, boom) {
		t.Fatalf("a failing Validate = %v", err)
	}
	if _, err := bad.Mount(Deps{}); !errors.Is(err, boom) {
		t.Fatalf("a failing Mount = %v", err)
	}
	if err := Compose(a, a).Validate(Deps{}); !errors.Is(err, ErrTwoConsoles) {
		t.Fatalf("two consoles = %v", err)
	}
	if Compose().Present() || Compose(Set{}).Present() {
		t.Fatal("composing nothing adds something")
	}
}
