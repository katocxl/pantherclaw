// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// modelRead is a models read over a model dispatch, for the checks below.
func modelRead() *domain.Definition {
	d := minimal(map[string]domain.ParamSpec{"model": {Type: domain.TypeIdentifier, MaxLength: 256}})
	d.Operation, d.Target.Type, d.Target.IDPattern = "anthropic.models.read", "model", "^[!-~]{1,256}$"
	d.Dispatch = &domain.Dispatch{Model: &domain.ModelDispatch{API: domain.ModelAPIAnthropicModels, Path: "/models"}}
	d.Mappings = []domain.Mapping{
		{Channel: domain.ChannelHTTP, Method: "GET", Path: "/models", Route: "models-list"},
		{Channel: domain.ChannelHTTP, Method: "GET", Path: "/models/{id}", Route: "models-get"},
	}
	return d
}

// TestM29_ModelDispatch: a model dispatch names a known API and exactly its
// fixed path, is a read for the models APIs and a write for the rest, is
// the definition's only dispatch, and its mappings are http routes that
// extract nothing (G0 M29 D813).
//
// Covers: F980, HR-691
func TestM29_ModelDispatch(t *testing.T) {
	if err := modelRead().Validate(); err != nil {
		t.Fatal(err)
	}
	if !modelRead().IsModel() || minimal(nil).IsModel() {
		t.Fatal("IsModel")
	}
	for name, edit := range map[string]func(d *domain.Definition){
		"unknown api":       func(d *domain.Definition) { d.Dispatch.Model.API = "anthropic.complete" },
		"wrong path":        func(d *domain.Definition) { d.Dispatch.Model.Path = "/models/list" },
		"empty path":        func(d *domain.Definition) { d.Dispatch.Model.Path = "" },
		"path of other api": func(d *domain.Definition) { d.Dispatch.Model.Path = "/messages" },
		"a write of models": func(d *domain.Definition) { d.Access = domain.AccessWrite },
		"a read of messages": func(d *domain.Definition) {
			d.Dispatch.Model = &domain.ModelDispatch{API: "anthropic.messages", Path: "/messages"}
		},
		"two dispatches": func(d *domain.Definition) {
			d.Dispatch.HTTP = &domain.HTTPDispatch{Method: "GET", Path: "/models"}
		},
		"mcp mapping": func(d *domain.Definition) {
			d.Mappings = []domain.Mapping{{
				Channel: domain.ChannelMCP, Tool: "models", Route: "m",
				Extract: domain.Extract{TargetID: "'a'", Params: map[string]string{}},
			}}
		},
		"extracts a target": func(d *domain.Definition) { d.Mappings[0].Extract.TargetID = "'sim-model'" },
		"extracts a param": func(d *domain.Definition) {
			d.Mappings[0].Extract.Params = map[string]string{"model": "path.id"}
		},
		"connection test": func(d *domain.Definition) { d.Test = true },
	} {
		d := modelRead()
		edit(d)
		if err := d.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for api, path := range domain.ModelAPIPaths {
		if path == "" || path[0] != '/' {
			t.Errorf("%s: path %q", api, path)
		}
	}
}
