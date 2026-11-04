// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"slices"
	"strconv"

	"google.golang.org/protobuf/proto"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// modelFlags are a model connection's settings on connection create and
// update (G0 M29 D811a). A price needs Team (D829).
type modelFlags struct {
	maxOut                                   optional
	tools                                    list
	currency, input, output, cacheR, cacheW optional
	clearPrice                               *bool
}

const modelFlagUsage = " [--max-output-tokens N] [--allow-server-tool TYPE...] [--price-currency CUR --price-input D --price-output D " +
	"[--price-cache-read D] [--price-cache-write D]]"

func addModelFlags(fs *flag.FlagSet, update bool) *modelFlags {
	m := &modelFlags{}
	fs.Var(&m.maxOut, "max-output-tokens", "model connections: the max output tokens added to a request that has none (default 64000)")
	fs.Var(&m.tools, "allow-server-tool", "model connections: a provider-side tool type to allow (repeatable; replaces the list; '' alone clears it)")
	fs.Var(&m.currency, "price-currency", "model connections (Team): the currency of the prices below")
	fs.Var(&m.input, "price-input", "model connections (Team): price per million input tokens, a decimal")
	fs.Var(&m.output, "price-output", "model connections (Team): price per million output tokens, a decimal")
	fs.Var(&m.cacheR, "price-cache-read", "model connections (Team): price per million cache-read tokens (default: the input price)")
	fs.Var(&m.cacheW, "price-cache-write", "model connections (Team): price per million cache-write tokens (default: the input price)")
	if update {
		m.clearPrice = fs.Bool("clear-price", false, "model connections: remove the price")
	} else {
		m.clearPrice = new(bool)
	}
	return m
}

// set reports whether any model flag was given.
func (m *modelFlags) set() bool {
	return m.maxOut.set || len(m.tools) > 0 || m.priceSet() || *m.clearPrice
}

func (m *modelFlags) priceSet() bool {
	return m.currency.set || m.input.set || m.output.set || m.cacheR.set || m.cacheW.set
}

// config applies the flags to base (the connection's current settings on
// update, nil on create).
func (m *modelFlags) config(base *pb.ModelConfig) (*pb.ModelConfig, error) {
	out := &pb.ModelConfig{}
	if base != nil {
		out = proto.CloneOf(base)
	}
	if m.maxOut.set {
		n, err := strconv.ParseInt(m.maxOut.v, 10, 64)
		if err != nil {
			return nil, errors.New("--max-output-tokens: an integer")
		}
		out.MaxOutputTokens = n
	}
	if len(m.tools) > 0 {
		out.AllowedServerTools = slices.DeleteFunc(slices.Clone(m.tools), func(t string) bool { return t == "" })
		if len(out.AllowedServerTools) != len(m.tools) && len(m.tools) != 1 {
			return nil, errors.New("--allow-server-tool '' clears the list and goes alone")
		}
	}
	switch {
	case *m.clearPrice && m.priceSet():
		return nil, errors.New("--clear-price goes without the --price-* flags")
	case *m.clearPrice:
		out.Price = nil
	case m.priceSet():
		p := out.GetPrice()
		if p == nil {
			p = &pb.ModelPrice{}
		}
		for _, f := range []struct {
			o   *optional
			dst *string
		}{
			{&m.currency, &p.Currency}, {&m.input, &p.InputPerMillion}, {&m.output, &p.OutputPerMillion},
			{&m.cacheR, &p.CacheReadPerMillion}, {&m.cacheW, &p.CacheWritePerMillion},
		} {
			if f.o.set {
				*f.dst = f.o.v
			}
		}
		out.Price = p
	}
	return out, nil
}

// currentModel is a model connection's settings, read before an update
// changes some of them.
func currentModel(ctx context.Context, c clients, id string) (*pb.ModelConfig, error) {
	res, err := c.connections.GetConnection(ctx, &pb.GetConnectionRequest{Id: id})
	if err != nil {
		return nil, err
	}
	if res.GetConnection().GetKind() != pb.ConnectionKind_CONNECTION_KIND_MODEL {
		return nil, errors.New("the model flags change model connections only")
	}
	return res.GetConnection().GetModel(), nil
}
