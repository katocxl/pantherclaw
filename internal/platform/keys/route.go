// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keys

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
)

// KEK id prefixes name the provider that holds a KEK (D157). A kek_id
// without a prefix was written before M18 and is a file KEK.
const (
	PrefixFile    = "file:"
	PrefixOpenBao = "bao:"
)

// Router is the KeyProvider the server uses: it wraps with one current
// provider and routes each unwrap by the KEK id inside the wrapped value,
// so file and OpenBao KEKs work side by side during a migration (D157).
// An unwrap never falls back to another provider (HR-486).
type Router struct {
	current string // PrefixFile or PrefixOpenBao
	file    *FileProvider
	bao     *OpenBaoProvider
}

var _ KeyProvider = (*Router)(nil)

// NewRouter returns a Router. current is PrefixFile or PrefixOpenBao and
// its provider must be set; the other provider is optional and only
// unwraps.
func NewRouter(current string, file *FileProvider, bao *OpenBaoProvider) (*Router, error) {
	switch {
	case current == PrefixFile && file == nil, current == PrefixOpenBao && bao == nil:
		return nil, fmt.Errorf("keys: the current key service %q is not configured", current)
	case current != PrefixFile && current != PrefixOpenBao:
		return nil, fmt.Errorf("keys: unknown key service %q", current)
	}
	return &Router{current: current, file: file, bao: bao}, nil
}

// CurrentKEK implements KeyProvider: the prefixed id of the current KEK.
func (r *Router) CurrentKEK() string {
	if r.current == PrefixOpenBao {
		return r.bao.CurrentKEK()
	}
	return PrefixFile + r.file.CurrentKEK()
}

// Wrap implements KeyProvider with the current provider.
func (r *Router) Wrap(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	if r.current == PrefixOpenBao {
		return r.bao.Wrap(ctx, plaintext, aad)
	}
	return r.file.Wrap(ctx, plaintext, aad)
}

// Unwrap implements KeyProvider: the KEK id in wrapped picks the provider.
func (r *Router) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	kek, err := KEKOf(wrapped)
	if err != nil {
		return nil, err
	}
	switch {
	case strings.HasPrefix(kek, PrefixOpenBao) && r.bao != nil:
		return r.bao.Unwrap(ctx, wrapped, aad)
	case strings.HasPrefix(kek, PrefixFile) && r.file != nil:
		return r.file.Unwrap(ctx, wrapped, aad)
	}
	return nil, ErrUnwrap
}

// KEKOf returns the prefixed id of the KEK that wrapped a value, read from
// its envelope (version ‖ len(kid) ‖ kid ‖ …).
func KEKOf(wrapped []byte) (string, error) {
	if len(wrapped) < 2 || wrapped[0] != wrapV1 || len(wrapped) < 2+int(wrapped[1]) || wrapped[1] == 0 {
		return "", ErrUnwrap
	}
	kid := string(wrapped[2 : 2+int(wrapped[1])])
	if strings.HasPrefix(kid, PrefixOpenBao) {
		return kid, nil
	}
	return PrefixFile + strings.TrimPrefix(kid, PrefixFile), nil
}

// SameKEK reports whether two kek_id values name the same KEK; an
// unprefixed id is a file KEK.
func SameKEK(a, b string) bool {
	return normalKEK(a) == normalKEK(b)
}

func normalKEK(id string) string {
	if strings.HasPrefix(id, PrefixOpenBao) || strings.HasPrefix(id, PrefixFile) {
		return id
	}
	return PrefixFile + id
}

// ErrRewrapVerify reports a re-wrapped value that does not unwrap to the
// original key; nothing may be written (HR-487).
var ErrRewrapVerify = errors.New("keys: re-wrapped key failed verification")

// Rewrap is the re-wrap port (D157): it unwraps wrapped, wraps the key
// again under the current KEK, and verifies by unwrapping the new value
// before returning it with its KEK id. Any failure returns no value, so the
// caller writes nothing (HR-486, HR-487).
func Rewrap(ctx context.Context, kp KeyProvider, wrapped, aad []byte) (newWrapped []byte, kekID string, err error) {
	plain, err := kp.Unwrap(ctx, wrapped, aad)
	if err != nil {
		return nil, "", err
	}
	defer clear(plain)
	out, err := kp.Wrap(ctx, plain, aad)
	if err != nil {
		return nil, "", fmt.Errorf("keys: re-wrap: %w", err)
	}
	kekID = kp.CurrentKEK()
	if got, err := KEKOf(out); err != nil || !SameKEK(got, kekID) {
		return nil, "", ErrRewrapVerify
	}
	check, err := kp.Unwrap(ctx, out, aad)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrRewrapVerify, err)
	}
	defer clear(check)
	if subtle.ConstantTimeCompare(check, plain) != 1 {
		return nil, "", ErrRewrapVerify
	}
	return out, kekID, nil
}

// Routes reports whether the router has a provider for a stored kek_id;
// an unprefixed id is a file KEK.
func (r *Router) Routes(kekID string) bool {
	if strings.HasPrefix(kekID, PrefixOpenBao) {
		return r.bao != nil && kekID == r.bao.CurrentKEK()
	}
	return r.file != nil && r.file.Holds(strings.TrimPrefix(kekID, PrefixFile))
}
