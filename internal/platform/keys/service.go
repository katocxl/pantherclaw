// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keys

import (
	"errors"
)

// Key service kinds (D157).
const (
	ServiceFile    = "file"
	ServiceOpenBao = "openbao"
)

// ServiceConfig is the server's key_service config:
// {kind: file|openbao, openbao: {address, mount, key_name, auth}}. The kind
// is the provider that wraps new keys. KEK files, when configured, still
// unwrap the keys they wrapped, so a deployment moves from file to OpenBao
// by re-wrapping (D157).
type ServiceConfig struct {
	// Kind is "file" (default) or "openbao".
	Kind    string        `json:"kind" env:"PC_KEY_SERVICE"`
	OpenBao OpenBaoConfig `json:"openbao"`
}

// IsOpenBao reports whether OpenBao wraps new keys.
func (c ServiceConfig) IsOpenBao() bool { return c.Kind == ServiceOpenBao }

// Validate checks the configuration; kekFiles is the number of KEK files.
func (c ServiceConfig) Validate(kekFiles int) []error {
	switch c.Kind {
	case "", ServiceFile:
		if kekFiles == 0 {
			return []error{errors.New("kek_files is required (generate one with: pantherclaw-server keys gen-kek --out FILE)")}
		}
		if c.OpenBao.Address != "" {
			return c.OpenBao.Validate()
		}
		return nil
	case ServiceOpenBao:
		return c.OpenBao.Validate()
	}
	return []error{errors.New(`key_service.kind must be "file" or "openbao"`)}
}

// FromConfig builds the server's Router: the configured kind wraps, and
// every configured provider unwraps its own keys. An OpenBao address with
// kind file lets keys already moved to OpenBao still unwrap.
func FromConfig(c ServiceConfig, kekFiles []string) (*Router, error) {
	if errs := c.Validate(len(kekFiles)); len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	var file *FileProvider
	if len(kekFiles) > 0 {
		fp, err := NewFileProvider(kekFiles)
		if err != nil {
			return nil, err
		}
		file = fp
	}
	var bao *OpenBaoProvider
	if c.OpenBao.Address != "" {
		tc, err := NewTransitClient(c.OpenBao)
		if err != nil {
			return nil, err
		}
		bao = NewOpenBaoProvider(tc)
	}
	current := PrefixFile
	if c.IsOpenBao() {
		current = PrefixOpenBao
	}
	return NewRouter(current, file, bao)
}
