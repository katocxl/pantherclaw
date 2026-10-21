// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package config loads typed, validated configuration once at start-up
// (BUILD_GUIDE §3.1).
//
// Precedence: defaults set in the struct before loading < JSON file < env
// variables named by `env` struct tags. The JSON file is strict (unknown and
// duplicate keys are errors). Secret values are never accepted from the file
// or the environment: configuration holds only *paths* to secret files, read
// with ReadSecretFile into log.Secret values (SB-7).
package config

import (
	"encoding"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// MaxFileBytes caps the configuration file size.
const MaxFileBytes = 1 << 20

// ErrInvalid wraps every configuration error.
var ErrInvalid = errors.New("config: invalid configuration")

// Validator is implemented by configuration structs that check themselves
// after loading. Nested structs are validated by their parents.
type Validator interface {
	Validate() error
}

// LookupEnv reads an environment variable; os.LookupEnv in production,
// a map in tests.
type LookupEnv func(key string) (string, bool)

// Load fills dst (a pointer to a struct) from the JSON file at path (skipped
// when path is empty), then from environment variables, then validates it.
func Load(dst any, path string, env LookupEnv) error {
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("%w: destination must be a pointer to a struct", ErrInvalid)
	}
	if path != "" {
		if err := loadFile(dst, path); err != nil {
			return err
		}
	}
	if env != nil {
		if err := applyEnv(rv.Elem(), env); err != nil {
			return err
		}
	}
	if v, ok := dst.(Validator); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
	}
	return nil
}

func loadFile(dst any, path string) error {
	f, err := os.Open(path) //nolint:gosec // G304: the operator chooses the config path
	if err != nil {
		return fmt.Errorf("%w: open %s: %w", ErrInvalid, path, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return fmt.Errorf("%w: read %s: %w", ErrInvalid, path, err)
	}
	if len(b) > MaxFileBytes {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, path, MaxFileBytes)
	}
	if err := json.Unmarshal(b, dst, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInvalid, path, err)
	}
	return nil
}

var textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()

func applyEnv(v reflect.Value, env LookupEnv) error {
	t := v.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		fv := v.Field(i)
		if !field.IsExported() {
			continue
		}
		name := field.Tag.Get("env")
		if name == "" {
			if fv.Kind() == reflect.Struct && !fv.Addr().Type().Implements(textUnmarshalerType) {
				if err := applyEnv(fv, env); err != nil {
					return err
				}
			}
			continue
		}
		raw, ok := env(name)
		if !ok {
			continue
		}
		if err := setFromString(fv, raw); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrInvalid, name, err)
		}
	}
	return nil
}

func setFromString(fv reflect.Value, raw string) error {
	if fv.Addr().Type().Implements(textUnmarshalerType) {
		u, _ := fv.Addr().Interface().(encoding.TextUnmarshaler)
		return u.UnmarshalText([]byte(raw))
	}
	//exhaustive:ignore // only the kinds configuration structs use are supported; the rest fail below
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(raw)
	case reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return errors.New("not a boolean")
		}
		fv.SetBool(b)
	case reflect.Int, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(raw, 10, fv.Type().Bits())
		if err != nil {
			return errors.New("not an integer")
		}
		fv.SetInt(n)
	case reflect.Float64:
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return errors.New("not a number")
		}
		fv.SetFloat(f)
	case reflect.Slice:
		if fv.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("unsupported slice type %s", fv.Type())
		}
		var parts []string
		for p := range strings.SplitSeq(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				parts = append(parts, p)
			}
		}
		fv.Set(reflect.ValueOf(parts))
	default:
		return fmt.Errorf("unsupported type %s", fv.Type())
	}
	return nil
}

// Duration is a time.Duration written as a Go duration string ("5s", "1m30s")
// in JSON files and environment variables.
type Duration time.Duration

// D returns the time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return errors.New("not a duration (use forms like 5s, 250ms, 1m30s)")
	}
	*d = Duration(v)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }
