// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ocsf

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
)

// Batch bounds (D36).
const (
	MaxBatchEvents = 100
	MaxBatchBytes  = 1 << 20
)

// BatchType is the Standard Webhooks type of an export batch.
const BatchType = "pantherclaw.ocsf.batch"

// ErrEventTooLarge reports a single event that does not fit in a batch.
var ErrEventTooLarge = errors.New("ocsf: an event is larger than a batch")

// batchBody is the body of one export request: the batch id and feed range
// (so a receiver can see gaps and duplicates) and the OCSF events.
type batchBody struct {
	Type string    `json:"type"`
	Data batchData `json:"data"`
}

type batchData struct {
	Batch   string           `json:"batch"`
	FromSeq int64            `json:"from_seq"`
	ToSeq   int64            `json:"to_seq"`
	Events  []jsontext.Value `json:"events"`
}

// Encode returns the deterministic JSON of one record.
func Encode(r Record) ([]byte, error) {
	return json.Marshal(r, json.Deterministic(true))
}

// Builder packs encoded records into one batch of at most MaxBatchEvents
// events and MaxBatchBytes bytes.
type Builder struct {
	events [][]byte
	size   int
}

// envelope is the bytes of the body around the events (generous).
const envelope = 256

// Add appends an encoded record; ok is false when the batch is full and
// the record was not added. A record that could never fit is an error.
func (b *Builder) Add(enc []byte) (bool, error) {
	if len(enc)+envelope > MaxBatchBytes {
		return false, ErrEventTooLarge
	}
	if len(b.events) == MaxBatchEvents || b.size+len(enc)+1+envelope > MaxBatchBytes {
		return false, nil
	}
	b.events = append(b.events, enc)
	b.size += len(enc) + 1
	return true, nil
}

// Len is the number of events.
func (b *Builder) Len() int { return len(b.events) }

// Body returns the request body of the batch id covering (from, to].
func (b *Builder) Body(id string, from, to int64) ([]byte, error) {
	d := batchData{Batch: id, FromSeq: from, ToSeq: to, Events: make([]jsontext.Value, 0, len(b.events))}
	for _, e := range b.events {
		d.Events = append(d.Events, e)
	}
	out, err := json.Marshal(batchBody{Type: BatchType, Data: d}, json.Deterministic(true))
	if err == nil && len(out) > MaxBatchBytes {
		return nil, ErrEventTooLarge
	}
	return out, err
}
