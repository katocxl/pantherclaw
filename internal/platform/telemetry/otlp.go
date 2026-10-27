// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/protobuf/proto"

	commonv1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/common/v1"
	resourcev1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/resource/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// OTLP/HTTP paths under the configured endpoint.
const (
	tracesPath  = "/v1/traces"
	metricsPath = "/v1/metrics"
	// ExportTimeout bounds one export request (G0 M13 D30).
	ExportTimeout = 10 * time.Second
	// maxResponseBytes is how much of a response body is read (and thrown
	// away) so the connection can be reused.
	maxResponseBytes = 64 << 10
)

// Header is one request header sent with every export (for example the
// Grafana Cloud basic authorization); its value is a secret.
type Header struct {
	Name  string
	Value pclog.Secret[string]
}

// client posts OTLP protobuf messages: application/x-protobuf, gzip, a 10 s
// timeout. It never logs a request or response body.
type client struct {
	endpoint string
	headers  []Header
	http     *http.Client
}

func newClient(endpoint string, headers []Header) *client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	tr.Proxy = nil
	return &client{endpoint: endpoint, headers: headers, http: &http.Client{
		Transport: tr, Timeout: ExportTimeout,
		// An export never follows a redirect: the headers carry credentials.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// errExport reports a failed export by its HTTP status only.
var errExport = errors.New("telemetry: OTLP export failed")

func (c *client) post(ctx context.Context, path string, m proto.Message) error {
	raw, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("telemetry: marshal: %w", err)
	}
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	if _, err := zw.Write(raw); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, ExportTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "gzip")
	for _, h := range c.headers {
		req.Header.Set(h.Name, h.Value.Reveal())
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// The endpoint carries no credentials (they are headers), so the
		// error may name it.
		return fmt.Errorf("%w: %w", errExport, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: HTTP %d", errExport, resp.StatusCode)
	}
	return nil
}

// resourceOf is the exported resource: the service name and version only.
func resourceOf(service, version string) *resourcev1.Resource {
	r := &resourcev1.Resource{Attributes: []*commonv1.KeyValue{strKV("service.name", service)}}
	if version != "" {
		r.Attributes = append(r.Attributes, strKV("service.version", version))
	}
	return r
}

func strKV(k, v string) *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: k, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: v}}}
}

// keyValues converts attributes that pass Filter (HR-380); the rest are
// dropped here too, whatever the caller recorded.
func keyValues(kvs []attribute.KeyValue) []*commonv1.KeyValue {
	var out []*commonv1.KeyValue
	for _, kv := range kvs {
		if !Filter(kv) {
			continue
		}
		v := &commonv1.AnyValue{}
		switch kv.Value.Type() { //nolint:exhaustive // Filter admits these four only
		case attribute.STRING:
			v.Value = &commonv1.AnyValue_StringValue{StringValue: kv.Value.AsString()}
		case attribute.BOOL:
			v.Value = &commonv1.AnyValue_BoolValue{BoolValue: kv.Value.AsBool()}
		case attribute.INT64:
			v.Value = &commonv1.AnyValue_IntValue{IntValue: kv.Value.AsInt64()}
		case attribute.FLOAT64:
			v.Value = &commonv1.AnyValue_DoubleValue{DoubleValue: kv.Value.AsFloat64()}
		}
		out = append(out, &commonv1.KeyValue{Key: string(kv.Key), Value: v})
	}
	return out
}

func unixNano(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.UnixNano())
}
