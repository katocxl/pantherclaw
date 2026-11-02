// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package outofprocess is the content classifier adapter to a customer-run
// local service (G0 M27 D503, D507; F940). There is no third-party API
// adapter and no model in process: the operator runs a classifier beside the
// gateway and names it in the gateway's own configuration, so the server can
// never point a gateway's content at another address.
//
// The call is one POST of one bounded body:
//
//	{"surface":"result","location":"result","content_base64":"..."}
//
// and the answer is {"flags":[{"location":"result/a"}]}: a location or none,
// never a value. Whatever the service calls a flag is a classifier_flag, and
// any other answer is an error, which the scan makes a scan_incomplete
// (HR-650). The service's answer is inference, and only ever restricts.
package outofprocess

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/contentsignals/builtin"
	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	"github.com/katocxl/pantherclaw/internal/contentsignals/ports"
)

// maxAnswer bounds a classifier's answer.
const maxAnswer = 64 << 10

// clientTimeout is the client's own backstop, whatever the caller's context
// allows (D533): the scan's timeout is at most 5 s too.
const clientTimeout = 5 * time.Second

// ErrAddress refuses a classifier that is not on this machine or a private
// network, named by IP.
var ErrAddress = errors.New("outofprocess: the classifier URL must be http or https on a loopback or private IP address")

// CheckURL checks a classifier address: an IP literal, loopback or private,
// so content cannot leave for a name that resolves elsewhere (HR-649).
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return ErrAddress
	}
	ip, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]"))
	if err != nil || (!ip.IsLoopback() && !ip.IsPrivate()) {
		return ErrAddress
	}
	return nil
}

// Classifier calls the service.
type Classifier struct {
	url    string
	client *http.Client
}

var _ ports.ContentClassifier = (*Classifier)(nil)

// New returns a Classifier for a checked address. It follows no redirect and
// uses no proxy: the content goes to the named address or nowhere.
func New(raw string) (*Classifier, error) {
	if err := CheckURL(raw); err != nil {
		return nil, err
	}
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("outofprocess: no default transport")
	}
	t := tr.Clone()
	t.Proxy = nil
	return &Classifier{url: raw, client: &http.Client{
		Timeout:       clientTimeout,
		Transport:     t,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

type request struct {
	Surface  string `json:"surface"`
	Location string `json:"location"`
	Content  string `json:"content_base64"`
}

type flag struct {
	Location string `json:"location"`
}

type answer struct {
	Flags *[]flag `json:"flags"`
}

// Classify implements ports.ContentClassifier.
func (c *Classifier) Classify(ctx context.Context, in ports.Input) ([]domain.Finding, error) {
	body, err := json.Marshal(request{Surface: string(in.Surface), Location: in.Location, Content: base64.StdEncoding.EncodeToString(in.Content)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("outofprocess: status %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxAnswer+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxAnswer {
		return nil, errors.New("outofprocess: answer too long")
	}
	var a answer
	if err := json.Unmarshal(raw, &a, json.RejectUnknownMembers(true)); err != nil {
		return nil, errors.New("outofprocess: malformed answer")
	}
	if a.Flags == nil {
		return nil, errors.New("outofprocess: no flags member")
	}
	var out []domain.Finding
	for _, f := range *a.Flags {
		// A location that is not the built-in's own grammar may carry a
		// value: the location asked about stands in for it (D533, HR-649).
		loc := f.Location
		if !builtin.PlainLocation(in.Location, loc) {
			loc = in.Location
		}
		out = append(out, domain.Finding{Kind: domain.KindClassifierFlag, Location: loc})
	}
	return out, nil
}
