// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package kube

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/kube/labels"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// MaxResponse caps an API server response (a pod object is a few KiB).
const MaxResponse = 1 << 20

// ErrUnavailable reports a cluster that could not be asked; attestation
// then fails closed.
var ErrUnavailable = errors.New("kube: cluster unavailable")

type cluster struct {
	cfg    ClusterConfig
	client *http.Client
	token  *tokenFile
}

// Client calls TokenReview and reads pods in configured clusters, each
// through an egress client with the cluster's CA pinned and only its own
// private ranges allowed (HR-142).
type Client struct {
	clusters map[string]cluster
}

// NewClient reads each cluster's CA and credential files. The credential
// file is read again while the server runs, so a rotated token needs no
// restart.
func NewClient(dir *Directory, timeout time.Duration) (*Client, error) {
	return newClient(dir, timeout, clock.System{})
}

func newClient(dir *Directory, timeout time.Duration, clk clock.Clock) (*Client, error) {
	c := &Client{clusters: map[string]cluster{}}
	if dir == nil {
		return c, nil
	}
	for name, cfg := range dir.clusters {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("kubernetes cluster %q: ca_file: %w", name, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kubernetes cluster %q: ca_file holds no certificate", name)
		}
		tok, err := readTokenFile(cfg.TokenFile, clk)
		if err != nil {
			return nil, fmt.Errorf("kubernetes cluster %q: %w", name, err)
		}
		c.clusters[name] = cluster{cfg: cfg, token: tok, client: httpx.NewEgressClient(httpx.EgressConfig{
			Timeout: timeout, RootCAs: pool, AllowedPrefixes: cfg.Prefixes(),
		})}
	}
	return c, nil
}

func (c *Client) cluster(name string) (cluster, error) {
	cl, ok := c.clusters[name]
	if !ok {
		return cluster{}, fmt.Errorf("%w: %q is not configured", ErrUnavailable, name)
	}
	return cl, nil
}

func (cl cluster) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(cl.cfg.APIServer, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+string(cl.token.get().Reveal()))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cl.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil || len(raw) > MaxResponse {
		return fmt.Errorf("%w: response too large or unreadable", ErrUnavailable)
	}
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	}
	return json.Unmarshal(raw, out)
}

var errNotFound = errors.New("kube: not found")

// Review asks the cluster's TokenReview API whether token is valid for
// audience (the org's pantherclaw:<org>).
func (c *Client) Review(ctx context.Context, clusterName, token, audience string) (issuers.TokenReview, error) {
	cl, err := c.cluster(clusterName)
	if err != nil {
		return issuers.TokenReview{}, err
	}
	in := map[string]any{
		"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
		"spec": map[string]any{"token": token, "audiences": []string{audience}},
	}
	var out struct {
		Status struct {
			Authenticated bool     `json:"authenticated"`
			Audiences     []string `json:"audiences"`
			User          struct {
				Username string              `json:"username"`
				UID      string              `json:"uid"`
				Extra    map[string][]string `json:"extra"`
			} `json:"user"`
		} `json:"status"`
	}
	if err := cl.do(ctx, http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", in, &out); err != nil {
		return issuers.TokenReview{}, err
	}
	first := func(k string) string {
		if v := out.Status.User.Extra[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	return issuers.TokenReview{
		Authenticated: out.Status.Authenticated, Audiences: out.Status.Audiences, Username: out.Status.User.Username,
		UID: out.Status.User.UID, PodName: first("authentication.kubernetes.io/pod-name"),
		PodUID: first("authentication.kubernetes.io/pod-uid"),
	}, nil
}

// Pod reads one pod. A missing pod is returned as an empty Pod, which no
// binding matches.
func (c *Client) Pod(ctx context.Context, clusterName, namespace, name string) (issuers.Pod, error) {
	cl, err := c.cluster(clusterName)
	if err != nil {
		return issuers.Pod{}, err
	}
	var out struct {
		Metadata struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
			UID       string `json:"uid"`
		} `json:"metadata"`
		Spec struct {
			InitContainers []struct {
				Name          string `json:"name"`
				RestartPolicy string `json:"restartPolicy"`
			} `json:"initContainers"`
		} `json:"spec"`
		Status struct {
			Phase             string `json:"phase"`
			ContainerStatuses []struct {
				ImageID string `json:"imageID"`
			} `json:"containerStatuses"`
			InitContainerStatuses []struct {
				Name    string `json:"name"`
				ImageID string `json:"imageID"`
			} `json:"initContainerStatuses"`
		} `json:"status"`
	}
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(name)
	if err := cl.do(ctx, http.MethodGet, path, nil, &out); errors.Is(err, errNotFound) {
		return issuers.Pod{}, nil
	} else if err != nil {
		return issuers.Pod{}, err
	}
	p := issuers.Pod{Namespace: out.Metadata.Namespace, Name: out.Metadata.Name, UID: out.Metadata.UID, Phase: out.Status.Phase}
	for _, cs := range out.Status.ContainerStatuses {
		p.ImageIDs = append(p.ImageIDs, cs.ImageID)
	}
	// The edge's native sidecar, if the pod runs one (G0 M32 D1218 H1).
	for _, ic := range out.Spec.InitContainers {
		if ic.Name == labels.EdgeContainer && ic.RestartPolicy == "Always" {
			p.Edge = &issuers.PodEdge{}
			for _, s := range out.Status.InitContainerStatuses {
				if s.Name == ic.Name {
					p.Edge.ImageID = s.ImageID
				}
			}
		}
	}
	return p, nil
}
