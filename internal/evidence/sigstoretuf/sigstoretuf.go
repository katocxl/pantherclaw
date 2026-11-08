// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sigstoretuf fetches Sigstore's trust material through The Update
// Framework (G0 M35 D1040, FQ35-4, HR-780): trusted_root.json, and the
// signing configuration when the repository has one, from Sigstore's TUF
// repository, checked by the go-tuf v2 client from a root.json embedded
// here. It is the only user of go-tuf, and does nothing else with it.
//
// The embedded root.json is version 14 of Sigstore's public-good root
// (https://tuf-repo-cdn.sigstore.dev), copied unchanged from
// github.com/sigstore/sigstore-go v1.3.0, pkg/tuf/repository/root.json
// (Apache-2.0), whose module checksum the Go checksum database records;
// SHA-256 a0dfcc5d51c1ce4a66b541a3fff0afa97225ccc40456b21140bb2e2f113122e2.
// The client walks the root chain from it to the current root on every
// refresh, so an older embedded root is enough; it never trusts a root a
// signature chain from it does not reach.
//
// Every download goes through the caller's HTTP client (the M1 egress
// client: no redirects, the connected address checked) and only over https
// to the repository's own host. Any failure fails closed: no trust
// material is returned, and the caller keeps what it had.
package sigstoretuf

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

// DefaultRepository is Sigstore's public-good TUF repository.
const DefaultRepository = "https://tuf-repo-cdn.sigstore.dev"

// Target names in Sigstore's repository.
const (
	TrustedRootTarget   = "trusted_root.json"
	SigningConfigTarget = "signing_config.v0.2.json"
)

// requestTimeout bounds one download.
const requestTimeout = 30 * time.Second

//go:embed root.json
var embeddedRoot []byte

// EmbeddedRoot returns the embedded Sigstore root.json.
func EmbeddedRoot() []byte { return append([]byte(nil), embeddedRoot...) }

// ErrNotHTTPS reports a repository URL that is not an https URL.
var ErrNotHTTPS = errors.New("sigstoretuf: the repository must be an https URL")

// ErrHostNotAllowed reports a download from another host than the
// repository's.
var ErrHostNotAllowed = errors.New("sigstoretuf: download from a host other than the repository")

// Doer sends HTTP requests.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client fetches Sigstore trust material from one TUF repository.
type Client struct {
	// Repository is the repository's https base URL (DefaultRepository when
	// empty).
	Repository string
	// CacheDir keeps the verified metadata and targets between runs (the
	// subdirectory of the repository's host); empty: nothing is cached.
	CacheDir string
	// Root is the initial trusted root.json (EmbeddedRoot when nil).
	Root []byte
	// HTTP sends the requests.
	HTTP Doer
}

// Material is what one refresh fetched and verified.
type Material struct {
	TrustedRoot []byte
	// SigningConfig is nil when the repository has none.
	SigningConfig []byte
}

func (c *Client) repository() (*url.URL, error) {
	repo := c.Repository
	if repo == "" {
		repo = DefaultRepository
	}
	u, err := url.Parse(repo)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrNotHTTPS
	}
	return u, nil
}

// Fetch runs a full TUF refresh (root, timestamp, snapshot, targets) and
// returns the verified trusted_root.json and signing configuration.
func (c *Client) Fetch(ctx context.Context) (Material, error) {
	repo, err := c.repository()
	if err != nil {
		return Material{}, err
	}
	if c.HTTP == nil {
		return Material{}, errors.New("sigstoretuf: no HTTP client")
	}
	root := c.Root
	if root == nil {
		root = EmbeddedRoot()
	}
	base := strings.TrimSuffix(repo.String(), "/")
	cfg, err := config.New(base, root)
	if err != nil {
		return Material{}, fmt.Errorf("sigstoretuf: %w", err)
	}
	cfg.Fetcher = &fetcher{ctx: ctx, host: repo.Host, http: c.HTTP}
	if c.CacheDir == "" {
		cfg.DisableLocalCache = true
	} else {
		dir := filepath.Join(c.CacheDir, safeName(repo.Host))
		cfg.LocalMetadataDir, cfg.LocalTargetsDir = dir, filepath.Join(dir, "targets")
	}
	up, err := updater.New(cfg)
	if err != nil {
		return Material{}, fmt.Errorf("sigstoretuf: %w", err)
	}
	if err := up.Refresh(); err != nil {
		return Material{}, fmt.Errorf("sigstoretuf: refresh: %w", err)
	}
	var m Material
	if m.TrustedRoot, err = target(up, TrustedRootTarget); err != nil {
		return Material{}, err
	}
	// The signing configuration is a top-level target when the repository
	// has one.
	if _, ok := up.GetTopLevelTargets()[SigningConfigTarget]; ok {
		if m.SigningConfig, err = target(up, SigningConfigTarget); err != nil {
			return Material{}, err
		}
	}
	return m, nil
}

// target returns a verified target, from the cache when it is current.
func target(up *updater.Updater, name string) ([]byte, error) {
	ti, err := up.GetTargetInfo(name)
	if err != nil {
		return nil, fmt.Errorf("sigstoretuf: target %s: %w", name, err)
	}
	if path, b, err := up.FindCachedTarget(ti, ""); err == nil && path != "" {
		return b, nil
	}
	_, b, err := up.DownloadTarget(ti, "", "")
	if err != nil {
		return nil, fmt.Errorf("sigstoretuf: target %s: %w", name, err)
	}
	return b, nil
}

// safeName turns a host into a directory name.
func safeName(host string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		}
		return '_'
	}, host)
}

// fetcher is go-tuf's fetcher on the caller's HTTP client, limited to the
// repository's host over https.
type fetcher struct {
	ctx  context.Context //nolint:containedctx // go-tuf's Fetcher interface takes no context
	host string
	http Doer
}

// DownloadFile implements go-tuf's fetcher.Fetcher.
func (f *fetcher) DownloadFile(urlPath string, maxLength int64, _ time.Duration) ([]byte, error) {
	u, err := url.Parse(urlPath)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, f.host) {
		return nil, ErrHostNotAllowed
	}
	ctx, cancel := context.WithTimeout(f.ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, &metadata.ErrDownload{Msg: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &metadata.ErrDownloadHTTP{StatusCode: resp.StatusCode, URL: u.String()}
	}
	if maxLength <= 0 {
		return nil, &metadata.ErrDownloadLengthMismatch{Msg: "no length limit"}
	}
	if resp.ContentLength > maxLength {
		return nil, &metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("%s is larger than %d bytes", u.Path, maxLength)}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxLength+1))
	if err != nil {
		return nil, &metadata.ErrDownload{Msg: err.Error()}
	}
	if int64(len(b)) > maxLength {
		return nil, &metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("%s is larger than %d bytes", u.Path, maxLength)}
	}
	return b, nil
}
