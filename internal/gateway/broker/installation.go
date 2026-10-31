// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
)

// ErrInstallationRead reports an installation whose permissions could not
// be read; what was read before stays as it was (G0 M9 F048, "not
// observed").
var ErrInstallationRead = errors.New("broker: the GitHub App installation could not be read")

// InstallationPermissions is what the connection's GitHub App installation
// holds, as GitHub reports it: the permissions its owner granted (name →
// level) and the repository selection ("all" or "selected"). It carries
// no token: the read uses the App's JWT, which never leaves the broker.
type InstallationPermissions struct {
	Permissions         map[string]string
	RepositorySelection string
}

// ReadInstallation reads the installation behind a github_app credential
// (GET /app/installations/{id}) with an App JWT signed by the opened key.
// It mints no installation token, so nothing it reads can reach an agent.
func ReadInstallation(ctx context.Context, s Sender, baseURL string, hosts []string, app domain.GitHubApp, now time.Time,
) (InstallationPermissions, error) {
	var out InstallationPermissions
	key, err := app.Key()
	if err != nil {
		return out, err
	}
	jwt, err := appJWT(key, app.Issuer, now)
	if err != nil {
		return out, err
	}
	defer clear(jwt)
	base, err := url.Parse(strings.TrimSuffix(baseURL, "/"))
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrInstallationRead, err)
	}
	res, err := send(ctx, s, base, hosts, http.MethodGet, "/app/installations/"+strconv.FormatInt(app.Installation, 10), nil, jwt)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrInstallationRead, err)
	}
	defer clear(res.Body)
	var body struct {
		ID                  int64             `json:"id"`
		Permissions         map[string]string `json:"permissions"`
		RepositorySelection string            `json:"repository_selection"`
	}
	if res.Status != http.StatusOK || json.Unmarshal(res.Body, &body) != nil || body.ID != app.Installation ||
		(body.RepositorySelection != "all" && body.RepositorySelection != "selected") {
		return out, fmt.Errorf("%w: status %d", ErrInstallationRead, res.Status)
	}
	if body.Permissions == nil {
		body.Permissions = map[string]string{}
	}
	out.Permissions, out.RepositorySelection = body.Permissions, body.RepositorySelection
	return out, nil
}

// ProbeApp asks GitHub who the App is (GET /app) with an App JWT signed by
// the opened key, for a key rotation (G0 M20 S20c, D253): its status, and
// whether the answer names the App the key was sealed for (its numeric id
// or client id). It mints nothing. A status of 0 with an error means no
// answer came.
func ProbeApp(ctx context.Context, s Sender, baseURL string, hosts []string, app domain.GitHubApp, now time.Time) (int, bool, error) {
	key, err := app.Key()
	if err != nil {
		return 0, false, err
	}
	jwt, err := appJWT(key, app.Issuer, now)
	if err != nil {
		return 0, false, err
	}
	defer clear(jwt)
	base, err := url.Parse(strings.TrimSuffix(baseURL, "/"))
	if err != nil {
		return 0, false, err
	}
	res, err := send(ctx, s, base, hosts, http.MethodGet, "/app", nil, jwt)
	if err != nil {
		return 0, false, err
	}
	defer clear(res.Body)
	var body struct {
		ID       int64  `json:"id"`
		ClientID string `json:"client_id"`
	}
	matches := res.Status == http.StatusOK && json.Unmarshal(res.Body, &body) == nil &&
		((body.ID > 0 && strconv.FormatInt(body.ID, 10) == app.Issuer) || (body.ClientID != "" && body.ClientID == app.Issuer))
	return res.Status, matches, nil
}

// ProbeInstallation reads the installation behind a key under rotation
// (GET /app/installations/{id}) with an App JWT signed by it, and returns
// GitHub's status; it mints nothing.
func ProbeInstallation(ctx context.Context, s Sender, baseURL string, hosts []string, app domain.GitHubApp, now time.Time) (int, error) {
	key, err := app.Key()
	if err != nil {
		return 0, err
	}
	jwt, err := appJWT(key, app.Issuer, now)
	if err != nil {
		return 0, err
	}
	defer clear(jwt)
	base, err := url.Parse(strings.TrimSuffix(baseURL, "/"))
	if err != nil {
		return 0, err
	}
	res, err := send(ctx, s, base, hosts, http.MethodGet, "/app/installations/"+strconv.FormatInt(app.Installation, 10), nil, jwt)
	if err != nil {
		return 0, err
	}
	clear(res.Body)
	return res.Status, nil
}
