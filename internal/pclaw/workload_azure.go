// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// azureMIToken asks the Azure managed identity endpoint for an access
// token for the Entra app appID (the resource), as clientID's
// user-assigned identity when it is set. App Service, Functions and
// Container Apps name their endpoint in IDENTITY_ENDPOINT and
// IDENTITY_HEADER; elsewhere the instance metadata service answers.
func azureMIToken(ctx context.Context, a *app, appID, clientID string) (string, error) {
	q := url.Values{"resource": {appID}}
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	endpoint, ok1 := a.env("IDENTITY_ENDPOINT")
	secret, ok2 := a.env("IDENTITY_HEADER")
	var u *url.URL
	header, value := "Metadata", "true"
	if ok1 && ok2 && endpoint != "" && secret != "" {
		var err error
		if u, err = url.Parse(endpoint); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return "", errors.New("IDENTITY_ENDPOINT must be an http URL")
		}
		q.Set("api-version", "2019-08-01")
		header, value = "X-IDENTITY-HEADER", secret
	} else {
		u = &url.URL{Scheme: "http", Host: "169.254.169.254", Path: "/metadata/identity/oauth2/token"}
		q.Set("api-version", "2018-02-01")
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(header, value)
	resp, err := a.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("azure managed identity: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("azure managed identity: status %d", resp.StatusCode)
	}
	var v struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &v); err != nil || v.AccessToken == "" {
		return "", errors.New("azure managed identity: no access token in the response")
	}
	return v.AccessToken, nil
}
