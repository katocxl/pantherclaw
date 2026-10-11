// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package docker

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var localIDRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// BuildImage builds the image of dockerfile with dir as its context, with
// no network and no pull (its base is pinned by digest and already
// present), and returns its id, by which it is referenced. The sandbox's
// own images (edge, probe) are built this way (task sandbox:images).
func (c *Client) BuildImage(ctx context.Context, dockerfile, dir string, labels map[string]string) (string, error) {
	for _, p := range []string{dockerfile, dir} {
		if p == "" || strings.ContainsAny(p, "\r\n\x00") || !filepath.IsAbs(p) {
			return "", fmt.Errorf("%w: build path %q", ErrInvalid, p)
		}
	}
	l, err := labelArgs(labels)
	if err != nil {
		return "", err
	}
	args := append([]string{"build", "--quiet", "--pull=false", "--network", "none", "--file", dockerfile}, l...)
	out, err := c.r.Run(ctx, append(args, dir)...)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(out))
	if !localIDRE.MatchString(id) {
		return "", fmt.Errorf("docker build: unexpected id %q", id)
	}
	return id, nil
}

// RemoveImage removes a local image the sandbox built, by its id.
func (c *Client) RemoveImage(ctx context.Context, id string) error {
	if !localIDRE.MatchString(id) {
		return fmt.Errorf("%w: image id %q", ErrInvalid, id)
	}
	_, err := c.r.Run(ctx, "image", "rm", id)
	return err
}
