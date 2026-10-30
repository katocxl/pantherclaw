// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ecsfacts reads the Amazon ECS fact pc.aws.ecs names (G0 M20 D284):
// a service's deployment controller. ECS reports a rollout's state only for
// its own controller, so a deploy under another one cannot be verified and
// is CANNOT_AUTHORIZE (VERIFIER_UNSUPPORTED, HR-191). It never guesses: an
// answer that names no controller is unread, so the decision sees the fact
// missing (HR-160), never ECS.
package ecsfacts

import (
	"regexp"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// ServiceController is the fact a deploy's prerequisite and its consequence
// rule name.
const ServiceController = "aws.ecs.service.controller"

// controllerPointer is where DescribeServices names the controller.
const controllerPointer = "/services/0/deploymentController/type"

var controllerRe = regexp.MustCompile(`^[A-Z_]{1,32}$`)

// Parse reads the fact from a DescribeServices answer of one service.
func Parse(status int, body []byte) map[string]any {
	if status < 200 || status >= 300 {
		return Unread("ECS did not answer")
	}
	kind, ok := defs.PointerValue(body, controllerPointer)
	if !ok || !controllerRe.MatchString(kind) {
		return Unread("ECS named no deployment controller for the service")
	}
	return map[string]any{"type": kind}
}

// Unread is the fact's value when it could not be read.
func Unread(why string) map[string]any { return map[string]any{"unread": why} }
