# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# The pantherclaw-host binary (G0 M19 D203): the host agent of a
# PantherClaw hosting host, a static build from the pinned Go toolchain.
# The agent drives the host's Docker engine through its CLI, so it runs as
# a host process (a systemd unit next to the engine), never inside one of
# the containers it starts; this file only builds the binary:
#
#   docker buildx build --platform linux/amd64 \
#     --build-arg VERSION=v0.2.0 --build-arg COMMIT=$(git rev-parse HEAD) \
#     --build-arg DATE=$(git log -1 --format=%cI) \
#     -f deploy/docker/host.Dockerfile --output type=local,dest=bin/host .
#
# A release build of it is a CI change for the founder (G0 M19, out of scope).
FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm@sha256:21ade014faf952365b9ecbd8dbdb87176fbacb82fac9fb132d9f2a7b8cc3f132 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOTOOLCHAIN=local go build -trimpath \
      -ldflags "-s -w -X github.com/katocxl/pantherclaw/internal/platform/version.version=${VERSION} -X github.com/katocxl/pantherclaw/internal/platform/version.commit=${COMMIT} -X github.com/katocxl/pantherclaw/internal/platform/version.date=${DATE}" \
      -o /out/pantherclaw-host ./cmd/pantherclaw-host

FROM scratch
COPY --from=build /out/pantherclaw-host /pantherclaw-host
