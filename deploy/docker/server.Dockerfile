# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# The pantherclaw-server image (G0 M13 D7, HR-374): a static build from the
# pinned Go toolchain (the Taskfile's GOLANG_IMAGE) on distroless static,
# non-root, with no shell. Multi-arch through buildx:
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --build-arg VERSION=v0.2.0 --build-arg COMMIT=$(git rev-parse HEAD) \
#     --build-arg DATE=$(git log -1 --format=%cI) \
#     -f deploy/docker/server.Dockerfile -t pantherclaw-server .
#
# Distroless has no curl: the orchestrator probes GET /readyz (HR-370).
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
      -o /out/pantherclaw-server ./cmd/pantherclaw-server

# gcr.io/distroless/static-debian12, pinned by digest (as docker.BaseImage).
FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/pantherclaw-server /pantherclaw-server
# distroless's nonroot user.
USER 65532:65532
ENTRYPOINT ["/pantherclaw-server"]
CMD ["serve"]
