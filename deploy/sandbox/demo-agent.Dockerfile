# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# The demo agent of the v0.1.0 preview (quickstart guided tests, `task
# test:preview`). Built locally by `task sandbox:images` from a static Linux
# build of cmd/pantherclaw-demo-agent and referenced by its image id; the
# base is pinned by digest (docker.BaseImage). Not part of the release.
FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY pantherclaw-demo-agent /pantherclaw-demo-agent
ENTRYPOINT ["/pantherclaw-demo-agent"]
