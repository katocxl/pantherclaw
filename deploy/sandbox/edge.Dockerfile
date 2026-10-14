# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# The containment sandbox's edge (G0 M9 design decision 10). Built locally by
# `task sandbox:images` from a static Linux build of cmd/pantherclaw-edge and
# referenced by its image id; the base is pinned by digest (docker.BaseImage).
FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY pantherclaw-edge /pantherclaw-edge
USER 65530:65530
ENTRYPOINT ["/pantherclaw-edge"]
