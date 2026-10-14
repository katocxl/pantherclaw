# The sandbox tests' agent image: the test agent on the pinned base.
FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY agent /agent
ENTRYPOINT ["/agent"]
