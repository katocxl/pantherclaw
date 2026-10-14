# The connector tests' image: pantherclaw-sim (mcp --stdio) on the pinned
# base, as a third-party stdio MCP server's image would be.
FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY pantherclaw-sim /pantherclaw-sim
