# Pi subagent extension provenance

This is a deliberately reduced, server-policy implementation derived from the
official Pi subagent example:

- Upstream: https://github.com/earendil-works/pi
- Source: `packages/coding-agent/examples/extensions/subagent/`
- Tag and commit: `v0.84.1` / `53fa77ccd8a279eb87e92294ef3687b03ff80112`
- License: MIT, Copyright (c) 2025 Mario Zechner

The upstream example supports user/project discovery and interactive project
agent confirmation. This Worker vendor retains the upstream isolated Pi child
process and bounded parallel scheduling model, but intentionally discovers only
the server-owned `PI_CODING_AGENT_DIR/agents` definitions. Project discovery,
project scopes, confirmations, workflow prompts, and recursive extensions are
not present.
