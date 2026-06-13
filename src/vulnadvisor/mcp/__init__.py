# File: src/vulnadvisor/mcp/__init__.py
"""VulnAdvisor MCP server: agent-native, fully-offline triage of local scan results.

This package exposes the local scan engine to any Model Context Protocol client (Claude Code,
Cursor, ...) over a stdio server. It has no platform dependency: ``scan(path)`` runs the same
deterministic engine the CLI uses, persists the result to a small local SQLite store, and the
other tools read that "last report" back — so an editor agent can ask "what's reachable here and
why" and get engine truth, with zero network beyond the public vuln APIs a scan already uses.

The third-party ``mcp`` SDK is imported only in :mod:`vulnadvisor.mcp.server`; :mod:`tools`,
:mod:`state`, and :mod:`session` are pure and importable without the optional ``[mcp]`` extra.
"""
