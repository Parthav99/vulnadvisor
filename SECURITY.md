# Security Policy

This policy covers vulnerabilities **in the VulnAdvisor tool itself** (the CLI and its analysis
code) — not vulnerabilities in the third-party packages it scans. For a finding you believe
VulnAdvisor wrongly marked safe, open a [Suspected false negative](../../issues/new?template=false_negative.yml)
issue instead.

## Supported versions

The latest released `1.x` version receives security fixes.

## Reporting a vulnerability

Please report privately using GitHub's [**Report a vulnerability**](../../security/advisories/new)
flow (Security → Advisories). Do not open a public issue for an undisclosed vulnerability.

Include, where possible:

- the VulnAdvisor version (`vulnadvisor --version`),
- a minimal reproduction and the impact,
- any suggested remediation.

We aim to acknowledge within a few days and to coordinate disclosure once a fix is available.

## Scope and design guarantees

VulnAdvisor is built to be safe to run on untrusted code:

- It **analyzes** Python via the `ast` module; it does **not import or execute** the project under
  analysis.
- It runs **locally** and sends source code nowhere. Network calls go only to public advisory/risk
  APIs (OSV, EPSS, GHSA, CISA KEV) and, if you opt in, your own LLM provider with your own key.
- There is **no telemetry**.

A break in any of these properties (e.g. a path that causes analyzed code to execute, or source
content leaving the machine without consent) is a security issue — please report it.
