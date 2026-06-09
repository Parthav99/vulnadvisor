"""A tiny example app for the VulnAdvisor quickstart.

It imports and uses a vulnerable PyYAML API (``yaml.load`` on untrusted input), so VulnAdvisor
surfaces PyYAML's advisories as IMPORTED (with the import site). ``requests`` is declared in
requirements but never imported here, so its advisories are deprioritized (no path from your code)
- the noise reduction in action. Build the symbol dataset (``vulnadvisor backfill``) to upgrade
direct calls to the vulnerable symbol to IMPORTED-AND-CALLED with the full path.
"""

import yaml


def load_config(raw: str) -> object:
    """Parse a YAML document (intentionally using the unsafe loader for the demo)."""
    return yaml.load(raw)


def main() -> None:
    """Entry point that reaches the vulnerable call."""
    print(load_config("name: example\n"))


if __name__ == "__main__":
    main()
