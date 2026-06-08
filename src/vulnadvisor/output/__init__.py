"""Output: JSON and SARIF emitters plus exit-code logic."""

from vulnadvisor.output.gating import (
    EXIT_FINDINGS,
    EXIT_OK,
    FailOn,
    parse_fail_on,
    should_fail,
)
from vulnadvisor.output.json_report import SCHEMA_VERSION, build_report, to_json
from vulnadvisor.output.remediation import fix_command
from vulnadvisor.output.sarif import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    build_sarif,
    to_sarif_json,
)

__all__ = [
    "EXIT_FINDINGS",
    "EXIT_OK",
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "SCHEMA_VERSION",
    "FailOn",
    "build_report",
    "build_sarif",
    "fix_command",
    "parse_fail_on",
    "should_fail",
    "to_json",
    "to_sarif_json",
]
