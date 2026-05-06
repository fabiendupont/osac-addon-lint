"""CLI entry point for osac-addon-lint."""

import argparse
import sys
from pathlib import Path

from .linter import lint_collection


def main():
    parser = argparse.ArgumentParser(
        prog="osac-addon-lint",
        description="Validate an Ansible collection against the OSAC Add-On convention.",
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to the collection root (directory containing galaxy.yml)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors",
    )
    args = parser.parse_args()

    if not args.path.is_dir():
        print(f"Error: {args.path} is not a directory", file=sys.stderr)
        sys.exit(1)

    findings = lint_collection(args.path)

    errors = [f for f in findings if f.severity == "error"]
    warnings = [f for f in findings if f.severity == "warning"]

    for finding in findings:
        icon = "✗" if finding.severity == "error" else "⚠"
        print(f"  {icon} [{finding.check}] {finding.message}")
        if finding.path:
            print(f"    → {finding.path}")

    print()
    if errors:
        print(f"✗ {len(errors)} error(s), {len(warnings)} warning(s)")
        sys.exit(1)
    elif warnings and args.strict:
        print(f"✗ {len(warnings)} warning(s) (strict mode)")
        sys.exit(1)
    elif warnings:
        print(f"✓ Passed with {len(warnings)} warning(s)")
    else:
        print("✓ All checks passed")


if __name__ == "__main__":
    main()
