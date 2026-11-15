#!/usr/bin/env python3
"""Deterministic fake OpenCode executable for native-shadow harness tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _run() -> int:
    if sys.argv[1:] == ["--version"]:
        sys.stdout.write("fake-opencode-native-shadow 1.0\n")
        return 0
    if sys.argv[1:3] != ["run", "--auto"] or "--dir" not in sys.argv:
        sys.stderr.write("unsupported fake OpenCode invocation\n")
        return 2

    task = Path("TASK.md").read_text(encoding="utf-8")
    source = Path("src/slugify.py").read_text(encoding="utf-8")
    guidance = Path("AGENTS.md").read_text(encoding="utf-8")
    if "preserve Unicode letters" not in task or "return value" not in source:
        sys.stderr.write("frozen task or source was not supplied\n")
        return 3
    if "Synthetic repository guidance" not in guidance:
        sys.stderr.write("fixture guidance was not supplied\n")
        return 4

    shadow = Path(".farna-context/shadow/AGENTS.md")
    shadow_consumed = shadow.is_file() and "preserve Unicode letters" in shadow.read_text(
        encoding="utf-8"
    )
    if shadow.exists() and not shadow_consumed:
        sys.stderr.write("native shadow constraint was not readable\n")
        return 5

    if shadow_consumed:
        implementation = (
            '"""Unicode-aware slugification."""\n\n'
            "import re\n\n\n"
            "def slugify(value: str) -> str:\n"
            '    """Convert text to a lowercase hyphenated slug."""\n'
            '    return "-".join(re.findall(r"[^\\W_] +", value.lower(), flags=re.UNICODE))\n'
        ).replace("[^\\W_] +", "[^\\W_]+")
        tests = (
            "from src.slugify import slugify\n\n\n"
            "def test_slugify_ascii() -> None:\n"
            '    assert slugify("Hello, world!") == "hello-world"\n\n\n'
            "def test_slugify_preserves_unicode_letters() -> None:\n"
            '    assert slugify("café déjà vu") == "café-déjà-vu"\n\n\n'
            "def test_slugify_without_alphanumeric_characters() -> None:\n"
            '    assert slugify("---") == ""\n'
        )
    else:
        implementation = (
            "import re\n\n\n"
            "def slugify(value: str) -> str:\n"
            '    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")\n'
        )
        tests = (
            "from src.slugify import slugify\n\n\n"
            "def test_slugify_ascii() -> None:\n"
            '    assert slugify("Hello, world!") == "hello-world"\n\n\n'
            "def test_slugify_without_alphanumeric_characters() -> None:\n"
            '    assert slugify("---") == ""\n'
        )

    Path("src/slugify.py").write_text(implementation, encoding="utf-8")
    Path("tests/test_slugify.py").write_text(tests, encoding="utf-8")
    sys.stdout.write(
        json.dumps({"fake_mode": True, "native_shadow_consumed": shadow_consumed}) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_run())
