"""Small offline secret scanner used as a fallback by the pre-commit hook."""

import re
import subprocess
import sys
from pathlib import Path

PATTERNS = {
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "assigned credential": re.compile(
        r"(?i)\b(?:api[_-]?key|client[_-]?secret|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    ),
}

SKIPPED_SUFFIXES = {".csv", ".json", ".xml", ".png", ".jpg", ".zip"}


def find_secrets(text: str) -> list[str]:
    """Return the names of credential patterns found in text."""
    return [name for name, pattern in PATTERNS.items() if pattern.search(text)]


def staged_files() -> list[str]:
    completed = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in completed.stdout.splitlines() if line]


def staged_content(path: str) -> str:
    completed = subprocess.run(
        ["git", "show", f":{path}"], check=True, capture_output=True
    )
    return completed.stdout.decode("utf-8", errors="ignore")


def main() -> int:
    findings = []
    for path in staged_files():
        if Path(path).suffix.lower() in SKIPPED_SUFFIXES:
            continue
        for finding in find_secrets(staged_content(path)):
            findings.append(f"{path}: {finding}")

    if findings:
        print("Commit blocked: possible credentials detected:", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print("Secret scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
