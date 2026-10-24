#!/usr/bin/env python3
"""Check that the three C2 components pin the same shared submodule commits."""

import argparse
import subprocess
import sys
from pathlib import Path


SHARED = (
    "core",
    "libs/libDns",
    "libs/libSocketHandler",
    "libs/libSocks5",
    "thirdParty/donut",
    "thirdParty/base64",
)


def gitlink(repo: Path, path: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "HEAD", "--", path],
        check=True,
        capture_output=True,
        text=True,
    )
    fields = result.stdout.split()
    if len(fields) < 4 or fields[0] != "160000" or fields[1] != "commit":
        raise ValueError(f"{repo}: missing submodule gitlink {path}")
    return fields[2]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("teamserver", type=Path)
    parser.add_argument("windows_implant", type=Path)
    parser.add_argument("linux_implant", type=Path)
    args = parser.parse_args()
    repos = {
        "TeamServer": args.teamserver.resolve(),
        "Windows": args.windows_implant.resolve(),
        "Linux": args.linux_implant.resolve(),
    }

    failed = False
    for path in SHARED:
        commits = {name: gitlink(repo, path) for name, repo in repos.items()}
        aligned = len(set(commits.values())) == 1
        print(f"{'OK' if aligned else 'MISMATCH'} {path}")
        if not aligned:
            failed = True
            for name, commit in commits.items():
                print(f"  {name}: {commit}")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (subprocess.CalledProcessError, ValueError) as exc:
        print(exc, file=sys.stderr)
        sys.exit(2)
