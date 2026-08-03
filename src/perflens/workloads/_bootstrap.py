"""Trusted wait-then-exec bootstrap used by the unprivileged workload runner."""

from __future__ import annotations

import os
import sys


def main() -> None:
    if len(sys.argv) < 4:
        raise SystemExit(125)
    try:
        release_fd = int(sys.argv[1])
        ready_fd = int(sys.argv[2])
    except ValueError as exc:
        raise SystemExit(125) from exc
    executable = sys.argv[3]
    arguments = sys.argv[4:]
    try:
        os.write(ready_fd, b"R")
        os.close(ready_fd)
        released = os.read(release_fd, 1)
        os.close(release_fd)
        if released != b"1":
            raise SystemExit(125)
        os.execv(  # noqa: S606 - parent canonicalizes an in-project executable before launch
            executable,
            [executable, *arguments],
        )
    except OSError as exc:
        raise SystemExit(126) from exc


if __name__ == "__main__":
    main()
