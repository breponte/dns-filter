#!/usr/bin/env python3
"""Clean blocked.txt in place: strip # comments, whitespace, empty lines, and '.'."""

import os
import re
import tempfile
from pathlib import Path

PATH = Path("blocked.txt")


def clean_line(line: str) -> str:
    line = line.split("#", 1)[0]       # drop comment (full-line or inline)
    line = re.sub(r"\s+", "", line)    # remove all whitespace
    return line.replace(".", "")       # remove all dots


def main() -> None:
    cleaned = []
    with PATH.open(encoding="utf-8") as f:
        for raw in f:
            line = clean_line(raw)
            if line:                   # skip lines that ended up empty
                cleaned.append(line)

    # Write to a temp file in the same directory, then atomically swap it in,
    # so a crash mid-write can't leave you with a truncated blocked.txt.
    fd, tmp = tempfile.mkstemp(dir=PATH.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(cleaned) + ("\n" if cleaned else ""))
        os.replace(tmp, PATH)
    except BaseException:
        os.unlink(tmp)
        raise


if __name__ == "__main__":
    main()