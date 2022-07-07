#!/usr/bin/env python3

import sys
from pathlib import Path

key_lol = bytes.fromhex("331e1e8fe458ab4506d02c05ca008c46")

def strip_header(path):
    should_strip = False
    with path.open("rb") as f:
        header = f.read(16)
        if header == key_lol:
            should_strip = True

    if should_strip:
        backup_path = Path(f"{path}.backup")
        path.rename(backup_path)
        with backup_path.open("rb") as original_file:
            with path.open("wb") as stripped_file:
                stripped_file.write(original_file.read()[16:])

        print(f"stripped {path}")
    else:
        print(f"skipped {path}")

    return should_strip

def main():
    input_dir = Path(sys.argv[1])

    for p in input_dir.rglob("*"):
        if not p.is_dir():
            strip_header(p)

if __name__ == "__main__":
    main()