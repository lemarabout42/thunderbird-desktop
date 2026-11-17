#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Exercise the real recovery dialogs with a new, disposable dummy profile."""

import argparse
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--test-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.test_root.resolve()
    if os.name != "nt" or not root.name.startswith("TestVault-") or root.exists():
        parser.error("Requires Windows and a new explicit TestVault-* dummy root")
    command = [str(args.probe), "--interactive", str(args.runtime), str(root)]

    def run_probe():
        subprocess.run(command, creationflags=subprocess.CREATE_NO_WINDOW, check=True)
        if Path("Z:/").exists():
            raise RuntimeError("Z: was not withdrawn after the probe")

    print("Create dummy profile; keep and confirm the displayed recovery code.", flush=True)
    run_probe()
    envelope = root / "vault" / "hello.key"
    original = envelope.read_bytes()
    stable_id = original[8:24]
    backup = root / "vault" / "hello.key.test-backup"
    envelope.rename(backup)
    try:
        print("Protector metadata set aside; recover using your saved code.", flush=True)
        run_probe()
        recovered = envelope.read_bytes()
        if recovered[8:24] != stable_id or recovered[24:40] == original[24:40]:
            raise RuntimeError("Recovery did not preserve identity and rotate protector")
        print("Recovered original dummy mail/SQLite with a new Hello protector.", flush=True)
        print("Reopen through Hello to verify the committed replacement.", flush=True)
        run_probe()
    finally:
        if not envelope.exists():
            backup.rename(envelope)


if __name__ == "__main__":
    main()
