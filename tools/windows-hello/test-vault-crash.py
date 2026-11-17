#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Kill only an owned dummy-profile probe, then verify mount withdrawal."""

import argparse
import ctypes
import os
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--test-root", type=Path, required=True)
    parser.add_argument("--test-recovery-fixture", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "nt" or not args.test_root.name.startswith("TestVault-"):
        parser.error("Requires Windows and an explicit TestVault-* dummy root")
    drives = ctypes.windll.kernel32.GetLogicalDrives
    def mounted():
        return bool(drives() & (1 << 25))

    if mounted():
        raise RuntimeError("Z: must be free before this test")
    marker = args.test_root.resolve() / "mount-ready"
    marker.unlink(missing_ok=True)
    process = subprocess.Popen(
        [str(args.probe), "--hold", str(args.runtime), str(args.test_root),
         str(args.test_recovery_fixture)],
        creationflags=subprocess.CREATE_NO_WINDOW,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 600
        while not marker.exists():
            if process.poll() is not None:
                raise RuntimeError(f"Probe exited before mount: {process.returncode}")
            if time.monotonic() > deadline:
                raise RuntimeError("Timed out waiting for the dummy profile")
            time.sleep(0.1)
        if not mounted():
            raise RuntimeError("Ready marker exists, but Z: is absent")
        process.kill()
        process.wait(timeout=10)
        deadline = time.monotonic() + 20
        while mounted() and time.monotonic() < deadline:
            time.sleep(0.1)
        if mounted():
            raise RuntimeError("Z: remained mounted after its owner was killed")
        print("Owned parent killed; its encrypted drive was withdrawn.")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        marker.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
