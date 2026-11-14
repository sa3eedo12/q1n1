#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Builds the stick tree for the Surface Pro 11 payload runner (docs/SP11-PAYLOAD.md).

    python3 tools/sp11_payload_manifest.py --out-dir build/stick build/uefi/payloads/state.bin [more.bin ...]

The first file is the payload; any further files are data it can find through the preload table. The tool
writes <out-dir>/SP11/PAYLOAD.MAN (a Q1N1PLD1 manifest, tools/preload.py's format, listing each file's size
and SHA-256) and copies every file to <out-dir>/SP11/ under its name in capitals, and prints the names to
copy to the stick and the one command to run. Nothing is written outside --out-dir. The manifest holds no
host path and no machine identifier: only the stick names, the sizes and the digests.

The limits are the runner's (platform/uefi/sp11-payload.h): at most five files, because slbounce takes eight
declared ranges and the image, the memory map and the preload table use three; each file at most 256 MiB,
because slbounce splits a range into at most 256 chunks of 1 MiB; and names in 8.3 form, so that no FAT
long-name alias can be in question."""
import argparse
import hashlib
from pathlib import Path
import re
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import preload  # noqa: E402  (tools/preload.py: the manifest format and its path rules)

STICK_DIR = 'SP11'
MANIFEST_NAME = 'PAYLOAD.MAN'
RUNNER_NAME = 'Q1N1-PAYLOAD.EFI'
SLBOUNCE_COUNT_BASE = 8      # SP11_EBS_MAX_RANGES
BASE_RANGES = 3              # the image, the memory-map buffer and the preload table
MAX_FILES = SLBOUNCE_COUNT_BASE - BASE_RANGES
MAX_FILE_BYTES = 256 << 20   # 256 chunks of the 1 MiB chunk cap
NAME = re.compile(r'^[A-Z0-9_-]{1,8}\.[A-Z0-9_-]{1,3}$')


def stick_name(local):
    """The name a local file takes on the stick: its base name in capitals, which must be 8.3."""
    name = Path(local).name.upper()
    if not NAME.match(name):
        raise ValueError(f'{Path(local).name!r} cannot be a stick name: use up to 8 letters, digits, _ or -, a '
                         'dot and up to 3 more')
    if name == MANIFEST_NAME:
        raise ValueError(f'{name} is reserved for the manifest')
    return name


def build(paths):
    """(manifest bytes, [(stick path, size, sha256 hex, local path)]) for the files, payload first."""
    paths = [Path(p) for p in paths]
    if not 1 <= len(paths) <= MAX_FILES:
        raise ValueError(f'the runner takes 1 to {MAX_FILES} files, not {len(paths)}')
    entries = []
    for index, local in enumerate(paths):
        if not local.is_file():
            raise ValueError(f'{local} is not a file')
        size = local.stat().st_size
        if not 0 < size <= MAX_FILE_BYTES:
            raise ValueError(f'{local} must be between 1 byte and {MAX_FILE_BYTES} bytes, not {size}')
        if index == 0 and size < 4:
            raise ValueError(f'the payload {local} is shorter than one instruction')
        data = local.read_bytes()
        if len(data) != size:
            raise ValueError(f'{local} changed while it was being read')
        entries.append((f'\\{STICK_DIR}\\{stick_name(local)}', len(data), hashlib.sha256(data).hexdigest(), local))
    # preload.manifest also refuses a duplicate name (without regard to case) and a total over 4 GiB.
    return preload.manifest([e[:3] for e in entries]), entries


def write_tree(out_dir, paths):
    """Writes the manifest and the copies below out_dir/SP11 and returns the entries."""
    manifest, entries = build(paths)
    target = Path(out_dir) / STICK_DIR
    target.mkdir(parents=True, exist_ok=True)
    (target / MANIFEST_NAME).write_bytes(manifest)
    for stick_path, _, _, local in entries:
        shutil.copyfile(local, target / stick_path.rsplit('\\', 1)[1])
    return entries


def instructions(entries):
    lines = ['Copy these to the stick, keeping the SP11 directory (the runner image only once):']
    lines += [f'  {STICK_DIR}\\{MANIFEST_NAME}']
    lines += [f'  {path[1:]}    {size} bytes  SHA-256 {digest[:16].upper()}...' for path, size, digest, _ in entries]
    lines += [f'  {STICK_DIR}\\{RUNNER_NAME}    (build: make PAYLOAD=1 payload-runner; see docs/SP11-PAYLOAD.md)',
              'Then, from the UEFI Shell, with slbounce already loaded as for q1n1:',
              f'  {STICK_DIR}\\{RUNNER_NAME} --el2']
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('files', nargs='+', type=Path, metavar='FILE', help='the payload, then its data files')
    args = parser.parse_args(argv)
    try:
        entries = write_tree(args.out_dir, args.files)
    except ValueError as error:
        print(f'sp11_payload_manifest: {error}', file=sys.stderr)
        return 1
    print(instructions(entries))
    return 0


if __name__ == '__main__':
    sys.exit(main())
