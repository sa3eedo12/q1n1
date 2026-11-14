#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Builds the stick tree for the Surface Pro 11 payload runner (docs/SP11-PAYLOAD.md).

    python3 tools/sp11_payload_manifest.py --out-dir build/stick build/uefi/payloads/state.bin [more files ...]

The files are the payloads and the data a payload can find through the preload table, in manifest order. A
file whose name ends in .BIN (in any case) is a payload: the runner calls it, one payload after the other in
the order given, in one boot. Any other file is data and is never called. The first file must be a payload.
The tool writes <out-dir>/SP11/PAYLOAD.MAN (a Q1N1PLD1 manifest, tools/preload.py's format, listing each
file's size and SHA-256) and copies every file to <out-dir>/SP11/ under its name in capitals, and prints the
names to copy to the stick, which of them will be called, and the one command to run. Nothing is written
outside --out-dir. The manifest holds no host path and no machine identifier: only the stick names, the
sizes and the digests. A stick with state.bin alone gets the manifest it always did.

The limits are the runner's (platform/uefi/sp11-payload.h): at most five files in all, because slbounce takes
eight declared ranges and the image, the memory map and the preload table use three; each file at most 256
MiB, because slbounce splits a range into at most 256 chunks of 1 MiB; and names in 8.3 form, so that no FAT
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
CODE_SUFFIX = '.BIN'         # the runner's rule (q1n1_payload_path_is_code): <stem>.BIN is called, anything else is data


def stick_name(local):
    """The name a local file takes on the stick: its base name in capitals, which must be 8.3."""
    name = Path(local).name.upper()
    if not NAME.match(name):
        raise ValueError(f'{Path(local).name!r} cannot be a stick name: use up to 8 letters, digits, _ or -, a '
                         'dot and up to 3 more')
    if name == MANIFEST_NAME:
        raise ValueError(f'{name} is reserved for the manifest')
    return name


def is_payload(name):
    """True for a stick name the runner will call. The 8.3 rule has already given it a non-empty stem."""
    return name.upper().endswith(CODE_SUFFIX)


def build(paths):
    """(manifest bytes, [(stick path, size, sha256 hex, local path, 'payload' or 'data')]), in the order given."""
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
        name = stick_name(local)
        kind = 'payload' if is_payload(name) else 'data'
        if index == 0 and kind != 'payload':
            raise ValueError(f'the first file {local.name!r} must be a payload: only files named *{CODE_SUFFIX} are called')
        if kind == 'payload' and size < 4:
            raise ValueError(f'the payload {local} is shorter than one instruction')
        data = local.read_bytes()
        if len(data) != size:
            raise ValueError(f'{local} changed while it was being read')
        entries.append((f'\\{STICK_DIR}\\{name}', len(data), hashlib.sha256(data).hexdigest(), local, kind))
    # preload.manifest also refuses a duplicate name (without regard to case) and a total over 4 GiB.
    return preload.manifest([e[:3] for e in entries]), entries


def write_tree(out_dir, paths):
    """Writes the manifest and the copies below out_dir/SP11 and returns the entries."""
    manifest, entries = build(paths)
    target = Path(out_dir) / STICK_DIR
    target.mkdir(parents=True, exist_ok=True)
    (target / MANIFEST_NAME).write_bytes(manifest)
    for stick_path, _, _, local, _ in entries:
        shutil.copyfile(local, target / stick_path.rsplit('\\', 1)[1])
    return entries


def instructions(entries):
    lines = ['Copy these to the stick, keeping the SP11 directory (the runner image only once):']
    lines += [f'  {STICK_DIR}\\{MANIFEST_NAME}']
    for index, (path, size, digest, _, kind) in enumerate(entries):
        role = 'payload, called in manifest order' if kind == 'payload' else 'data, never called'
        lines.append(f'  {path[1:]}    {size} bytes  SHA-256 {digest[:16].upper()}...  (INDEX={index}, {role})')
    lines += [f'  {STICK_DIR}\\{RUNNER_NAME}    (build: make PAYLOAD=1 payload-runner; see docs/SP11-PAYLOAD.md)',
              'Then, from the UEFI Shell, with slbounce already loaded as for q1n1:',
              f'  {STICK_DIR}\\{RUNNER_NAME} --el2']
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('files', nargs='+', type=Path, metavar='FILE',
                        help=f'payloads (*{CODE_SUFFIX}, called in this order; the first must be one) and data '
                             '(any other name, never called)')
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
