#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Refuses a payload ELF that could depend on the address the firmware loads it at.

    python3 tools/sp11_payload_elfcheck.py [--readelf llvm-readelf] build/uefi/payloads/state.elf

A payload (docs/SP11-PAYLOAD.md) is linked at 0 and flattened to a binary the firmware loads wherever it
finds room, so nothing in it may hold an address. The Makefile links with --emit-relocs, which keeps every
relocation the linker applied, and this reads them with llvm-readelf. It fails when the ELF

  * is not a static executable (a DYN or REL file is one a loader has to relocate);
  * has a dynamic, GOT, PLT, TLS or init-array section, or a program header that is not a load segment;
  * has any relocation whose type is not on the PC-relative list below, which is where an absolute
    pointer in a table, a movz/movk of an address and a GOT access all show up.

The ADD and LDST low-12 relocations are on the list although their names say ABS: they are the low half
of an ADRP pair and only the low twelve bits of the address are in them, which a page-aligned load
does not change. Exit status: 0 clean, 1 a problem was found, 2 the check itself could not run."""
import argparse
import re
import subprocess
import sys

PC_RELATIVE = {
    'R_AARCH64_CALL26', 'R_AARCH64_JUMP26', 'R_AARCH64_CONDBR19', 'R_AARCH64_TSTBR14',
    'R_AARCH64_LD_PREL_LO19', 'R_AARCH64_ADR_PREL_LO21', 'R_AARCH64_ADR_PREL_PG_HI21',
    'R_AARCH64_ADR_PREL_PG_HI21_NC', 'R_AARCH64_ADD_ABS_LO12_NC', 'R_AARCH64_LDST8_ABS_LO12_NC',
    'R_AARCH64_LDST16_ABS_LO12_NC', 'R_AARCH64_LDST32_ABS_LO12_NC', 'R_AARCH64_LDST64_ABS_LO12_NC',
    'R_AARCH64_LDST128_ABS_LO12_NC', 'R_AARCH64_PREL16', 'R_AARCH64_PREL32', 'R_AARCH64_PREL64',
}
FORBIDDEN_SECTIONS = {'.dynamic', '.dynsym', '.dynstr', '.interp', '.got', '.got.plt', '.plt', '.plt.got', '.tdata',
                      '.tbss', '.init_array', '.fini_array', '.preinit_array', '.data.rel.ro', '.rela.dyn',
                      '.rela.plt'}
ALLOWED_SEGMENTS = {'LOAD', 'GNU_STACK'}

SECTION = re.compile(r'^\s*\[\s*\d+\]\s+(.*)$')
RELOCATION = re.compile(r'^\s*([0-9a-fA-F]{8,16})\s+([0-9a-fA-F]{8,16})\s+(\S+)\s*(.*)$')


def run_readelf(readelf, elf):
    try:
        done = subprocess.run([readelf, '--wide', '--file-header', '--sections', '--program-headers',
                               '--relocations', str(elf)], capture_output=True, text=True)
    except OSError as error:
        raise RuntimeError(f'cannot run {readelf}: {error}') from error
    if done.returncode:
        raise RuntimeError(f'{readelf} failed on {elf}: {done.stderr.strip() or done.stdout.strip()}')
    return done.stdout


def parse(text):
    """(file type, machine, class, sections as (name, type, flags), segment types, relocations as
    (offset, type, rest))."""
    header = {}
    sections, segments, relocations = [], [], []
    in_segments = False
    for line in text.splitlines():
        found = re.match(r'^\s*(Class|Type|Machine):\s+(.*?)\s*$', line)
        if found and not in_segments:
            header.setdefault(found.group(1), found.group(2))
            continue
        if line.startswith('Program Headers:'):
            in_segments = True
            continue
        if in_segments and not line.strip():
            in_segments = False
        if in_segments:
            fields = line.split()
            if fields and fields[0] not in ('Type',):
                segments.append(fields[0])
            continue
        found = SECTION.match(line)
        if found:
            fields = found.group(1).split()
            # name type addr off size es [flags] lk inf al
            if len(fields) >= 9:
                flags = fields[6] if len(fields) == 10 else ''
                sections.append((fields[0], fields[1], flags))
            continue
        found = RELOCATION.match(line)
        if found and found.group(3).startswith('R_'):
            relocations.append((found.group(1), found.group(3), found.group(4)))
    return header, sections, segments, relocations


def problems(elf, readelf='llvm-readelf'):
    """The reasons `elf` cannot be loaded anywhere; an empty list means it can."""
    header, sections, segments, relocations = parse(run_readelf(readelf, elf))
    found = []
    if not header.get('Type', '').startswith('EXEC'):
        found.append(f'not a static executable: type {header.get("Type", "?")!r}')
    if 'AArch64' not in header.get('Machine', ''):
        found.append(f'not an AArch64 file: machine {header.get("Machine", "?")!r}')
    if header.get('Class') != 'ELF64':
        found.append(f'not a 64-bit file: class {header.get("Class", "?")!r}')
    if not sections:
        found.append('no section table was read')
    for name, kind, flags in sections:
        if name in FORBIDDEN_SECTIONS:
            found.append(f'section {name} needs a loader')
        elif kind in ('RELA', 'REL') and 'A' in flags:
            found.append(f'section {name} is a dynamic relocation section')
    for kind in segments:
        if kind not in ALLOWED_SEGMENTS:
            found.append(f'program header {kind} needs a loader')
    if not any(kind == 'LOAD' for kind in segments):
        found.append('no load segment was read')
    for offset, kind, rest in relocations:
        if kind not in PC_RELATIVE:
            found.append(f'relocation {kind} at 0x{int(offset, 16):x} ({rest.split()[0] if rest.split() else "?"}) '
                         'depends on the load address')
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--readelf', default='llvm-readelf')
    parser.add_argument('elf')
    args = parser.parse_args(argv)
    try:
        found = problems(args.elf, args.readelf)
    except RuntimeError as error:
        print(f'payload ELF check could not run: {error}', file=sys.stderr)
        return 2
    for text in found:
        print(f'{args.elf}: {text}', file=sys.stderr)
    if found:
        print(f'{args.elf}: NOT position independent; refusing to build a payload from it', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
