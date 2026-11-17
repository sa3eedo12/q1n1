# SPDX-License-Identifier: MIT
"""Helpers shared by the host tests and the QEMU test of the payload `xhci` (docs/SP11-PAYLOAD-XHCI.md): the files of the payload, the
policy its binary is held to, a builder of the native host harness and a builder of the payload binary, each from the tree it is given
(the real one, or a copy with a seeded bug). Writes only below the directories it is given. Hardware: NOT RUN."""
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402

PARTS = ('xhci', 'xhci-io', 'xhci-text', 'xhci-map', 'xhci-ctl', 'xhci-smmu', 'xhci-watch')
HEADERS = ('xhci-priv.h', 'xhci-regs.h')
CONTROLLERS = (0, 1)
HARNESS = ('test-q1n1-sp11-payload-xhci.c', 'test-q1n1-sp11-payload-xhci-cases.c', 'test-q1n1-sp11-payload-xhci-gates.c')
HARNESS_HEADER = 'test-q1n1-sp11-payload-xhci.h'
TIGHT_CAPS = (12, 16, 20, 24, 30)
TIGHT_LOAD_CAPS = (100, 300, 700, 1200)
# The simulator the harness includes has statics that a given build does not use, and a seeded bug may leave a variable unused.
SANITIZE = ['-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-function', '-Wno-unused-variable', '-Wno-unused-parameter', '-Wno-unused-but-set-variable']
GATES = ['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1', '-DQ1N1_PAYLOAD_HOST_TEST=1']
RUN_TIMEOUT = 300


def register_policies():
    """The binary of the payload is held to MRS of CurrentEL and CNTFRQ_EL0, DC CVAC and DC CIVAC (the two cache operations of its
    DMA buffers), DSB SY, no ISB, DMB or SMC. The form of DC CVAC is the shared allow-list's, added with the retention probe (retprobe):
    this module registers its two policies and nothing else of the shared module."""
    for controller in CONTROLLERS:
        lib.POLICIES[f'xhci{controller}'] = {
            'registers': {'currentel', 'cntfrq_el0'}, 'smc': 0, 'bytes': 24576, 'forbid': {'isb', 'dmb', 'sb', 'sev', 'sevl'},
            'allow': {'dc': {'cvac', 'civac'}}}


register_policies()


def payload_files(root=ROOT):
    """Every source and header of the payload, the files the audits of the record cover."""
    root = Path(root)
    return [root / 'payloads' / f'{part}.c' for part in PARTS] + [root / 'payloads' / name for name in HEADERS]


def copy_tree(directory):
    """The files the harness and the binary need, in the layout of the repository, below `directory`."""
    directory = Path(directory)
    shutil.rmtree(directory, ignore_errors=True)
    wanted = (('payloads', ['xhci*.c', 'xhci*.h', 'payload-util.h', 'start.S', 'payload.ld']),
              ('platform/uefi', ['*.h', 'sp11-payload-text.c', 'Makefile']),
              ('tools', ['test-q1n1-xhci.c', 'test-q1n1-sp11-payload-xhci*.[ch]', 'sp11_payload_elfcheck.py']))
    for sub, patterns in wanted:
        (directory / sub).mkdir(parents=True)
        for pattern in patterns:
            for path in sorted((ROOT / sub).glob(pattern)):
                shutil.copy(path, directory / sub / path.name)
    return directory


def harness_command(controller, out, root=ROOT, cap=None, load_cap=None):
    """The command that builds the host harness for one controller, from the sources of `root`; `cap` shrinks the payload's line budget
    and `load_cap` its load budget."""
    root = Path(root).resolve()
    flags = SANITIZE + GATES + [f'-DXHCI_S1_CONTROLLER={controller}'] + ([f'-DXHCI_S1_LINE_CAP={cap}'] if cap else []) + (
        [f'-DXHCI_S1_LOAD_CAP={load_cap}'] if load_cap else [])
    sources = [root / 'tools' / name for name in HARNESS] + [root / 'payloads' / f'{part}.c' for part in PARTS]
    sources.append(root / 'platform' / 'uefi' / 'sp11-payload-text.c')
    return (['clang'] + flags + ['-I', str(root / 'platform' / 'uefi'), '-I', str(root / 'payloads'), '-I', str(root / 'tools')] +
            [str(source) for source in sources] + ['-o', str(Path(out).resolve())])


def build_harness(controller, out, root=ROOT, cap=None, load_cap=None):
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    return lib.run(harness_command(controller, out, root, cap, load_cap), cwd=Path(root).resolve())


def run_harness(binary, *args):
    """(returncode, output); a hang is reported as returncode None."""
    import subprocess
    try:
        done = lib.run([str(binary)] + list(args or ['all']), timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired as hung:
        return None, (hung.stdout or '') if isinstance(hung.stdout, str) else ''
    return done.returncode, done.stdout + done.stderr


def build_binary(controller, out_dir, root=ROOT, defines=(), check=True):
    """Compiles every part for one controller with the Makefile's own flags, links with the stub and the linker script of `root`, runs the
    ELF check and flattens. Returns (CompletedProcess of the first failing step or of the last, elf, flat)."""
    root, out_dir = Path(root).resolve(), Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    makefile = root / 'platform' / 'uefi' / 'Makefile'
    flags = lib.payload_cflags(makefile) + [f'-DXHCI_S1_CONTROLLER={controller}'] + list(defines) + ['-Ipayloads']
    name = f'xhci{controller}'
    elf, flat = out_dir / f'{name}.elf', out_dir / f'{name}.bin'
    objects = [out_dir / 'start.o'] + [out_dir / f'{name}-{part}.o' for part in PARTS]
    steps = [['clang'] + flags + ['-c', str(root / 'payloads' / 'start.S'), '-o', str(objects[0])]]
    for part, obj in zip(PARTS, objects[1:]):
        steps.append(['clang'] + flags + ['-c', str(root / 'payloads' / f'{part}.c'), '-o', str(obj)])
    steps.append(['ld.lld'] + lib.makefile_flags('PAYLOAD_LDFLAGS', makefile) + ['-T', str(root / 'payloads' / 'payload.ld'), '-o', str(elf)] +
                 [str(obj) for obj in objects])
    if check:
        steps.append(['python3', '-B', str(root / 'tools' / 'sp11_payload_elfcheck.py'), '--readelf',
                      shutil.which('llvm-readelf', path=lib.ENV['PATH']) or 'llvm-readelf', str(elf)])
    steps.append(['llvm-objcopy', '-O', 'binary', str(elf), str(flat)])
    done = None
    for step in steps:
        done = lib.run(step, cwd=root)
        if done.returncode:
            return done, elf, flat
    return done, elf, flat
