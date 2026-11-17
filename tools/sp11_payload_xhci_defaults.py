# SPDX-License-Identifier: MIT
"""The checks of `XhciDefaults` (tools/test-q1n1-sp11-payload-xhci.py) and their seeded bugs: that the xHCI payload leaves the default build, every other
payload and the shared machinery as they are. Each check is a function of a tree and is true at every commit: it compares the tree with a copy of itself
without payloads/xhci*, never with an earlier commit, so that it passes at the commit that adds the payload as well as at the ones after it.

  1. default_problems: the default build (`make -n`, no target) plans no file of the xHCI payload. q1n1's own USB driver, platform/uefi/xhci.c, is in the
     default build and is another thing.
  2. target_problems: `make -n payloads` plans xhci0.bin and xhci1.bin and no other binary named for xhci (the parts are not payloads).
  3. without_problems and binary_problems: without payloads/xhci* the target plans the same commands but for the xHCI lines (its rules are present only
     where the sources are, as every other payload is found by wildcard), and every other payload built in both trees is byte for byte the same; the
     full tree has exactly the two extra binaries.
  4. shared_problems: the shared machinery names no xhci, a proxy that holds at every commit for "the shared machinery is untouched".
  5. clean_problems: `make clean` removes the objects of the payload, which are in directories of their own, so that a clean build is one.

Each seeded bug is an edit of a copy of the Makefile or of a shared file that one of the checks must reject, for the reason it is meant for. Writes only
below the directory it is given (scratch under build/). Hardware: NOT RUN. Evidence: EXPERIMENTAL (host only)."""
from pathlib import Path
import re
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sp11_payload_testlib as lib  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = 'platform/uefi/Makefile'
SHARED = ('tools/sp11_payload_testlib.py', 'tools/test-q1n1-sp11-payload.py', 'tools/sp11_payload_manifest.py', 'payloads/payload-util.h')
# The names of the xHCI payload in a plan: its directory and parts, its two binaries, its build macro.
PAYLOAD_NAMES = re.compile(r'payloads/xhci|xhci[01]|XHCI_S1', re.I)
BINARY = re.compile(r'payloads/([A-Za-z0-9_.-]+)\.bin\b')
APPEND = ''


def copy_build_tree(root, dest, with_xhci=True):
    """What `make payloads` needs, below `dest`: the Makefile and the headers beside it, every payload source, header, stub and linker script, the ELF
    check, and the shared files; without the xHCI sources (payloads/xhci*) if asked."""
    root, dest = Path(root), Path(dest)
    shutil.rmtree(dest, ignore_errors=True)
    files = {root / MAKEFILE, root / 'tools' / 'sp11_payload_elfcheck.py'} | {root / name for name in SHARED}
    files |= set((root / 'platform' / 'uefi').glob('*.h')) | {path for path in (root / 'payloads').iterdir() if path.is_file()}
    for path in sorted(files):
        relative = path.relative_to(root)
        if relative.parts[0] == 'payloads' and path.name.startswith('xhci') and not with_xhci:
            continue
        (dest / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(path, dest / relative)
    return dest


def plan(tree, targets=(), makefile=None):
    """The commands `make -n` would run in `tree` for the targets, with OUT=build/dry: nothing is written."""
    return lib.run(['make', '-n', '-f', str(makefile or MAKEFILE), 'OUT=build/dry'] + list(targets), cwd=tree)


def others(text):
    """The lines of a plan that do not name xhci."""
    return [line for line in text.splitlines() if 'xhci' not in line.lower()]


def default_problems(tree, makefile=None):
    """1. The default build plans nothing of the xHCI payload. `makefile` names another Makefile to plan with, run in `tree` (a seeded bug's)."""
    done = plan(tree, (), makefile)
    if done.returncode or len(done.stdout.splitlines()) < 10:
        return ['the default build does not plan: ' + (done.stderr or done.stdout)[-200:]]
    return [f'the default build plans {name}' for name in sorted(set(PAYLOAD_NAMES.findall(done.stdout)))]


def target_problems(tree):
    """2. `make -n payloads` plans xhci0.bin and xhci1.bin and no other binary named for xhci."""
    done = plan(tree, ('payloads',))
    if done.returncode:
        return ['make -n payloads does not plan: ' + done.stderr[-200:]]
    names = sorted({name for name in BINARY.findall(done.stdout) if 'xhci' in name.lower()})
    return [] if names == ['xhci0', 'xhci1'] else [f'the xHCI binaries planned are {names}, not xhci0 and xhci1']


def without_problems(tree, scratch):
    """3a. A copy of the tree without payloads/xhci* plans the payloads target, plans nothing of xhci, and plans the same commands as the tree for
    every line that does not name xhci."""
    without = copy_build_tree(tree, Path(scratch) / 'without', with_xhci=False)
    full, bare = plan(tree, ('payloads',)), plan(without, ('payloads',))
    for label, done in (('with', full), ('without', bare)):
        if done.returncode:
            return [f'make -n payloads does not plan {label} the xHCI sources: ' + done.stderr[-200:]]
    problems = []
    if len(others(bare.stdout)) < 20:
        problems.append('without the xHCI sources the payloads target plans (almost) nothing')
    if len(others(bare.stdout)) != len(bare.stdout.splitlines()):
        problems.append('without the xHCI sources the payloads target still plans xhci')
    if others(full.stdout) != others(bare.stdout):
        problems.append('the commands for the other payloads differ with and without the xHCI sources')
    return problems


def binary_problems(tree, scratch):
    """3b. Every payload built without the xHCI sources is built byte for byte the same with them, and the full tree builds exactly the two more."""
    scratch = Path(scratch).resolve()
    without = copy_build_tree(tree, scratch / 'without', with_xhci=False)
    built = {}
    for label, directory in (('with', Path(tree)), ('without', without)):
        out = scratch / f'out-{label}'
        shutil.rmtree(out, ignore_errors=True)
        done = lib.run(['make', '-f', MAKEFILE, f'OUT={out}', 'payloads'], cwd=directory)
        if done.returncode:
            return [f'make payloads fails {label} the xHCI sources: ' + (done.stderr or done.stdout)[-300:]]
        built[label] = {path.name: path.read_bytes() for path in sorted((out / 'payloads').glob('*.bin'))}
    full, bare = built['with'], built['without']
    problems = ['fewer than nine other payloads are built: the comparison would say little'] if len(bare) < 9 else []
    if sorted(full) != sorted(list(bare) + ['xhci0.bin', 'xhci1.bin']):
        problems.append(f'the full tree builds {sorted(full)} and the tree without the sources {sorted(bare)}')
    return problems + [f'{name} is not the same with and without the xHCI sources' for name in sorted(bare) if full.get(name) != bare[name]]


def clean_problems(tree):
    """`make clean` removes the objects of the xHCI payload, which are in directories of their own (xhci0 and xhci1) below the payloads' output."""
    done = plan(tree, ('clean',))
    if done.returncode:
        return ['make -n clean does not plan: ' + done.stderr[-200:]]
    removed = ' '.join(line for line in done.stdout.splitlines() if line.startswith('rm -rf '))
    return [f'make clean does not remove {name}' for name in ('payloads/xhci0', 'payloads/xhci1') if name not in removed]


def shared_texts(tree):
    return {name: (Path(tree) / name).read_text(encoding='utf-8') for name in SHARED}


def shared_problems(texts):
    """4. The shared machinery names no xhci."""
    return [f'{name} names xhci' for name, text in sorted(texts.items()) if 'xhci' in text.lower()]


# ---- seeded bugs: (name, the check that must reject it, edits (file, needle, replacement) of a copy, what the problem must say, checks that must pass) ---
# An empty needle appends. Each needle occurs exactly once in the file it names, so that a change of the Makefile that moves a target is a stale mutant.
BINS = 'XHCI_S1_BINS := $(if $(wildcard payloads/xhci.c),$(OUT)/payloads/xhci0.bin $(OUT)/payloads/xhci1.bin)'
LDFLAGS = 'PAYLOAD_LDFLAGS := -static -nostdlib -z norelro --build-id=none --emit-relocs\n'
CLEAN = '\trm -rf $(OUT)/payloads/xhci0 $(OUT)/payloads/xhci1\n'
MUTANTS = [
    ('the-default-build-plans-the-xhci-payload', 'default', [(MAKEFILE, APPEND, '\nall: $(XHCI_S1_BINS)\n')], 'the default build plans', ()),
    ('the-payloads-target-plans-xhci-bin-and-the-parts', 'target', [(MAKEFILE, '$(filter-out payloads/xhci%.c,$(PAYLOAD_SRCS))', '$(PAYLOAD_SRCS)')],
     'not xhci0 and xhci1', ()),
    ('the-payloads-target-lacks-xhci1', 'target', [(MAKEFILE, ' $(OUT)/payloads/xhci1.bin)', ')')], 'not xhci0 and xhci1', ()),
    ('the-xhci-rule-is-unconditional', 'without',
     [(MAKEFILE, BINS, 'XHCI_S1_BINS := $(OUT)/payloads/xhci0.bin $(OUT)/payloads/xhci1.bin')], 'does not plan without the xHCI sources', ()),
    ('a-flag-of-the-other-payloads-changes-when-the-sources-are-there', 'without',
     [(MAKEFILE, LDFLAGS, LDFLAGS + 'ifneq ($(wildcard payloads/xhci.c),)\nPAYLOAD_CFLAGS += -DPAYLOAD_EXTRA=1\nendif\n')],
     'differ with and without the xHCI sources', ()),
    ('a-payload-source-changes-when-the-xhci-headers-are-there', 'binaries',
     [('payloads/payload-util.h', APPEND, '\n#if __has_include("xhci-priv.h")\n__attribute__((used)) static const unsigned char pl_mark[4] = {1, 2, 3, 4};\n#endif\n')],
     'is not the same with and without the xHCI sources', ('without',)),
    ('the-testlib-names-xhci', 'shared', [('tools/sp11_payload_testlib.py', APPEND, '\n# xhci\n')], 'names xhci', ()),
    ('make-clean-leaves-the-xhci-objects', 'clean', [(MAKEFILE, CLEAN, '')], 'make clean does not remove', ()),
    ('the-base-suite-names-xhci', 'shared', [('tools/test-q1n1-sp11-payload.py', APPEND, '\n# xhci\n')], 'names xhci', ()),
    ('the-manifest-tool-names-xhci', 'shared', [('tools/sp11_payload_manifest.py', APPEND, '\n# xhci\n')], 'names xhci', ()),
    ('the-payload-header-names-xhci', 'shared', [('payloads/payload-util.h', APPEND, '\n/* xhci */\n')], 'names xhci', ()),
]


def run_check(check, directory, scratch, root):
    if check == 'default':
        return default_problems(root, makefile=(Path(directory) / MAKEFILE).resolve())
    if check == 'target':
        return target_problems(directory)
    if check == 'without':
        return without_problems(directory, scratch)
    if check == 'binaries':
        return binary_problems(directory, scratch)
    if check == 'clean':
        return clean_problems(directory)
    return shared_problems(shared_texts(directory))


def evaluate(mutant, scratch, root=ROOT):
    """(status, detail): 'caught' if the check the mutant is meant for says what it is meant to say, 'survived', 'wrong' (it says something else, or a check
    that has to pass does not) or 'stale' (a needle is not in its file exactly once)."""
    name, check, edits, phrase, quiet = mutant
    scratch = Path(scratch).resolve() / name
    directory = copy_build_tree(root, scratch / 'with')
    for file, needle, replacement in edits:
        path = directory / file
        text = path.read_text(encoding='utf-8')
        if needle and text.count(needle) != 1:
            return 'stale', f'target not found exactly once in {file}: {needle[:70]!r}'
        path.write_text(text.replace(needle, replacement, 1) if needle else text + replacement, encoding='utf-8')
    problems = run_check(check, directory, scratch, root)
    if not problems:
        return 'survived', f'the {check} check found nothing'
    if not any(phrase in problem for problem in problems):
        return 'wrong', f'the {check} check says {problems[0]!r}, not {phrase!r}'
    for other in quiet:
        if run_check(other, directory, scratch, root):
            return 'wrong', f'the {other} check rejects it too: the {check} check is not what catches it alone'
    return 'caught', problems[0]
