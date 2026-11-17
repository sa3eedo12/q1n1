#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The compiled code of the xhci payload (docs/SP11-PAYLOAD-XHCI.md), audited beyond what its allow-list and disassembly show
(tools/test-q1n1-sp11-payload-xhci.py holds those):

  * XhciProvenance: the root of every pointer that a store, a memset, a memcpy or a call uses, in the LLVM IR of every part of both
    controllers, built with the Makefile's own flags (tools/sp11_payload_xhci_audit.py): only the two sinks store through a pointer
    that is not rooted in the payload's own stack, context or line buffers. The audit proves the base of a store, not its offset (a test
    shows a digit buffer that is too small passing it: the host harness's sanitizers check the offsets on the paths the tests run). The count of stores is not
    pinned (it depends on the compiler); the structure is. Faulty IR texts, clean ones and three faulty source trees show what it rejects.
  * XhciDepth: how deep the payload's own frames reach (frame sizes from -fstack-size-section objects, the call graph of the linked ELF)
    against the stack the runner leaves it: arena 2 lies below the 24 KiB the payload and the runner's ops keep, and the ABI leaves
    16 KiB of that to the runner's ops.

    python3 tools/test-q1n1-sp11-payload-xhci-compiled.py

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_ecv_lib as ecv  # noqa: E402
import sp11_payload_xhci_audit as audit  # noqa: E402
import sp11_payload_xhci_audit_cases as audit_cases  # noqa: E402
import sp11_payload_xhci_lib as xl  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-xhci-compiled-test'


def disassembly(elf):
    return lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)]).stdout


def stack_keep():
    header = (ROOT / 'payloads' / 'xhci-regs.h').read_text(encoding='utf-8')
    return int(re.search(r'#define STACK_KEPT \((\d+)u \* 1024u\)', header).group(1)) * 1024


class XhciProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ecv.need_tools()

    def test_every_store_of_the_compiled_code_goes_to_the_payloads_own_memory_but_the_two_sinks(self):
        for controller in xl.CONTROLLERS:
            with self.subTest(controller=controller):
                problems, counts = audit.provenance(audit.build_ir(controller, BUILD / 'ir' / f'c{controller}'))
                self.assertEqual(problems, [])
                self.assertEqual(counts['sink_stores'], 2)
                self.assertEqual(counts['by_root']['I'], 2, 'the two sinks are the only stores through an integer made a pointer')
                self.assertEqual(set(counts['by_root']), {'S', 'P', 'I'})
                self.assertGreater(counts['stores'], 100, 'the audit read the code')
                self.assertEqual(set(counts['inttoptr']) - set(audit.INTTOPTR_READERS), set(audit.INTTOPTR))

    def test_the_audit_rejects_every_faulty_text_and_passes_the_shapes_the_payload_has(self):
        self.assertGreaterEqual(len(audit_cases.FAULTY), 20)
        for what, text, phrase in audit_cases.FAULTY:
            with self.subTest(faulty=what):
                problems, _ = audit.provenance({'case': text})
                self.assertTrue(any(phrase in p for p in problems), f'{phrase!r} not in {problems}')
        for what, text in audit_cases.CLEAN:
            with self.subTest(clean=what):
                self.assertEqual(audit.provenance({'case': text})[0], [])

    def test_the_audit_proves_the_base_of_a_store_and_not_its_offset_which_only_the_host_harness_bounds(self):
        # A digit buffer one byte too small: the store is still rooted in the payload's own stack, so the audit passes it; the harness (mutant
        # a-digit-buffer-that-is-too-small of tools/test-q1n1-sp11-payload-xhci.py, caught by a sanitizer) is what rejects it.
        copy = xl.copy_tree(BUILD / 'offset')
        path = copy / 'payloads' / 'xhci-text.c'
        text = path.read_text(encoding='utf-8')
        self.assertEqual(text.count('    char digits[20];\n'), 1)
        path.write_text(text.replace('    char digits[20];\n', '    char digits[2];\n', 1), encoding='utf-8')
        problems, counts = audit.provenance(audit.build_ir(1, copy / 'ir', root=copy))
        self.assertEqual(problems, [])
        self.assertEqual(counts['sink_stores'], 2)

    def test_the_audit_rejects_a_store_added_to_the_source_that_the_source_audit_cannot_see(self):
        cases = (
            ('a store through the runner\'s arguments', 'xhci.c', '    c.a = a;\n', '    c.a = a;\n    ((struct q1n1_payload_args *)c.a)->magic = 0;\n', 'not its own memory'),
            ('a store through an integer', 'xhci-ctl.c', '    r->stage = STG_RUN;\n', '    r->stage = STG_RUN;\n    *(uint32_t *)(uintptr_t)c->hz = 0;\n',
             'integer-to-pointer'),
            ('the runner\'s arguments handed to a function', 'xhci.c', '    c.a = a;\n', '    c.a = a;\n    watch_run((struct ctx *)c.a, 0);\n', 'hands watch_run'),
        )
        for index, (label, name, needle, replacement, phrase) in enumerate(cases):
            with self.subTest(case=label):
                copy = xl.copy_tree(BUILD / 'faulty' / str(index))
                path = copy / 'payloads' / name
                text = path.read_text(encoding='utf-8')
                self.assertEqual(text.count(needle), 1)
                path.write_text(text.replace(needle, replacement, 1), encoding='utf-8')
                problems, _ = audit.provenance(audit.build_ir(1, copy / 'ir', root=copy))
                self.assertTrue(any(phrase in p for p in problems), f'{phrase!r} not in {problems}')


class XhciDepth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ecv.need_tools()
        cls.elf = {}
        for controller in xl.CONTROLLERS:
            done, elf, _ = xl.build_binary(controller, BUILD / 'binary' / f'c{controller}')
            if done.returncode:
                raise RuntimeError(done.stdout[-1500:] + done.stderr[-1500:])
            cls.elf[controller] = elf

    def test_the_payloads_own_frames_leave_the_runners_ops_their_share_of_the_stack_it_keeps(self):
        for controller in xl.CONTROLLERS:
            with self.subTest(controller=controller):
                sizes = audit.frame_sizes(controller, BUILD / 'frames' / f'c{controller}')
                used, path = audit.depth(audit.call_graph(disassembly(self.elf[controller])), sizes)
                self.assertEqual(path[0], 'payload_entry')
                self.assertGreater(used, 512, 'the audit read the frames')
                self.assertLessEqual(used + audit.OPS_ALLOWANCE, stack_keep(), f'{used} bytes along {path}')

    def test_the_check_rejects_a_deep_frame_a_recursion_and_a_function_without_a_frame_size(self):
        used, path = audit.depth({'payload_entry': {'a'}, 'a': {'b'}, 'b': set()}, {'payload_entry': 100, 'a': 20000, 'b': 8})
        self.assertEqual((used, path), (20108, ['payload_entry', 'a', 'b']))
        self.assertGreater(used + audit.OPS_ALLOWANCE, stack_keep())
        with self.assertRaisesRegex(ValueError, 'recursion'):
            audit.depth({'payload_entry': {'a'}, 'a': {'payload_entry'}}, {'payload_entry': 8, 'a': 8})
        with self.assertRaisesRegex(ValueError, 'no frame size for ghost'):
            audit.depth({'payload_entry': {'ghost'}}, {'payload_entry': 8})
        graph = audit.call_graph('0000000000000100 <payload_entry>:\n   100: \tbl\t0x200 <a>\n   104: \tb\t0x300 <b>\n   108: \tb.ne\t0x10c <payload_entry+0xc>\n'
                                 '   10c: \tb\t0x110 <payload_entry+0x10>\n0000000000000200 <a>:\n   200: \tret\n0000000000000300 <b>:\n   300: \tret\n')
        self.assertEqual(graph, {'payload_entry': {'a', 'b'}, 'a': set(), 'b': set()})

    def test_a_large_frame_added_to_the_no_op_path_is_refused_by_the_check(self):
        copy = xl.copy_tree(BUILD / 'deep')
        path = copy / 'payloads' / 'xhci-ctl.c'
        needle = '    r->stage = STG_NOOP;\n'
        text = path.read_text(encoding='utf-8')
        self.assertEqual(text.count(needle), 1)
        path.write_text(text.replace(needle, needle + '    volatile uint8_t pad[16384];\n    c->failed = (const char *)pad;\n', 1), encoding='utf-8')
        done, elf, _ = xl.build_binary(1, copy / 'out', root=copy, check=False)
        self.assertEqual(done.returncode, 0, done.stderr[-800:])
        used, along = audit.depth(audit.call_graph(disassembly(elf)), audit.frame_sizes(1, copy / 'frames', root=copy))
        self.assertGreater(used + audit.OPS_ALLOWANCE, stack_keep(), f'{used} bytes along {along}')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
