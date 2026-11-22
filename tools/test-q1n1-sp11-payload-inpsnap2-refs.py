#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests of the pinned reference copies behind the payload inpsnap2 (payloads/inpsnap2-regs.h, docs/SP11-PAYLOAD-INPSNAP2.md and its evidence document).

    INPSNAP2_REFS_DIR=<dir>[:<dir>...] SNAPINTOSH_DIR=<main checkout> python3 tools/test-q1n1-sp11-payload-inpsnap2-refs.py

  Ledger  needs no pinned copy: the ledger's own shape, the citations of the two documents against it, the digests the evidence document lists against the module's.
  Refs    reads the copies (SKIP without them: the directories INPSNAP2_REFS_DIR, GPUSNAP_REFS_DIR, INPUTSNAP_REFS_DIR, SNAPINTOSH_DIR/build/sp11-stick-log/refs and this tree's
          build/sp11-inpsnap2/refs are looked in): every digest, every ledger range, and the registers of the header read BY NAME from the Linux files (a window from its device-tree
          node, a clock word from its branch struct, the root clock generator's words from its struct and the DFS macros of clk-rcg2.c, GPLL0's words from the alpha-PLL layout it uses,
          the wrapper's version from the geni driver), so that a table whose line numbers are right and whose offsets are not is still caught.
  Plan    the read set of the payload against the host tool's list of the I0 survey (tools/geni_uart_plan.py of SNAPINTOSH_DIR; SKIP without it): the table is derived from the header
          and compared with the plan's list, word for word, so that neither can drift from the other.

VERIFIED means that a pinned file says so, never that the unit does. Hardware: NOT RUN."""
import importlib.util
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_inpsnap2_refs as refs  # noqa: E402

REGS = ROOT / 'payloads' / 'inpsnap2-regs.h'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-INPSNAP2.md'
EVIDENCE = ROOT / 'docs' / 'SP11-PAYLOAD-INPSNAP2-EVIDENCE.md'
HARNESS = ROOT / 'tools' / 'test-q1n1-sp11-payload-inpsnap2.c'
BUILD = ROOT / 'build' / 'sp11-payload-inpsnap2-refs'
ROW = re.compile(r'X\((\w+), "(\w+)", (0x[0-9a-f]+), (WIN_\w+), (B_\w+), ([^,]+), (\d+)\)')
# The key of the page and the word of the host plan's survey (tools/geni_uart_plan.py SURVEY_READS) it is: the table the parser of the page uses.
PLAN_WORD = {'SE0': 'cbcr', 'VT0': 'vote', 'GV': 'gpll0_vote', 'DIV': 'div', 'DFS': 'dfs', 'CMD': 'cmd', 'CFG': 'cfg', 'M': 'm', 'N': 'n', 'D': 'd', 'MODE': 'gpll0_mode',
             'OP': 'gpll0_opmode', 'ST': 'gpll0_status', 'L': 'gpll0_l', 'AL': 'gpll0_alpha', 'USR': 'gpll0_user', 'VER': 'qup_ver',
             **{f'LC{i}': f'lv_cfg{i}' for i in range(8)}, **{f'LM{i}': f'lv_m{i}' for i in range(8)}, **{f'LN{i}': f'lv_n{i}' for i in range(8)}}
GATE_ONLY = ('MA0', 'SA0', 'CR0')       # the three clock words of the wrapper's gate: read by the payload, not words the plan asks for


def header_rows():
    """[(id, key, offset, window name, block name, flags, vote bit)] of the register table of the header, in page order."""
    return [(rid, key, int(off, 16), win[4:], block[2:], flags, int(vbit)) for rid, key, off, win, block, flags, vbit in ROW.findall(REGS.read_text(encoding='utf-8'))]


def header_windows():
    """{name: (base, size)} of the two windows of the header."""
    text = REGS.read_text(encoding='utf-8')
    sizes = {name: int(value, 16) for name, value in re.findall(r'#define (GCC|QUP)_BYTES (0x[0-9a-f]+)u', text)}
    found = re.search(r'windows\[WINDOWS\] = \{\{(0x[0-9a-f]+)u, GCC_BYTES, 0\}, \{(0x[0-9a-f]+)u, QUP_BYTES, 0\}\}', text)
    return {'GCC': (int(found.group(1), 16), sizes['GCC']), 'QUP': (int(found.group(2), 16), sizes['QUP'])}


def node(lines, label):
    """The text of the device-tree node `label` (from its label line to the closing brace at the same indentation)."""
    for n, line in enumerate(lines):
        if re.match(rf'\s*{re.escape(label)}: ', line):
            indent = re.match(r'\s*', line).group(0)
            for m in range(n + 1, len(lines)):
                if lines[m] == indent + '};':
                    return '\n'.join(lines[n:m + 1])
    raise KeyError(label)


def dt_reg(text):
    """(base, size) of the first `reg = <0 base 0 size>` of a node."""
    found = re.search(r'\treg = <0 (0x[0-9a-fA-F]+) 0 (0x[0-9a-fA-F]+)>', text)
    return int(found.group(1), 16), int(found.group(2), 16)


def definition(text, name):
    """The body of `static struct <kind> <name> = { ... };` in a C file."""
    found = re.search(rf'^static (?:const )?struct \w+ {re.escape(name)} = \{{(.*?)^\}};', text, re.S | re.M)
    if not found:
        raise KeyError(name)
    return found.group(1)


def number(body, field):
    found = re.search(rf'\.{field} = (0x[0-9a-fA-F]+|\d+)', body)
    return int(found.group(1), 0)


def vote_bit(body):
    return int(re.search(r'\.enable_mask = BIT\((\d+)\)', body).group(1))


class Ledger(unittest.TestCase):
    def test_the_ledger_is_well_formed(self):
        self.assertEqual(set(refs.LINUX_PATH), set(refs.PINNED))
        for name, sha in refs.PINNED.items():
            self.assertRegex(sha, r'^[0-9a-f]{64}$', name)
        files = set()
        for name, first, last, needle in refs.LEDGER:
            self.assertIn(name, refs.PINNED)
            self.assertTrue(1 <= first <= last, (name, first, last))
            re.compile(needle)
            files.add(name)
        self.assertEqual({refs.PREFIX[p] for p in refs.PREFIX}, files, 'every prefix names a file the ledger covers, and every ledger file has a prefix')
        self.assertEqual(len(refs.LINUX_REVISION), 40)
        self.assertEqual(sorted(refs.UNVERIFIED), [f'UV{n}' for n in range(1, len(refs.UNVERIFIED) + 1)])
        self.assertEqual(len({(f, a, b) for f, a, b, _ in refs.LEDGER}), len(refs.LEDGER), 'a range is listed once')

    def test_the_documents_cite_only_what_the_ledger_covers(self):
        for path in (DOC, EVIDENCE):
            text = path.read_text(encoding='utf-8')
            citations = refs.cited(text)
            self.assertGreater(len(citations), 3 if path == DOC else 20, path.name)
            for prefix, first, last in citations:
                self.assertTrue(refs.covered(prefix, first, last), f'{path.name}: {prefix}:{first}-{last} is in no ledger range')

    def test_every_ledger_range_is_cited_somewhere_in_the_documents(self):
        text = DOC.read_text(encoding='utf-8') + '\n' + EVIDENCE.read_text(encoding='utf-8')
        cited = refs.cited(text)
        for name, first, last, _ in refs.LEDGER:
            prefix = next(p for p, f in refs.PREFIX.items() if f == name)
            self.assertTrue(any(p == prefix and first <= a and b <= last for p, a, b in cited), f'{name}:{first}-{last} is cited by no document: a ledger entry nobody uses')

    def test_the_evidence_document_lists_the_digests_the_module_pins(self):
        text = EVIDENCE.read_text(encoding='utf-8')
        self.assertIn(refs.LINUX_REVISION, text)
        for name, sha in refs.PINNED.items():
            self.assertIn(f'`{name}`', text, name)
            self.assertIn(sha, text, name)
            self.assertIn(refs.LINUX_PATH[name], text, name)

    def test_the_documents_list_exactly_the_unverified_items(self):
        text = DOC.read_text(encoding='utf-8')
        section = text[text.index('\n## 9. What could not be verified'):]
        self.assertEqual(sorted(set(re.findall(r'\*\*(UV\d+)\.\*\*', section))), sorted(refs.UNVERIFIED))


class Refs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not refs.refs_dirs():
            raise unittest.SkipTest('no pinned copies: set INPSNAP2_REFS_DIR (or GPUSNAP_REFS_DIR, INPUTSNAP_REFS_DIR or SNAPINTOSH_DIR)')
        cls.files = {name: refs.load(name) for name in refs.PINNED}
        cls.missing = sorted(name for name, lines in cls.files.items() if lines is None)
        if cls.missing:
            raise unittest.SkipTest('pinned copies not found (or not the pinned bytes): ' + ', '.join(cls.missing))
        cls.rows = header_rows()
        cls.by_key = {row[1]: row for row in cls.rows}

    def text(self, name):
        return '\n'.join(self.files[name])

    def test_every_ledger_range_holds_its_text(self):
        for name, first, last, needle in refs.LEDGER:
            with self.subTest(file=name, lines=f'{first}-{last}'):
                text = ' '.join(line.strip() for line in self.files[name][first - 1:last])
                self.assertRegex(text, needle)

    def test_the_windows_are_the_device_tree(self):
        lines = self.files['hamoa.dtsi']
        windows = header_windows()
        self.assertEqual(windows['GCC'], dt_reg(node(lines, 'gcc')))
        self.assertEqual(windows['QUP'], dt_reg(node(lines, 'qupv3_0')))
        engine = dt_reg(node(lines, 'uart2'))
        self.assertEqual(engine[0], 0xb88000)
        self.assertFalse(windows['QUP'][0] <= engine[0] < windows['QUP'][0] + windows['QUP'][1], 'the wrapper\'s page does not hold the engine\'s registers: the payload reads the wrapper, never the engine')
        self.assertEqual(len({r[3] for r in self.rows}), 2)

    def test_the_clock_words_are_the_branch_structs(self):
        gcc = self.text('gcc-x1e80100.c')
        clocks = {'MA0': 'gcc_qupv3_wrap_0_m_ahb_clk', 'SA0': 'gcc_qupv3_wrap_0_s_ahb_clk', 'CR0': 'gcc_qupv3_wrap0_core_clk', 'SE0': 'gcc_qupv3_wrap0_s2_clk'}
        votes = set()
        for key, name in clocks.items():
            body = definition(gcc, name)
            row = self.by_key[key]
            with self.subTest(key=key):
                self.assertEqual(row[3:5], ('GCC', 'GATE'))
                self.assertEqual(row[2], number(body, 'halt_reg'))
                self.assertIn('BRANCH_HALT_VOTED', body, 'a voted branch: its CLK_ENABLE bit stays clear while it runs')
                self.assertEqual(('F_HWCG' in row[5]), '.hwcg_reg' in body, 'the hardware gating flag is exactly the clocks that declare a hwcg register')
                self.assertEqual(('F_CBCR' in row[5]), True)
                self.assertEqual(('F_WRAP' in row[5]), key != 'SE0', 'the wrapper gate takes the three wrapper words, not the engine\'s own clock')
                if '.hwcg_reg' in body:
                    self.assertEqual(number(body, 'hwcg_reg'), number(body, 'halt_reg'))
                    self.assertEqual(number(body, 'hwcg_bit'), 1, 'HW_CTL is bit 1 of the branch word')
                    self.assertEqual(row[6], vote_bit(body), 'the vote bit of a hardware-gated clock is its enable_mask in the vote word')
                else:
                    self.assertEqual(row[6], 0)
            votes.add(number(definition(gcc, name), 'enable_reg'))
        self.assertEqual(votes, {self.by_key['VT0'][2]}, 'the four clocks are all voted in the one word the table reads')
        self.assertEqual(self.by_key['GV'][2], number(definition(gcc, 'gcc_gpll0'), 'enable_reg'))
        self.assertEqual(vote_bit(definition(gcc, 'gcc_gpll0')), 0, 'the bit of GPLL0 in its vote word is bit 0')
        self.assertEqual((self.by_key['VT0'][5], self.by_key['GV'][5]), ('0', '0'), 'the two vote words are no branch clock words')

    def test_the_root_generator_words_are_the_rcg_struct_and_its_registers(self):
        gcc, rcg = self.text('gcc-x1e80100.c'), self.text('clk-rcg2.c')
        cmd = number(definition(gcc, 'gcc_qupv3_wrap0_s2_clk_src'), 'cmd_rcgr')
        self.assertNotIn('.cfg_off', definition(gcc, 'gcc_qupv3_wrap0_s2_clk_src'), 'the configuration word is at the default +4')
        regs = {name: int(value, 16) for name, value in re.findall(r'#define (CMD_REG|CFG_REG|M_REG|N_REG|D_REG)\s+(0x[0-9a-f]+)', rcg)}
        self.assertEqual(regs, {'CMD_REG': 0, 'CFG_REG': 4, 'M_REG': 8, 'N_REG': 0xc, 'D_REG': 0x10})
        for key, add in (('CMD', regs['CMD_REG']), ('CFG', regs['CFG_REG']), ('M', regs['M_REG']), ('N', regs['N_REG']), ('D', regs['D_REG'])):
            self.assertEqual(self.by_key[key][2], cmd + add, key)
            self.assertEqual(self.by_key[key][3:5], ('GCC', 'RCG'), key)
        self.assertEqual(self.by_key['DIV'][2], number(definition(gcc, 'gcc_qupv3_wrap0_s2_div_clk_src'), 'reg'))
        self.assertIn('clk_regmap_div_ro_ops', definition(gcc, 'gcc_qupv3_wrap0_s2_div_clk_src'), 'a read-only divider: nothing writes it')
        self.assertEqual(number(definition(gcc, 'gcc_qupv3_wrap0_s2_div_clk_src'), 'shift'), 0)
        self.assertIn('DEFINE_RCG_DFS(gcc_qupv3_wrap0_s2_clk_src)', gcc, 'the engine\'s root clock generator is registered as a DFS candidate: the flag decides')

    def test_the_dfs_words_are_the_pinned_macros(self):
        rcg = self.text('clk-rcg2.c')
        cmd = self.by_key['CMD'][2]
        flag = int(re.search(r'#define SE_CMD_DFSR_OFFSET\s+(0x[0-9a-f]+)', rcg).group(1), 16)
        self.assertEqual(self.by_key['DFS'][2], cmd + flag)
        self.assertEqual(re.search(r'#define SE_CMD_DFS_EN\s+BIT\((\d)\)', rcg).group(1), '0', 'the DFS flag is bit 0')
        self.assertEqual(int(re.search(r'#define MAX_PERF_LEVEL\s+(\d+)', rcg).group(1)), 8)
        for prefix, macro in (('LC', 'SE_PERF_DFSR'), ('LM', 'SE_PERF_M_DFSR'), ('LN', 'SE_PERF_N_DFSR')):
            base, stride = re.search(rf'#define {macro}\(level\)\s+\((0x[0-9a-f]+) \+ (0x[0-9a-f]+) \* \(level\)\)', rcg).groups()
            for level in range(8):
                self.assertEqual(self.by_key[f'{prefix}{level}'][2], cmd + int(base, 16) + int(stride, 16) * level, f'{prefix}{level}')
                self.assertEqual(self.by_key[f'{prefix}{level}'][3:5], ('GCC', 'LVL'))
        self.assertIn('level &= GENMASK(4, 1)', rcg, 'the current level is bits 4:1 of the DFS word')
        self.assertIn('n = ~n', rcg, 'N is stored inverted (the plan decodes it so)')

    def test_the_pll_words_are_the_layout_gpll0_picks(self):
        gcc, pll = self.text('gcc-x1e80100.c'), self.text('clk-alpha-pll.c')
        body = definition(gcc, 'gcc_gpll0')
        base = number(body, 'offset')
        self.assertIn('CLK_ALPHA_PLL_TYPE_LUCID_OLE', body)
        layout = re.search(r'\[CLK_ALPHA_PLL_TYPE_LUCID_OLE\] = \{(.*?)\n\t\},', pll, re.S).group(1)
        offsets = {name: int(value, 16) for name, value in re.findall(r'\[PLL_OFF_(\w+)\] = (0x[0-9a-f]+)', layout)}
        self.assertEqual(re.search(r'#define PLL_MODE\(p\)\s+\(\(p\)->offset \+ (0x0)\)', pll).group(1), '0x0')
        want = {'MODE': base + 0, 'OP': base + offsets['OPMODE'], 'ST': base + offsets['STATUS'], 'L': base + offsets['L_VAL'], 'AL': base + offsets['ALPHA_VAL'], 'USR': base + offsets['USER_CTL']}
        for key, off in want.items():
            self.assertEqual(self.by_key[key][2], off, key)
            self.assertEqual(self.by_key[key][3:5], ('GCC', 'PLL'), key)
        self.assertEqual({k: offsets[k] for k in ('OPMODE', 'STATUS', 'L_VAL', 'ALPHA_VAL', 'USER_CTL')}, {'OPMODE': 4, 'STATUS': 0xc, 'L_VAL': 0x10, 'ALPHA_VAL': 0x14, 'USER_CTL': 0x18})
        self.assertIn('clk_alpha_pll_fixed_lucid_ole_ops', body, 'GPLL0 has the fixed ops: Linux never reconfigures it')
        self.assertRegex(pll, r'# define PLL_LOCK_DET\s+BIT\(31\)')
        self.assertRegex(pll, r'# define PLL_ACTIVE_FLAG\s+BIT\(30\)')
        self.assertRegex(pll, r'# define PLL_ALPHA_EN\s+BIT\(24\)')
        self.assertEqual(sum(1 for row in self.rows if row[4] == 'PLL'), 6)

    def test_the_wrapper_version_is_the_geni_register(self):
        se, header = self.text('qcom-geni-se.c'), self.text('geni-se.h')
        self.assertEqual(int(re.search(r'#define QUPV3_HW_VER_REG\s+(0x[0-9a-f]+)', se).group(1), 16), self.by_key['VER'][2])
        self.assertEqual(self.by_key['VER'][3:5], ('QUP', 'QUP'))
        self.assertIn('readl_relaxed(wrapper->base + QUPV3_HW_VER_REG)', se)
        self.assertRegex(header, r'HW_VER_MAJOR_MASK\s+GENMASK\(31, 28\)')
        self.assertRegex(header, r'HW_VER_MINOR_MASK\s+GENMASK\(27, 16\)')

    def test_the_rows_in_the_window_are_inside_it(self):
        windows = header_windows()
        for rid, key, off, win, block, flags, vbit in self.rows:
            with self.subTest(key=key):
                self.assertTrue(off % 4 == 0 and off + 4 <= windows[win][1])


def plan_module():
    """The host plan tool of SNAPINTOSH_DIR, or None."""
    path = Path(os.environ.get('SNAPINTOSH_DIR', '/nonexistent')) / 'tools' / 'geni_uart_plan.py'
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location('geni_uart_plan_for_inpsnap2', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Plan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = plan_module()
        if cls.plan is None:
            raise unittest.SkipTest('no tools/geni_uart_plan.py: set SNAPINTOSH_DIR to a main checkout that has it')
        cls.rows = header_rows()

    def test_the_payloads_table_is_the_plans_survey_and_the_three_gate_words(self):
        plan = {name: self.plan.BASES[base] + off for name, base, off, _ in self.plan.SURVEY_READS}
        self.assertEqual(len(plan), 41)
        windows = header_windows()
        table = {key: windows[win][0] + off for rid, key, off, win, block, flags, vbit in self.rows}
        self.assertEqual(len(table), 44)
        self.assertEqual(sorted(set(table) - set(PLAN_WORD)), sorted(GATE_ONLY), 'the table has the plan\'s words and the three gate words, nothing else')
        self.assertEqual(sorted(set(PLAN_WORD) - set(table)), [], 'every word of the plan is a row of the table')
        self.assertEqual(sorted(PLAN_WORD.values()), sorted(plan), 'the key map names every word of the plan once')
        for key, name in PLAN_WORD.items():
            self.assertEqual(table[key], plan[name], f'{key} is the plan word {name}')

    def test_the_order_of_the_blocks_puts_what_the_plan_decides_first_first(self):
        order = [row[1] for row in self.rows]
        self.assertLess(order.index('DFS'), order.index('LC0'), 'the DFS flag before the levels it makes meaningful')
        self.assertLess(order.index('MODE'), order.index('LC0'))
        self.assertEqual(order[-1], 'VER', 'the one word nobody has read is the last')
        self.assertEqual(order[:3], list(GATE_ONLY))

    def test_the_decoders_of_the_plan_agree_with_the_pinned_macros(self):
        self.assertEqual(self.plan.DFS_LEVELS, 8)
        self.assertEqual(self.plan.decode_dfs_cmd(0x7), {'dfs': True, 'level': 3})
        self.assertEqual(self.plan.decode_dfs_cmd(0x6), {'dfs': False, 'level': 3})


@unittest.skipUnless(shutil.which('clang'), 'no clang')
class Table(unittest.TestCase):
    """The table the host test prints for the shipped payload (key, window, physical address, block) is the header's."""

    @classmethod
    def setUpClass(cls):
        BUILD.mkdir(parents=True, exist_ok=True)
        binary = BUILD / 'harness'
        flags = ['-std=gnu11', '-O1', '-DQ1N1_PAYLOAD_HOST_TEST=1', '-Iplatform/uefi', '-Ipayloads', '-w']
        done = subprocess.run(['clang', *flags, '-o', str(binary), str(HARNESS)], cwd=ROOT, capture_output=True, text=True)
        if done.returncode:
            raise RuntimeError('the host test did not build:\n' + done.stderr[-1500:])
        cls.printed = subprocess.run([str(binary), '--table'], cwd=ROOT, capture_output=True, text=True).stdout.splitlines()

    def test_the_printed_table_is_the_headers(self):
        windows = header_windows()
        rows = header_rows()
        self.assertEqual(len(self.printed), len(rows))
        for line, (rid, key, off, win, block, flags, vbit) in zip(self.printed, rows):
            printed_key, printed_win, address, printed_block = line.split()
            self.assertEqual((printed_key, printed_win, int(address, 16)), (key, win, windows[win][0] + off))
            self.assertEqual(int(printed_block), ['GATE', 'RCG', 'PLL', 'LVL', 'QUP'].index(block))


if __name__ == '__main__':
    unittest.main()
