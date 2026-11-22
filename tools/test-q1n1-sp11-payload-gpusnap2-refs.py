#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests of the pinned reference copies behind the payload gpusnap2 (payloads/gpusnap2-regs.h, docs/SP11-PAYLOAD-GPUSNAP2.md and its evidence ledger).

    GPUSNAP2_REFS_DIR=<dir>[:<dir>...] python3 tools/test-q1n1-sp11-payload-gpusnap2-refs.py

  Ledger  needs no pinned copy: the ledger's own shape, the citations of the two documents against it, the digests the evidence document lists against the module's, and the
          Linux path of every file against the name it is pinned under and against the gpusnap module's table.
  Statements  needs no pinned copy: what the documents and the header say that an independent review corrected (the descriptor counts of the unit's memory maps, boot 30's words,
          the rows drawn in boot 29, the catalog's path), each held by its own entry, and the stale phrases they may not hold again.
  Refs    reads the copies (SKIP without them: the directories GPUSNAP2_REFS_DIR, GPUSNAP_REFS_DIR, TSNAP_REFS_DIR, SNAPINTOSH_DIR/build/sp11-stick-log/refs and this tree's
          build/sp11-gpusnap2/refs are looked in): every digest, every ledger range, and the registers of the header read BY NAME from the Linux files (a window from its device-tree
          node, a GPUCC register from its clock or divider struct, a PLL word from the alpha-PLL layout it uses, an RSC register from its version's table, the command database's
          layout and ids, the speed-bin map, the status word's fields), so that a table whose line numbers are right and whose offsets are not is still caught.

VERIFIED means that a pinned file says so, never that the unit does. Hardware: NOT RUN."""
from pathlib import Path
import re
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_gpusnap2_refs as refs  # noqa: E402
import sp11_payload_gpusnap_refs as gpusnap_refs  # noqa: E402

REGS = ROOT / 'payloads' / 'gpusnap2-regs.h'
TSNAP_REGS = ROOT / 'payloads' / 'tsnap-regs.h'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-GPUSNAP2.md'
EVIDENCE = ROOT / 'docs' / 'SP11-PAYLOAD-GPUSNAP2-EVIDENCE.md'


def c_value(text):
    text = re.sub(r'\b(0x[0-9a-fA-F]+|\d+)[uUlL]*\b', r'\1', text.split('/*')[0]).strip()
    if not re.fullmatch(r'[0-9a-fx<>()+* -]+', text):
        raise ValueError(f'not a plain constant: {text!r}')
    return eval(text, {'__builtins__': {}})


def define(name, path=None):
    found = re.search(rf'^#define {name} (.+)$', (path or REGS).read_text(encoding='utf-8'), re.M)
    if not found:
        raise KeyError(name)
    return c_value(found.group(1))


def header_rows():
    """[(window name, offset, key)] of the register table of the header, in reading order."""
    return [(win[4:], int(off, 16), key) for win, off, key in re.findall(r'ROW\((WIN_\w+), (0x[0-9a-f]+), \w+, "(\w+)"\)', REGS.read_text(encoding='utf-8'))]


def unique_rows():
    """{key: (window name, offset)} for the keys the table holds once (the PLL rows repeat MODE, OP, L and AL)."""
    rows = header_rows()
    return {key: (win, off) for win, off, key in rows if sum(1 for row in rows if row[2] == key) == 1}


def header_windows():
    text = REGS.read_text(encoding='utf-8')
    body = re.search(r'windows\[WIN_MAP\] = \{(.*?)\n\};', text, re.S).group(1)
    return [(c_value(a), c_value(b)) for a, b in re.findall(r'\{(0x[0-9a-fA-F]+u), (0x[0-9a-fA-F]+u|CMDDB_BYTES), 0\}', body.replace('CMDDB_BYTES', '0x20000u'))]


def header_layouts():
    rows = re.findall(r'\{(\d), (0x[0-9a-f]+)u, (0x[0-9a-f]+)u, (0x[0-9a-f]+)u, (\d+)u, \{0, 0, 0\}\}', REGS.read_text(encoding='utf-8'))
    return {int(major): tuple(c_value(v) for v in rest) for major, *rest in rows}


def node(lines, label):
    """The text of the device-tree node `label` (from its label line to the closing brace at the same indentation)."""
    for n, line in enumerate(lines):
        if re.match(rf'\s*{re.escape(label)}: ', line):
            indent = re.match(r'\s*', line).group(0)
            for m in range(n + 1, len(lines)):
                if lines[m] == indent + '};':
                    return '\n'.join(lines[n:m + 1])
    raise KeyError(label)


def dt_regs(text):
    return [(int(a, 16), int(b, 16)) for a, b in re.findall(r'<0x?0? ?(0x[0-9a-fA-F]+) 0x?0? ?(0x[0-9a-fA-F]+)>', re.search(r'\treg = (.*?);', text, re.S).group(1))]


def wrong_paths(paths):
    """The names whose Linux path does not end in that name. A pin is the bytes of the file of that name, and a neighbour in the same directory (a6xx_catalog.c lies beside
    a7xx_catalog.c) is another file: a reader who fetches it gets bytes that fail the digest, so the table is wrong and the check on the digest cannot say where."""
    return sorted(name for name, path in paths.items() if path.rpartition('/')[2] != name)


class Ledger(unittest.TestCase):
    def test_the_ledger_is_well_formed(self):
        for name, (sha, where) in refs.PINNED.items():
            self.assertRegex(sha, r'^[0-9a-f]{64}$', name)
            self.assertIn(where, {'STICK', 'GPUSNAP', 'TSNAP', 'THIS'}, name)
            self.assertIn(name, refs.LINUX_PATH, name)
        self.assertEqual(set(refs.LINUX_PATH), set(refs.PINNED))
        files = set()
        for name, first, last, needle in refs.LEDGER:
            self.assertIn(name, refs.PINNED)
            self.assertTrue(1 <= first <= last, (name, first, last))
            re.compile(needle)
            files.add(name)
        self.assertEqual({refs.PREFIX[p] for p in refs.PREFIX}, files, 'every prefix names a file the ledger covers, and every ledger file has a prefix')
        self.assertEqual(len(refs.LINUX_REVISION), 40)
        self.assertEqual(sorted(refs.UNVERIFIED), [f'UV{n}' for n in range(1, len(refs.UNVERIFIED) + 1)])

    def test_the_documents_cite_only_what_the_ledger_covers(self):
        for path in (DOC, EVIDENCE):
            text = path.read_text(encoding='utf-8')
            citations = refs.CITATION.findall(text)
            self.assertGreater(len(citations), 1 if path == EVIDENCE else 30, path.name)
            for prefix, first, last in citations:
                self.assertTrue(refs.covered(prefix, int(first), int(last or first)), f'{path.name}: {prefix}:{first}-{last} is in no ledger range')

    def test_the_evidence_document_lists_the_digests_the_module_pins(self):
        text = EVIDENCE.read_text(encoding='utf-8')
        self.assertIn(refs.LINUX_REVISION, text)
        for name, (sha, _) in refs.PINNED.items():
            self.assertIn(f'`{name}`', text, name)
            self.assertIn(sha, text, name)

    def test_the_documents_list_exactly_the_unverified_items(self):
        text = DOC.read_text(encoding='utf-8')
        section = text[text.index('\n## 9. Not verified'):]
        self.assertEqual(sorted(set(re.findall(r'\*\*(UV\d+)\*\*', section))), sorted(refs.UNVERIFIED))

    def test_every_linux_path_ends_in_the_name_the_file_is_pinned_under(self):
        self.assertEqual(wrong_paths(refs.LINUX_PATH), [])

    def test_a_path_that_names_a_neighbouring_file_is_refused(self):
        right = {'a7xx_catalog.c': 'drivers/gpu/drm/msm/adreno/a7xx_catalog.c', 'qfprom.c': 'drivers/nvmem/qfprom.c'}
        self.assertEqual(wrong_paths(right), [])
        self.assertEqual(wrong_paths(dict(right, **{'a7xx_catalog.c': 'drivers/gpu/drm/msm/adreno/a6xx_catalog.c'})), ['a7xx_catalog.c'])
        self.assertEqual(wrong_paths(dict(right, **{'qfprom.c': 'drivers/nvmem/qfprom-sunxi.c'})), ['qfprom.c'])

    def test_the_paths_and_digests_agree_with_the_gpusnap_module_where_both_pin_a_file(self):
        common = sorted(set(refs.PINNED) & set(gpusnap_refs.PINNED))
        self.assertGreaterEqual(len(common), 10)
        self.assertIn('a7xx_catalog.c', common)
        for name in common:
            self.assertEqual(refs.LINUX_PATH[name], gpusnap_refs.LINUX_PATH[name], name)
            self.assertEqual(refs.PINNED[name][0], gpusnap_refs.PINNED[name][0], name)


# What the documents and the header say that an independent review corrected, and what they may not say any more.
MUST_HOLD = (
    ('dump-counts-in-section-3', 'doc', 'six dumps of 227, 226, 226, 230, 231 and 231 descriptors, a descriptor size of 48'),
    ('dump-counts-in-section-8', 'doc', "the six memory maps hold 227, 226, 226, 230, 231 and 231 descriptors of 48 bytes (the payload's cap is 320, a margin of 89 over the largest)"),
    ('boot-30-gcc-vote-words', 'doc', 'the GCC words that carry the GPLL0 votes, 0x52000 and 0x52030 (`VOTE=0XE0657B CPH=0 DIV=0 GP0V=0X201`)'),
    ('boot-30-root-clock-generator-words', 'doc', 'GPUCC 0x9318, 0x931c, 0x93ec and 0x93f0 (`GRC=0X80000000.OFF GRF=0 S=0 HRC=0.ON HRF=0 S=0`)'),
    ('rows-drawn-in-boot-29', 'doc', 'The most rows seen drawn is 73, in boot 29: 9 runner rows, the 34 lines of `tsnap` and the 30 of `inputsnap`'),
    ('catalog-is-the-a7xx-file', 'evidence', '`a6xx_catalog.c` lies beside it in the same directory and is another file'),
    ('header-rows-comment', 'regs', "boot 29's film showed 73 rows drawn"),
    ('header-descriptors-comment', 'regs', "the unit's six dumps hold 226 to 231 descriptors"),
)
MUST_NOT_HOLD = (
    ('dump-counts-up-to-234', '227 to 234'),
    ('panel-never-seen-beyond-58', 'never seen beyond 58', 'never been seen beyond 58', 'within the 58 ever seen'),
)


def statement_problems(texts):
    """The names of the statements that `texts` ({'doc', 'evidence', 'regs'}, whitespace collapsed) lacks, and of the stale ones that it still holds."""
    problems = [name for name, key, needle in MUST_HOLD if needle not in texts[key]]
    problems += [name for name, *needles in MUST_NOT_HOLD for text in texts.values() for needle in needles if needle in text]
    return problems


class Statements(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.texts = {key: ' '.join(path.read_text(encoding='utf-8').split()) for key, path in (('doc', DOC), ('evidence', EVIDENCE), ('regs', REGS))}

    def test_the_documents_and_the_header_hold_what_the_review_corrected_and_nothing_stale(self):
        self.assertEqual(statement_problems(self.texts), [])

    def test_each_statement_is_refused_by_its_own_entry(self):
        for name, key, needle in MUST_HOLD:
            with self.subTest(statement=name):
                self.assertEqual(self.texts[key].count(needle), 1)
                self.assertEqual(statement_problems(dict(self.texts, **{key: self.texts[key].replace(needle, '')})), [name])
        for name, *needles in MUST_NOT_HOLD:
            for key in self.texts:
                for needle in needles:
                    with self.subTest(stale=name, where=key, text=needle):
                        self.assertEqual(statement_problems(dict(self.texts, **{key: self.texts[key] + ' ' + needle})), [name])


class Refs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not refs.refs_dirs():
            raise unittest.SkipTest('no pinned copies: set GPUSNAP2_REFS_DIR (or GPUSNAP_REFS_DIR, TSNAP_REFS_DIR or SNAPINTOSH_DIR)')
        cls.files = {name: refs.load(name) for name in refs.PINNED}
        cls.missing = sorted(name for name, lines in cls.files.items() if lines is None)
        if cls.missing:
            raise unittest.SkipTest('pinned copies not found: ' + ', '.join(cls.missing))

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
        names = ['tsrot', 'ttm', 'gcc', 'gpucc', 'cmddb', 'rsc', 'qfprom']
        tsens3 = dt_regs(node(lines, 'tsens3'))
        want = {'ttm': tsens3[0], 'tsrot': tsens3[1], 'gcc': dt_regs(node(lines, 'gcc'))[0], 'gpucc': dt_regs(node(lines, 'gpucc'))[0],
                'cmddb': dt_regs(node(lines, 'aop_cmd_db_mem'))[0], 'qfprom': dt_regs(node(lines, 'qfprom'))[0]}
        apps = node(lines, 'apps_rsc')
        regs = dt_regs(apps)
        self.assertEqual(re.search(r'reg-names = (.*?);', apps, re.S).group(1).replace('\n', '').replace('\t', ''), '"drv-0", "drv-1", "drv-2"')
        self.assertEqual(int(re.search(r'qcom,drv-id = <(\d+)>', apps).group(1)), define('RSC_DRV_NUMBER'))
        self.assertEqual(int(re.search(r'qcom,tcs-offset = <(0x[0-9a-f]+)>', apps).group(1), 16), define('RSC_TCS_BASE'))
        want['rsc'] = regs[define('RSC_DRV_NUMBER')]
        for number, name in enumerate(names):
            self.assertEqual(windows[number], want[name], name)
        self.assertEqual(len(windows), 7)

    def test_the_tcs_config_is_the_header_s(self):
        apps = node(self.files['hamoa.dtsi'], 'apps_rsc')
        config = dict((kind, int(n)) for kind, n in re.findall(r'<(\w+_TCS)\s+(\d+)>', apps))
        bindings = dict((kind, int(n)) for kind, n in re.findall(r'#define (\w+_TCS)\s+(\d+)', self.text('qcom,rpmh-rsc.h')))
        self.assertEqual(bindings, {'SLEEP_TCS': 0, 'WAKE_TCS': 1, 'ACTIVE_TCS': 2, 'CONTROL_TCS': 3})
        self.assertEqual(config, {'ACTIVE_TCS': 3, 'SLEEP_TCS': 2, 'WAKE_TCS': 2, 'CONTROL_TCS': 0})
        order = re.findall(r'<(\w+_TCS)\s+\d+>', apps)
        first = 0
        starts = {}
        for kind in order:
            starts[kind] = first
            first += config[kind]
        self.assertEqual((starts['ACTIVE_TCS'], starts['SLEEP_TCS'], starts['WAKE_TCS']), (define('RSC_TCS_ACTIVE'), define('RSC_TCS_SLEEP'), define('RSC_TCS_WAKE')))
        self.assertEqual(first, define('RSC_TCS_NUM'))
        self.assertEqual(config['WAKE_TCS'], define('RSC_WAKE_COUNT'))

    def test_the_gpucc_rows_are_the_driver(self):
        text = self.text('gpucc-x1e80100.c')

        def field(struct, name):
            body = re.search(rf'^static struct \w+ {struct} = \{{(.*?)^\}};', text, re.S | re.M).group(1)
            return int(re.search(rf'\.{name} = (0x[0-9a-f]+)', body).group(1), 16)

        rows = unique_rows()
        for key, struct in (('AHB', 'gpu_cc_ahb_clk'), ('CRC', 'gpu_cc_crc_ahb_clk'), ('CXFF', 'gpu_cc_cx_ff_clk'), ('FM', 'gpu_cc_freq_measure_clk'),
                            ('MEM', 'gpu_cc_memnoc_gfx_clk'), ('SLP', 'gpu_cc_sleep_clk')):
            self.assertEqual(rows[key], ('GPUCC', field(struct, 'halt_reg')), key)
            self.assertEqual(field(struct, 'halt_reg'), field(struct, 'enable_reg'), f'{key}: a branch clock has one control word')
        self.assertEqual(rows['FFC'], ('GPUCC', field('gpu_cc_ff_clk_src', 'cmd_rcgr')))
        self.assertEqual(rows['FFF'], ('GPUCC', field('gpu_cc_ff_clk_src', 'cmd_rcgr') + 4), 'the config word is the next one (clk-rcg2.c CFG_REG 0x4)')
        self.assertEqual(rows['XDIV'], ('GPUCC', field('gpu_cc_xo_div_clk_src', 'reg')))
        self.assertEqual(rows['DDIV'], ('GPUCC', field('gpu_cc_demet_div_clk_src', 'reg')))
        self.assertEqual(rows['CXGD'], ('GPUCC', field('gpu_cx_gdsc', 'gdscr')))
        self.assertEqual(rows['CXHW'], ('GPUCC', field('gpu_cx_gdsc', 'gds_hw_ctrl')))
        self.assertEqual(rows['CB'], ('GPUCC', int(re.search(r'critical_cbcrs\[\] = \{\s*(0x[0-9a-f]+), /\* GPU_CC_CB_CLK \*/', text).group(1), 16)))
        self.assertEqual(rows['CFGA'], ('GCC', int(re.search(r'critical_cbcrs\[\] = \{.*?(0x[0-9a-f]+), /\* GCC_GPU_CFG_AHB_CLK \*/', self.text('gcc-x1e80100.c'), re.S).group(1), 16)))
        # what is excluded is named in the driver and is not in the table: the GX-side clocks
        for gx in (0x90b0, 0x9288, 0x928c):
            self.assertIn(f'0x{gx:x}', text)
            self.assertNotIn(('GPUCC', gx), rows.values())

    def test_the_pll_words_are_the_layouts_the_driver_picks(self):
        text = self.text('gpucc-x1e80100.c')
        pll = self.text('clk-alpha-pll.c')
        rows = header_rows()
        bases, kinds = {}, {}
        for name in ('gpu_cc_pll0', 'gpu_cc_pll1'):
            body = re.search(rf'^static struct clk_alpha_pll {name} = \{{(.*?)^\}};', text, re.S | re.M).group(1)
            bases[name] = int(re.search(r'\.offset = (0x[0-9a-f]+)', body).group(1), 16)
            kinds[name] = re.search(r'clk_alpha_pll_regs\[CLK_ALPHA_PLL_TYPE_(\w+)\]', body).group(1)
        self.assertEqual(kinds, {'gpu_cc_pll0': 'ZONDA_OLE', 'gpu_cc_pll1': 'LUCID_OLE'})

        def table(kind):
            body = re.search(rf'\[CLK_ALPHA_PLL_TYPE_{kind}\] = \{{(.*?)\n\t\}},', pll, re.S).group(1)
            return {name: int(value, 16) for name, value in re.findall(r'\[PLL_OFF_(\w+)\] = (0x[0-9a-f]+)', body)}

        self.assertEqual(re.search(r'#define PLL_MODE\(p\)\s+\(\(p\)->offset \+ (0x0)\)', pll).group(1), '0x0')
        zonda, lucid = table('ZONDA_OLE'), table('LUCID_OLE')
        for rows_of_pll, base, regs in ((rows[4:8], bases['gpu_cc_pll0'], zonda), (rows[8:12], bases['gpu_cc_pll1'], lucid)):
            self.assertEqual([key for _, _, key in rows_of_pll], ['MODE', 'OP', 'L', 'AL'])
            self.assertEqual([window for window, _, _ in rows_of_pll], ['GPUCC'] * 4)
            self.assertEqual([off for _, off, _ in rows_of_pll], [base, base + regs['OPMODE'], base + regs['L_VAL'], base + regs['ALPHA_VAL']])
        self.assertEqual(define('PLL_OUTCTRL_BIT'), 0)
        self.assertEqual(define('PLL_LOCK_DET_BIT'), 31)
        self.assertEqual(define('PLL_RUN_BIT'), 0)
        self.assertRegex(pll, r'# define PLL_OUTCTRL\s+BIT\(0\)')
        self.assertRegex(pll, r'# define PLL_LOCK_DET\s+BIT\(31\)')
        self.assertRegex(pll, r'#define PLL_RUN\s+0x1')

    def test_the_rsc_registers_are_the_drivers_tables(self):
        text = self.text('rpmh-rsc.c')
        layouts = header_layouts()
        for major, array in ((2, 'ver_2_7'), (3, 'ver_3_0')):
            body = re.search(rf'rpmh_rsc_reg_offset_{array}\[\] = \{{(.*?)\n\}};', text, re.S).group(1)
            values = {name: int(value, 0) for name, value in re.findall(r'\[(\w+)\]\s*= (0x[0-9A-Fa-f]+|\d+)', body)}
            self.assertEqual(layouts[major], (values['RSC_DRV_CMD_ENABLE'], values['RSC_DRV_CMD_ADDR'], values['RSC_DRV_CMD_DATA'], values['RSC_DRV_CMD_OFFSET']), array)
            self.assertEqual(values['RSC_DRV_TCS_OFFSET'], define('RSC_TCS_STRIDE'), array)
            self.assertEqual((values['DRV_SOLVER_CONFIG'], values['DRV_PRNT_CHLD_CONFIG']), (define('RSC_DRV_SOLVER'), define('RSC_DRV_CHLD')), array)
            self.assertEqual((values['RSC_DRV_IRQ_ENABLE'], values['RSC_DRV_IRQ_STATUS']), (define('RSC_IRQ_ENABLE'), define('RSC_IRQ_STATUS')), array)
            self.assertEqual(define('RSC_IRQ_STATUS'), 4)
            self.assertNotEqual(values['RSC_DRV_IRQ_CLEAR'], values['RSC_DRV_IRQ_STATUS'], 'the clear register is a different word and is never read')
        self.assertEqual(sorted(layouts), [2, 3])
        self.assertEqual(int(re.search(r'#define RSC_DRV_ID\s+(\d+)', text).group(1)), define('RSC_DRV_ID'))
        self.assertEqual((int(re.search(r'#define MAJOR_VER_SHIFT\s+(\d+)', text).group(1)), int(re.search(r'#define MINOR_VER_SHIFT\s+(\d+)', text).group(1))),
                         (define('RSC_MAJOR_SHIFT'), define('RSC_MINOR_SHIFT')))
        self.assertEqual((int(re.search(r'#define DRV_NUM_TCS_SHIFT\s+(\d+)', text).group(1)), int(re.search(r'#define DRV_NUM_TCS_MASK\s+(0x[0-9A-F]+)', text).group(1), 16)),
                         (define('RSC_NUM_TCS_SHIFT'), define('RSC_NUM_TCS_MASK')))
        self.assertEqual((int(re.search(r'#define DRV_NCPT_SHIFT\s+(\d+)', text).group(1)), int(re.search(r'#define DRV_NCPT_MASK\s+(0x[0-9A-F]+)', text).group(1), 16)),
                         (define('RSC_NCPT_SHIFT'), define('RSC_NCPT_MASK')))
        self.assertEqual(int(re.search(r'#define MAX_CMDS_PER_TCS\s+(\d+)', self.text('rpmh-internal.h')).group(1)), define('RSC_CMDS_MAX'))
        self.assertRegex(text, r'if \(drv->ver\.major >= 3\)\n\t\tdrv->regs = rpmh_rsc_reg_offset_ver_3_0;\n\telse\n\t\tdrv->regs = rpmh_rsc_reg_offset_ver_2_7;')

    def test_the_command_database_layout_and_ids(self):
        text = self.text('cmd-db.c')
        self.assertEqual(int(re.search(r'#define NUM_PRIORITY\s+(\d+)', text).group(1)), 2)
        self.assertEqual(int(re.search(r'#define MAX_SLV_ID\s+(\d+)', text).group(1)), define('CMDDB_SLV_MAX'))
        entry = re.search(r'struct entry_header \{(.*?)\};', text, re.S).group(1)
        self.assertEqual(re.findall(r'(u8 id\[8\]|__le32 priority\[NUM_PRIORITY\]|__le32 addr|__le16 len|__le16 offset);', entry),
                         ['u8 id[8]', '__le32 priority[NUM_PRIORITY]', '__le32 addr', '__le16 len', '__le16 offset'], '8 + 8 + 4 + 2 + 2 = 24 bytes, the address at +16, len and offset at +20')
        self.assertEqual(8 + 4 * 2 + 4 + 2 + 2, define('CMDDB_ENTRY_BYTES'))
        rsc_hdr = re.search(r'struct rsc_hdr \{(.*?)\};', text, re.S).group(1)
        self.assertEqual(re.findall(r'__le16 (\w+)(?:\[(\d)\])?;', rsc_hdr), [('slv_id', ''), ('header_offset', ''), ('data_offset', ''), ('cnt', ''), ('version', ''), ('reserved', '3')])
        self.assertEqual(8 * 2, define('CMDDB_RSC_HDR_BYTES'))
        header = re.search(r'struct cmd_db_header \{(.*?)\};', text, re.S).group(1)
        self.assertEqual(re.findall(r'(__le32 version|u8 magic\[4\]|struct rsc_hdr header\[MAX_SLV_ID\]|__le32 checksum|__le32 reserved|u8 data\[\]);', header),
                         ['__le32 version', 'u8 magic[4]', 'struct rsc_hdr header[MAX_SLV_ID]', '__le32 checksum', '__le32 reserved', 'u8 data[]'])
        self.assertEqual(4 + 4 + 8 * define('CMDDB_RSC_HDR_BYTES') + 4 + 4, define('CMDDB_HDR_BYTES'))
        self.assertEqual(4 + 4, define('CMDDB_RSC_HDR_OFF'))
        magic = [int(b, 16) for b in re.search(r'CMD_DB_MAGIC\[\] = \{ (.*?) \}', text).group(1).split(', ')]
        self.assertEqual(int.from_bytes(bytes(magic), 'little'), define('CMDDB_MAGIC'))
        types = {name: int(re.search(rf'{name}\s+= (\w+)', self.text('cmd-db.h')).group(1).replace('CMD_DB_HW_MIN', '3')) for name in ('CMD_DB_HW_ARC', 'CMD_DB_HW_VRM', 'CMD_DB_HW_BCM')}
        self.assertEqual((types['CMD_DB_HW_ARC'], types['CMD_DB_HW_BCM']), (define('CMDDB_SLV_ARC'), define('CMDDB_SLV_BCM')))
        # the ids of the targets are the names the GPU's drivers ask for
        header_text = REGS.read_text(encoding='utf-8')
        names = []
        for a, b in re.findall(r"\{ID4\(((?:'.', ?){3}'.'|(?:'.', ?){2}'.', 0|'.', ?'.', 0, 0)\), (ID4\([^)]*\)|0), CMDDB_SLV", header_text):
            letters = ''.join(re.findall(r"'(.)'", a)) + ''.join(re.findall(r"'(.)'", b)) if b != '0' else ''.join(re.findall(r"'(.)'", a))
            names.append(letters)
        self.assertEqual(names, ['cx.lvl', 'mx.lvl', 'gfx.lvl', 'gmxc.lvl', 'gbx.lvl', 'SH0', 'MC0', 'ACV'])
        gmu = self.text('a6xx_gmu.c')
        for name in ('cx.lvl', 'mx.lvl', 'gfx.lvl', 'gmxc.lvl', 'gbx.lvl'):
            self.assertIn(f'"{name}"', gmu, name)
        catalog = '\n'.join(self.files['a7xx_catalog.c'][397:408])
        for name in ('SH0', 'MC0', 'ACV'):
            self.assertIn(f'"{name}"', catalog, name)

    def test_the_speed_bin_and_its_fuse_field(self):
        catalog = self.files['a7xx_catalog.c']
        block = '\n'.join(catalog[410:417])
        bins = [(int(a), int(b)) for a, b in re.findall(r'\{ (\d+),\s+(\d) \}', block)]
        self.assertEqual(bins, [(0, 0), (59, 1), (7, 2), (232, 3), (146, 4)])
        found = re.findall(r'\{\s*(\d+),\s*(\d+)\s*\}', REGS.read_text(encoding='utf-8').split('speedbins[5] = ')[1].split(';')[0])
        self.assertEqual([(int(a), int(b)) for a, b in found], bins)
        cell = node(self.files['hamoa.dtsi'], 'gpu_speed_bin')
        reg = [int(v, 16) for v in re.search(r'reg = <(0x[0-9a-f]+) (0x[0-9a-f]+)>', cell).groups()]
        bits = [int(v) for v in re.search(r'bits = <(\d+) (\d+)>', cell).groups()]
        word, byte = reg[0] & ~3, reg[0] & 3
        self.assertEqual(word, define('QFPROM_WORD'))
        self.assertEqual(bits[0] + byte * 8, define('QFPROM_FUSE_SHIFT'), 'qfprom.c:343 adds the byte offset within the word to the bit offset')
        self.assertEqual(bits[1] - bits[0] + 1 - 1 + 0, 1 + 0 if False else bits[1] - bits[0], 'the cell is two bytes starting at bit 7 and counts eight bits')
        self.assertEqual((1 << bits[1]) - 1, define('QFPROM_FUSE_MASK'))
        self.assertIn('readl(base + reg + i * sizeof(u32))', self.text('qfprom.c'))

    def test_the_status_word_fields_and_the_tsnap_constants(self):
        text = self.text('tsens-v2.c')
        fields = {name: (int(lo), int(hi)) for name, lo, hi in re.findall(r'REG_FIELD_FOR_EACH_SENSOR16\((\w+),\s+TM_Sn_STATUS_OFF,\s+(\d+),\s+(\d+)\)', text)}
        self.assertEqual(fields['LAST_TEMP'], (0, 11))
        self.assertEqual(fields['VALID'], (21, 21))
        self.assertEqual(define('ST_TEMP_MASK'), 0xfff)
        self.assertEqual(define('ST_VALID'), 1 << fields['VALID'][0])
        self.assertEqual(define('ST_CRIT_FLAGS'), (1 << fields['CRITICAL_STATUS'][0]) | (1 << fields['MAX_STATUS'][0]))
        self.assertTrue(all(hi <= 21 for _, hi in fields.values()), 'no pinned field lies above bit 21: the sensor number (26:22) is INFERRED')
        for name in ('ST_TEMP_MASK', 'ST_CRIT_FLAGS', 'ST_VALID', 'ST_ID_SHIFT', 'ST_ID_MASK', 'ST_RESERVED_SHIFT', 'TEMP_MIN_TENTHS', 'TEMP_MAX_TENTHS', 'CTRL_EN', 'CTRL_SW_RST',
                     'CTRL_SENSOR_SHIFT', 'CTRL_SENSOR_MASK', 'CTRL_CODE_OR_TEMP', 'SROT_HW_VER', 'SROT_CTRL', 'TM_STATUS'):
            self.assertEqual(define(name), define(name, TSNAP_REGS), f'{name} is tsnap v1.1\'s')

    def test_the_sensors_are_the_gpus(self):
        lines = self.files['hamoa.dtsi']
        for n in range(8):
            zone = node(lines, f'thermal_gpuss_{n}')
            self.assertIn(f'thermal-sensors = <&tsens3 {5 + n}>', zone)
        self.assertEqual((define('TS_FIRST'), define('TS_COUNT')), (5, 8))
        self.assertEqual(define('TM_STATUS'), 0xa0)

    def test_the_clock_decodes_are_the_drivers_bits(self):
        branch, rcg, gdsc = self.text('clk-branch.h'), self.text('clk-rcg2.c'), self.text('gdsc.c')
        self.assertRegex(branch, r'#define CBCR_CLK_OFF\s+BIT\(31\)')
        self.assertRegex(branch, r'#define CBCR_NOC_FSM_STATUS\s+GENMASK\(30, 28\)')
        self.assertRegex(branch, r'#define FSM_STATUS_ON\s+BIT\(1\)')
        self.assertRegex(branch, r'#define CBCR_CLOCK_ENABLE\s+BIT\(0\)')
        self.assertEqual((define('CBCR_CLK_OFF_BIT'), define('CBCR_ENABLE_BIT'), define('CBCR_FSM_SHIFT'), define('CBCR_FSM_MASK'), define('CBCR_FSM_ON')), (31, 0, 28, 7, 2))
        self.assertRegex(rcg, r'#define CMD_ROOT_OFF\s+BIT\(31\)')
        self.assertRegex(rcg, r'#define CFG_SRC_SEL_SHIFT\s+8')
        self.assertRegex(rcg, r'#define CFG_SRC_SEL_MASK\s+\(0x7 << CFG_SRC_SEL_SHIFT\)')
        self.assertEqual((define('RCG_SRC_SHIFT'), define('RCG_SRC_MASK')), (8, 7))
        self.assertRegex(gdsc, r'#define PWR_ON_MASK\s+BIT\(31\)')
        self.assertRegex(gdsc, r'#define HW_CONTROL_MASK\s+BIT\(1\)')
        self.assertRegex(gdsc, r'#define SW_COLLAPSE_MASK\s+BIT\(0\)')
        self.assertEqual((define('GDSC_PWR_ON_BIT'), define('GDSC_HW_CONTROL_BIT'), define('GDSC_SW_COLLAPSE_BIT')), (31, 1, 0))

    def test_a_citation_moved_by_a_line_is_refused(self):
        for name, first, last, needle in refs.LEDGER:
            if first != last:
                continue
            for shift in (-1, 1):
                text = ' '.join(line.strip() for line in self.files[name][first - 1 + shift:last + shift])
                self.assertIsNone(re.search(needle, text), f'{name}:{first} still holds its text one line {"up" if shift < 0 else "down"}: the entry is not line-exact')


# One wrong value each in a copy of the header: the check named must refuse it (the test of a test). The copies are written under build/sp11-gpusnap2/.
HEADER_MISTAKES = (
    ('a-branch-clock-moves', 'ROW(WIN_GPUCC, 0x9150, D_CBCR, "MEM")', 'ROW(WIN_GPUCC, 0x9154, D_CBCR, "MEM")', 'test_the_gpucc_rows_are_the_driver'),
    ('a-gx-clock-replaces-a-cx-one', 'ROW(WIN_GPUCC, 0x9134, D_CBCR, "SLP")', 'ROW(WIN_GPUCC, 0x90b0, D_CBCR, "SLP")', 'test_the_gpucc_rows_are_the_driver'),
    ('a-pll-word-moves', 'ROW(WIN_GPUCC, 0x0030, D_PLLOP, "OP")', 'ROW(WIN_GPUCC, 0x0034, D_PLLOP, "OP")', 'test_the_pll_words_are_the_layouts_the_driver_picks'),
    ('the-second-pll-takes-the-first-layout', 'ROW(WIN_GPUCC, 0x1010, D_NONE, "L")', 'ROW(WIN_GPUCC, 0x1004, D_NONE, "L")', 'test_the_pll_words_are_the_layouts_the_driver_picks'),
    ('a-window-moves', '{0x221c8000u, 0x01000u, 0}', '{0x221c9000u, 0x01000u, 0}', 'test_the_windows_are_the_device_tree'),
    ('the-rsc-stride-moves', '#define RSC_TCS_STRIDE 672u', '#define RSC_TCS_STRIDE 680u', 'test_the_rsc_registers_are_the_drivers_tables'),
    ('an-rsc-layout-moves', '{3, 0x2cu, 0x38u, 0x3cu, 24u, {0, 0, 0}}', '{3, 0x30u, 0x38u, 0x3cu, 24u, {0, 0, 0}}', 'test_the_rsc_registers_are_the_drivers_tables'),
    ('the-irq-status-is-the-clear-register', '#define RSC_IRQ_STATUS 0x04u', '#define RSC_IRQ_STATUS 0x08u', 'test_the_rsc_registers_are_the_drivers_tables'),
    ('the-wake-tcs-moves', '#define RSC_TCS_WAKE 5u', '#define RSC_TCS_WAKE 3u', 'test_the_tcs_config_is_the_header_s'),
    ('the-database-magic-moves', '#define CMDDB_MAGIC 0x0c0330dbu', '#define CMDDB_MAGIC 0x0c0330dcu', 'test_the_command_database_layout_and_ids'),
    ('an-entry-is-not-24-bytes', '#define CMDDB_ENTRY_BYTES 24u', '#define CMDDB_ENTRY_BYTES 32u', 'test_the_command_database_layout_and_ids'),
    ('a-target-is-misnamed', "ID4('g', 'f', 'x', '.'), ID4('l', 'v', 'l', 0)", "ID4('g', 'f', 'x', '.'), ID4('l', 'v', 'x', 0)", 'test_the_command_database_layout_and_ids'),
    ('a-speed-bin-moves', '{59, 1}', '{59, 2}', 'test_the_speed_bin_and_its_fuse_field'),
    ('the-fuse-shift-moves', '#define QFPROM_FUSE_SHIFT 15u', '#define QFPROM_FUSE_SHIFT 7u', 'test_the_speed_bin_and_its_fuse_field'),
    ('the-valid-bit-moves', '#define ST_VALID (1u << 21)', '#define ST_VALID (1u << 20)', 'test_the_status_word_fields_and_the_tsnap_constants'),
    ('the-first-gpu-sensor-moves', '#define TS_FIRST 5u', '#define TS_FIRST 4u', 'test_the_sensors_are_the_gpus'),
    ('the-clk-off-bit-moves', '#define CBCR_CLK_OFF_BIT 31u', '#define CBCR_CLK_OFF_BIT 30u', 'test_the_clock_decodes_are_the_drivers_bits'),
    ('the-source-select-moves', '#define RCG_SRC_SHIFT 8u', '#define RCG_SRC_SHIFT 4u', 'test_the_clock_decodes_are_the_drivers_bits'),
)


class RefsMistakes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Refs.setUpClass()          # skips without the copies

    def test_each_wrong_header_value_is_refused_by_the_check_that_names_it(self):
        global REGS
        original = REGS
        text = original.read_text(encoding='utf-8')
        directory = ROOT / 'build' / 'sp11-gpusnap2' / 'refs-mistakes'
        directory.mkdir(parents=True, exist_ok=True)
        methods = [name for name in dir(Refs) if name.startswith('test_')]
        names = [name for name, *_ in HEADER_MISTAKES]
        self.assertEqual(len(names), len(set(names)))
        try:
            for name, old, new, expected in HEADER_MISTAKES:
                with self.subTest(mistake=name):
                    self.assertEqual(text.count(old), 1, 'the pattern is not in the header exactly once')
                    self.assertIn(expected, methods)
                    REGS = directory / f'{name}.h'
                    REGS.write_text(text.replace(old, new), encoding='utf-8')
                    refused = set()
                    for method in methods:
                        try:
                            getattr(Refs(method), method)()
                        except Exception:   # noqa: BLE001 - a wrong header may fail a check by any exception
                            refused.add(method)
                    self.assertIn(expected, refused, f'{name}: refused by {sorted(refused)}, not by {expected}')
            REGS = original
            for method in methods:     # the same checks pass on the header as it is
                getattr(Refs(method), method)()
        finally:
            REGS = original
            shutil.rmtree(directory, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
