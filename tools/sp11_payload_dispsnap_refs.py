# SPDX-License-Identifier: MIT
"""The pinned reference copies behind docs/SP11-PAYLOAD-DISPSNAP.md and the register table of payloads/dispsnap-regs.h, and how to read them from a test.

Four of the Linux files this payload leans on are the ones the Snapintosh fork keeps in build/sp11-stick-log/refs/ (git-ignored; docs/SP11-STICK-LOG.md
section 10 pins the revision and the SHA-256 of each). The others are fetched, read-only, at the same Linux revision (7475ea8b58616b33c04afb976cf0fbaad9dd63fb,
from https://raw.githubusercontent.com/torvalds/linux/<revision>/<path>) into build/sp11-dispsnap/refs/ of this tree, or into the directory DISPSNAP_REFS_DIR
names; the digests of the display files are the ones docs/SP11-DISPLAY-STUDY.md section 1 records as 16-digit prefixes (re-computed in full, and equal), except
clk-branch.c and common.c, which no table pins and whose digests are recorded here and in the payload's document. This module finds the copies
(DISPSNAP_REFS_DIR, then SNAPINTOSH_DIR/build/sp11-stick-log/refs, then this tree's build/sp11-dispsnap/refs), checks every digest, and offers:

  LEDGER      every file:line the document may cite, with what that line must show in the pinned copy. The document test holds each citation of the document
              to this list; tools/test-q1n1-sp11-payload-dispsnap-refs.py holds each entry of it to the files.
  extractors  the same registers read by NAME (a #define of a Linux file, the clock or GDSC struct of the dispcc driver), so that a register table whose line
              numbers are right and whose offsets are not is still caught.
  parse_rows  the register table of payloads/dispsnap-regs.h.

VERIFIED in this module means: a pinned file says so. It never means that the unit does. Nothing here reads hardware."""
import hashlib
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
LINUX_REVISION = '7475ea8b58616b33c04afb976cf0fbaad9dd63fb'

# file name -> (SHA-256 of the fetched bytes, where it is pinned). STICK = docs/SP11-STICK-LOG.md section 10, STUDY = docs/SP11-DISPLAY-STUDY.md section 1 (prefix of 16
# digits there), NONE = in no table (recorded here, in the document and in the report only).
PINNED = {
    'hamoa.dtsi': ('d5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0', 'STICK'),
    'gcc-x1e80100.c': ('f1c3779c7bc273dfe170ea2ff4d40f975083ee149e3b02a4f42d5939596eb775', 'STICK'),
    'clk-branch.h': ('bac7dcf51a0da5b27eaa0d4dc276f540fec80013bd4862cfbbc115a50161ef72', 'STICK'),
    'gdsc.c': ('a5a73fcc890f658b48a1e2dc015f3d47316d77b8c7853bbf999828f25a8c86b1', 'STICK'),
    'dispcc-x1e80100.c': ('d1c30db5bfda8b410c4052b9ebb4850ba93d71adce84d147aa074f972f071a03', 'STUDY'),
    'dpu_hw_intf.c': ('bfba5fb9089248f07e9e43b3dbc5a5a9c791ac24426efa1c237e053b033d8e21', 'STUDY'),
    'dpu_hw_ctl.c': ('d9c585e20e88d47a79911f15100eec2beaac0a5a6c202f6e80fa30e7fcf79909', 'STUDY'),
    'dpu_9_2_x1e80100.h': ('4676efe547032286419aef9addc847318cb52114e4581033ca70b96d4e8cfc1e', 'STUDY'),
    'msm_mdss.c': ('e6186a1bf87e87b5c5b2f46d4b6fe46934b3fcd44542ab790c8b1de300d72700', 'STUDY'),
    'clk-branch.c': ('d29259eb77a5d1d6a07adf4aa835588f8e04d1fa3c14be2b7d4162cce737abfa', 'NONE'),
    'common.c': ('ebefa181817ee8218b314218bbd94315ba239ff4f816a6565af3ec6aeed14226', 'NONE'),
}
# Linux path of every file (what a reader fetches the unpinned ones from).
LINUX_PATH = {
    'hamoa.dtsi': 'arch/arm64/boot/dts/qcom/hamoa.dtsi', 'gcc-x1e80100.c': 'drivers/clk/qcom/gcc-x1e80100.c', 'clk-branch.h': 'drivers/clk/qcom/clk-branch.h',
    'gdsc.c': 'drivers/clk/qcom/gdsc.c', 'dispcc-x1e80100.c': 'drivers/clk/qcom/dispcc-x1e80100.c', 'clk-branch.c': 'drivers/clk/qcom/clk-branch.c',
    'common.c': 'drivers/clk/qcom/common.c', 'dpu_hw_intf.c': 'drivers/gpu/drm/msm/disp/dpu1/dpu_hw_intf.c',
    'dpu_hw_ctl.c': 'drivers/gpu/drm/msm/disp/dpu1/dpu_hw_ctl.c', 'dpu_9_2_x1e80100.h': 'drivers/gpu/drm/msm/disp/dpu1/catalog/dpu_9_2_x1e80100.h',
    'msm_mdss.c': 'drivers/gpu/drm/msm/msm_mdss.c',
}
# The prefixes of the document's citations (`dc:1513`), and the file each names.
PREFIX = {'dt': 'hamoa.dtsi', 'gcc': 'gcc-x1e80100.c', 'dc': 'dispcc-x1e80100.c', 'gdsc': 'gdsc.c', 'cb': 'clk-branch.h', 'cbc': 'clk-branch.c', 'cmn': 'common.c',
          'hi': 'dpu_hw_intf.c', 'hc': 'dpu_hw_ctl.c', 'cat': 'dpu_9_2_x1e80100.h', 'mm': 'msm_mdss.c'}
CITATION = re.compile(r'\b(' + '|'.join(sorted(PREFIX, key=len, reverse=True)) + r'):(\d+)(?:-(\d+))?\b')

# What no pinned file says: the document's "What could not be verified" lists these ids and no others, and no register offset or bit position of the table
# or the code rests on an item of this list except where the item says so.
UNVERIFIED = {
    'UV1': 'what any display word holds on the unit, and whether the unit\'s EL2 stage-1 map reaches the MDSS, the DPU and the display clock controller: none has ever '
           'been read there, so whether a read faults, hangs the bus or raises an SError is UNKNOWN',
    'UV2': 'the offset of the MDSS hardware version: REG_MDSS_HW_VERSION is defined in a generated header that is not pinned (msm_mdss.c:283 reads it at the MDSS base); '
           '0 is the study\'s INFERRED value',
    'UV3': 'that the firmware\'s display driver sets the same bits as Linux: CTL_INTF_ACTIVE, the frame counter\'s enable and the timing words are read as Linux defines '
           'them; what the firmware wrote is the question the run asks',
    'UV4': 'that reading any word of the list has no side effect on the unit: no Linux code reads the eight timing words, the enable or the counter\'s enable, and the '
           'frame counter is read by Linux (hi:339, hi:491) without any acknowledgement; "no clear-on-read register is on the list" is INFERRED from that and from the A16 tool',
    'UV5': 'the state of the display-configuration NoC vote that makes the registers reachable (hamoa.dtsi:5574, "cpu-cfg"): it has no readable state, and the lit panel '
           'is the only evidence that it is up',
    'UV6': 'whether the GOP framebuffer is the scanout address of the DPU (the display goes through apps_smmu stream 0x1c00, hamoa.dtsi:5578): no SSPP register is read',
}


def refs_dirs():
    """The directories that may hold the pinned copies, in the order they are looked in."""
    dirs = []
    if os.environ.get('DISPSNAP_REFS_DIR'):
        dirs += [Path(p) for p in os.environ['DISPSNAP_REFS_DIR'].split(os.pathsep) if p]
    if os.environ.get('SNAPINTOSH_DIR'):
        dirs.append(Path(os.environ['SNAPINTOSH_DIR']) / 'build' / 'sp11-stick-log' / 'refs')
    dirs.append(ROOT / 'build' / 'sp11-dispsnap' / 'refs')
    return [d for d in dirs if d.is_dir()]


def locate(name):
    """The path of the pinned copy of `name`, or None."""
    for directory in refs_dirs():
        path = directory / name
        if path.is_file():
            return path
    return None


def available():
    """True when every pinned file is found."""
    return all(locate(name) for name in PINNED)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


_CACHE = {}


def lines_of(name):
    """The lines of the pinned copy of `name` (1-based access through line(name, n))."""
    if name not in _CACHE:
        path = locate(name)
        _CACHE[name] = path.read_text(encoding='utf-8', errors='replace').splitlines() if path else None
    return _CACHE[name]


def span(name, first, last=None):
    """The text of lines first..last (inclusive) of the pinned copy."""
    text = lines_of(name)
    last = first if last is None else last
    if text is None or first < 1 or last > len(text):
        return None
    return '\n'.join(text[first - 1:last])


# prefix:first[-last] -> (what the lines must show: a regular expression, every part of which must match somewhere in the span). The document may cite only these.
def _e(prefix, first, last, *patterns):
    key = f'{prefix}:{first}' + (f'-{last}' if last else '')
    return key, (PREFIX[prefix], first, last, patterns)


LEDGER = dict([
    # the windows and the nodes: hamoa.dtsi
    _e('dt', 758, 760, r'gcc: clock-controller@100000', r'reg = <0 0x00100000 0 0x200000>'),
    _e('dt', 5553, 5557, r'mdss: display-subsystem@ae00000', r'reg = <0 0x0ae00000 0 0x1000>'),
    _e('dt', 5560, 5562, r'<&dispcc DISP_CC_MDSS_AHB_CLK>', r'<&gcc GCC_DISP_HF_AXI_CLK>', r'<&dispcc DISP_CC_MDSS_MDP_CLK>'),
    _e('dt', 5574, None, r'"cpu-cfg"'),
    _e('dt', 5578, None, r'iommus = <&apps_smmu 0x1c00 0x2>'),
    _e('dt', 5589, 5593, r'mdss_mdp: display-controller@ae01000', r'reg = <0 0x0ae01000 0 0x8f000>'),
    _e('dt', 5633, 5639, r'port@5', r'mdss_intf5_out', r'<&mdss_dp3_in>'),
    _e('dt', 6022, 6026, r'dispcc: clock-controller@af00000', r'reg = <0 0x0af00000 0 0x20000>'),
    # the clock files
    _e('gcc', 7447, None, r'0x27004, /\* GCC_DISP_AHB_CLK \*/'),
    _e('dc', 792, 808, r'disp_cc_mdss_ahb_clk = ', r'halt_reg = 0x80a8', r'enable_reg = 0x80a8', r'BRANCH_HALT,'),
    _e('dc', 1332, 1348, r'disp_cc_mdss_mdp_clk = ', r'halt_reg = 0x800c', r'enable_reg = 0x800c', r'BRANCH_HALT,'),
    _e('dc', 1512, 1522, r'struct gdsc mdss_gdsc', r'gdscr = 0x9000', r'HW_CTRL \| RETAIN_FF_ENABLE'),
    _e('gdsc', 21, None, r'PWR_ON_MASK\s+BIT\(31\)'),
    _e('gdsc', 26, 27, r'HW_CONTROL_MASK\s+BIT\(1\)', r'SW_COLLAPSE_MASK\s+BIT\(0\)'),
    _e('gdsc', 61, 91, r'gdsc_check_status', r'reg = sc->gdscr;', r'val & PWR_ON_MASK'),
    _e('gdsc', 127, 141, r'gdsc_update_collapse_bit', r'reg = sc->gdscr;', r'mask = SW_COLLAPSE_MASK;', r'regmap_update_bits\(sc->regmap, reg, mask'),
    _e('cb', 63, 71, r'CBCR_CLK_OFF\s+BIT\(31\)', r'CBCR_NOC_FSM_STATUS\s+GENMASK\(30, 28\)', r'FSM_STATUS_ON\s+BIT\(1\)', r'CBCR_CLOCK_ENABLE\s+BIT\(0\)'),
    _e('cbc', 54, 58, r'if \(enabling\)', r'CBCR_CLK_OFF', r'FIELD_GET\(CBCR_NOC_FSM_STATUS, val\) == FSM_STATUS_ON'),
    _e('cmn', 317, 318, r'for \(i = 0; i < data->num_clk_cbcrs; i\+\+\)', r'qcom_branch_set_clk_en\(regmap, data->clk_cbcrs\[i\]\)'),
    # the display driver
    _e('cat', 28, 54, r'x1e80100_ctl\[\]', r'"ctl_0"', r'\.base = 0x15000, \.len = 0x290', r'"ctl_5"', r'\.base = 0x1a000, \.len = 0x290'),
    _e('cat', 350, 356, r'"intf_5"', r'\.base = 0x39000, \.len = 0x280', r'\.type = INTF_DP', r'MSM_DP_CONTROLLER_3'),
    _e('cat', 414, 417, r'x1e80100_mdss_ver', r'\.core_major_ver = 9', r'\.core_minor_ver = 2'),
    _e('hi', 17, 75, r'INTF_TIMING_ENGINE_EN\s+0x000', r'INTF_CONFIG\s+0x004', r'INTF_HSYNC_CTL\s+0x008', r'INTF_VSYNC_PERIOD_F0\s+0x00C', r'INTF_DISPLAY_V_START_F0\s+0x01C',
       r'INTF_DISPLAY_V_END_F0\s+0x024', r'INTF_ACTIVE_V_START_F0\s+0x02C', r'INTF_ACTIVE_V_END_F0\s+0x034', r'INTF_DISPLAY_HCTL\s+0x03C', r'INTF_ACTIVE_HCTL\s+0x040',
       r'INTF_CONFIG2\s+0x060', r'INTF_FRAME_LINE_COUNT_EN\s+0x0A8', r'INTF_FRAME_COUNT\s+0x0AC', r'INTF_LINE_COUNT\s+0x0B0', r'INTF_MISR_SIGNATURE\s+0x184',
       r'INTF_STATUS\s+0x26C'),
    _e('hi', 123, None, r'DPU_REG_READ\(c, INTF_CONFIG\)'),
    _e('hi', 257, None, r'DPU_REG_WRITE\(c, INTF_FRAME_LINE_COUNT_EN, 0x3\)'),
    _e('hi', 296, None, r'DPU_REG_READ\(c, INTF_CONFIG\)'),
    _e('hi', 333, 335, r'DPU_REG_READ\(c, INTF_STATUS\) & BIT\(0\)', r'DPU_REG_READ\(c, INTF_TIMING_ENGINE_EN\)'),
    _e('hi', 339, None, r'DPU_REG_READ\(c, INTF_FRAME_COUNT\)'),
    _e('hi', 491, None, r'DPU_REG_READ\(c, INTF_FRAME_COUNT\)'),
    _e('hi', 593, None, r'DPU_REG_READ\(&intf->hw, INTF_CONFIG2\)'),
    _e('hc', 35, None, r'CTL_INTF_ACTIVE\s+0x0F4'),
    _e('hc', 592, None, r'DPU_REG_READ\(c, CTL_INTF_ACTIVE\)'),
    _e('hc', 700, None, r'DPU_REG_READ\(c, CTL_INTF_ACTIVE\)'),
    _e('mm', 241, 244, r'MDSS_HW_VER\(major, minor, step\)', r'\(\(major\) & 0xf\) << 28', r'\(\(minor\) & 0xfff\) << 16'),
    _e('mm', 276, 283, r'Register access requires MDSS_MDP_CLK', r'readl_relaxed\(msm_mdss->mmio \+ REG_MDSS_HW_VERSION\)'),
])


def ledger_index():
    """{citation text: (file, first, last, patterns)} of the ledger."""
    return {key: (name, first, last, patterns) for key, (name, first, last, patterns) in LEDGER.items()}


def cited(text):
    """The citations of a document, as the ledger writes them (`dc:792-808`)."""
    return [f'{prefix}:{first}' + (f'-{last}' if last else '') for prefix, first, last in CITATION.findall(text)]


def ledger_problems(key):
    """Why the pinned copy does not show what the ledger says at `key`, or []."""
    name, first, last, patterns = LEDGER[key]
    text = span(name, first, last)
    if text is None:
        return [f'{key}: the pinned copy of {name} is missing or has fewer lines']
    return [f'{key}: {name}:{first}-{last or first} does not show /{pattern}/' for pattern in patterns if not re.search(pattern, text)]


# ---- The register table of the payload -------------------------------------------------------------------------------------------------------------
ROW = re.compile(r'^\s*ROW\((WIN_\w+), ([^,]+(?:\([^)]*\))?[^,]*), (D_\w+), ([^,]+), "(\w+)"\),', re.M)


def parse_rows(regs_text):
    """[(key, window, offset expression, decode, flags)] of the table of the header, in order."""
    return [(key, window, expression.strip(), dec, flags.strip()) for window, expression, dec, flags, key in ROW.findall(regs_text)]


def defines(regs_text):
    """{NAME: int} of the `#define NAME 0x..u` / decimal constants of the header (the ones that are plain numbers)."""
    out = {}
    for name, value in re.findall(r'^#define (\w+) (0x[0-9a-fA-F]+|\d+)u?\b', regs_text, re.M):
        out[name] = int(value, 0)
    return out


def row_offset(regs_text, expression):
    """The numeric offset of a row's expression: a named constant, INTF(<constant>) or CTL(<n>)."""
    d = defines(regs_text)
    found = re.fullmatch(r'INTF\((\w+)\)', expression)
    if found:
        return d['INTF_PAGE_OFF'] + d[found.group(1)]
    found = re.fullmatch(r'CTL\((\d+)\)', expression)
    if found:
        return d['CTL_FIRST_OFF'] + d['CTL_STEP'] * int(found.group(1)) + d['CTL_INTF_ACTIVE_OFF']
    return d[expression]


def windows_of(regs_text):
    """[(base, size)] of the window table, in order, and the names."""
    body = re.search(r'windows\[WINDOWS\] = \{(.*?)\};', regs_text, re.S).group(1)
    return [(int(b, 16), int(s, 16)) for b, s in re.findall(r'\{(0x[0-9a-fA-F]+)u, (0x[0-9a-fA-F]+)u, 0\}', body)]


def window_names(regs_text):
    return re.findall(r'"(\w+)"', re.search(r'window_name\[WINDOWS\]\[\d+\] = \{(.*?)\};', regs_text, re.S).group(1))


# ---- The same facts read from the pinned files by name ---------------------------------------------------------------------------------------------
def define_value(name, symbol):
    """The integer a `#define <symbol> <value>` of the pinned file gives (0x.. or decimal), or None."""
    text = '\n'.join(lines_of(name) or [])
    found = re.search(rf'^\s*#define\s+{re.escape(symbol)}\s+(0[xX][0-9a-fA-F]+|\d+)\b', text, re.M)
    return int(found.group(1), 0) if found else None


def bit_define(name, symbol):
    """The bit number a `#define <symbol> BIT(n)` of the pinned file gives, or None."""
    text = '\n'.join(lines_of(name) or [])
    found = re.search(rf'^\s*#define\s+{re.escape(symbol)}\s+BIT\((\d+)\)', text, re.M)
    return int(found.group(1)) if found else None


def genmask(name, symbol):
    """(high, low) of a `#define <symbol> GENMASK(h, l)` of the pinned file, or None."""
    text = '\n'.join(lines_of(name) or [])
    found = re.search(rf'^\s*#define\s+{re.escape(symbol)}\s+GENMASK\((\d+), (\d+)\)', text, re.M)
    return (int(found.group(1)), int(found.group(2))) if found else None


def struct_field(name, struct, field, kind='clk_branch'):
    """The integer a field of a named `static struct <kind> <struct> = {` of the pinned file gives (first match inside the struct), or None."""
    text = '\n'.join(lines_of(name) or [])
    found = re.search(rf'static struct {kind} {re.escape(struct)} = \{{(.*?)\n\}};', text, re.S)
    if not found:
        return None
    value = re.search(rf'\.{re.escape(field)} = (0x[0-9a-fA-F]+)', found.group(1))
    return int(value.group(1), 16) if value else None


def catalog_base(block):
    """The `.base` of a catalog block of dpu_9_2_x1e80100.h by its name ("intf_5", "ctl_0"), or None."""
    text = '\n'.join(lines_of('dpu_9_2_x1e80100.h') or [])
    found = re.search(rf'\.name = "{re.escape(block)}", \.id = \w+,\s*\.base = (0x[0-9a-fA-F]+), \.len = (0x[0-9a-fA-F]+)', text)
    return (int(found.group(1), 16), int(found.group(2), 16)) if found else None


def dt_reg(label_pattern, which=0):
    """(base, size) of the `which`-th reg pair of the node of hamoa.dtsi whose header line matches `label_pattern`, or None."""
    text = '\n'.join(lines_of('hamoa.dtsi') or [])
    found = re.search(rf'{label_pattern}[^\n]*\{{[^}}]*?reg = <((?:0 0x[0-9a-fA-F]+ 0 0x[0-9a-fA-F]+[,>\s]*)+)', text)
    if not found:
        return None
    pairs = re.findall(r'0 (0x[0-9a-fA-F]+) 0 (0x[0-9a-fA-F]+)', found.group(1))
    return (int(pairs[which][0], 16), int(pairs[which][1], 16)) if len(pairs) > which else None
