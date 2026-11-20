<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `dispsnap`: the evidence (safety rules and their seeded bugs, tests, QEMU, the pinned files)

**EXPERIMENTAL, hardware NOT RUN.** This is the second document of the payload: [SP11-PAYLOAD-DISPSNAP.md](SP11-PAYLOAD-DISPSNAP.md) has the registers, the gates, the page and what each outcome would mean; this one holds what shows that the code does what that one says, on a host. Nothing here ran on the Surface Pro 11, and a green test is evidence about the host model and the compiled code only (VERIFIED by a host test that ran; never OBSERVED on the unit).

## Safety rules, each with the seeded bug that must be refused

Each rule is a statement about the code; each seeded bug edits a copy of the sources and must be rejected by the suites it names, for its own reason (`tools/sp11_payload_dispsnap_mutants.py`: `harness`, `ir`, `binary`, `refs`).

| Rule | Where | Seeded bugs |
| --- | --- | --- |
| Every device access is the runner's guarded `load32`; no plain load | `load()` | `unguarded-load` |
| No store reaches a device, the framebuffer or RAM outside the payload's own stack; no writable global | IR audit, binary check, host trap | `store-to-window`, `store-to-framebuffer`, `store-through-args`, `writable-global` |
| The framebuffer the page is drawn in is never read | host trap, IR audit | `framebuffer-read` |
| Only the table's addresses are loaded; a window the table does not have is refused before the table is indexed | `rd32()`, the harness's own list | `window-range-unchecked`, `far-offset-read`, `line-counter-in-place-of-frame-counter` |
| No barrier, no SMC, no MSR, no system register but CurrentEL and CNTFRQ_EL0 | the `dispsnap` policy | `barrier-inserted`, `smc-inserted`, `msr-inserted`, `extra-sysreg` |
| DISPCC is read only while the display register clock runs; a failed read is `DAHBERR`, not `DAHB` | `gate_reason()`, `ahb_reason()` | `display-register-clock-gate-removed`, `dahb-failed-read-reported-as-off` |
| The MDSS and the DPU are read only on `DISP=ON`, and a context nobody initialised is closed | `disp_eval()`, `gate_reason()` | `display-gate-removed`, `display-gate-ignores-hwctl`, `display-gate-ignores-swcollapse`, `display-gate-ignores-pwr-on`, `display-gate-needs-one-clock`, `display-gate-unknown-is-known`, `display-verdict-zero-is-on`, `gated-reason-swapped`, `gate-clock-count-drift` |
| A gate opens on proof only: a word that was not read or is all ones, a clock without ENABLE or with CLK_OFF, proves nothing | `word_ok()`, `clock_runs()` | `word-ok-accepts-all-ones`, `clock-ignores-clk-off`, `clock-ignores-enable` |
| The DPU is read only behind a hardware version that is neither all ones nor zero | `gate_reason()` | `version-gate-removed`, `version-zero-accepted`, `ver-failed-read-reported-as-zero` |
| The frame counter is read only when its enable says it counts | `do_line()`, the table's flag | `frame-counter-read-without-enable`, `frame-counter-enable-zero-counts`, `frame-counter-enable-all-ones-counts`, `frame-counter-flag-dropped` |
| A `NEXT` line before each block of reads, and no read without it | `snapshot_one()`, `snapshot_two()` | `no-next-line`, `no-next-gcc`, `no-next-mdss`, `no-next-dpu`, `no-next-wait`, `read-without-next`, `s2-without-next`, `s2-note-dropped` |
| A line is read whole and printed before the first load of the next; the verdict goes out before any MDSS word | `do_line()`, the line table | `block-read-then-printed`, `verdict-line-dropped` |
| The first abort in a window ends its reads; nothing is retried; the code of the abort is printed | `rd32()`, `side()` | `retry-after-fault`, `dead-window-ignored`, `fault-code-lost` |
| At most 34 lines and 48 loads; the closing lines are never crowded out | `emit()`, `load()` | `line-overflow`, `closing-crowded-out`, `load-cap-ignored` |
| The wait waits on the counter, is bounded, and a dead counter and a slow one are different statements | `delay_ticks()`, `snapshot_two()` | `wait-zero`, `unbounded-wait`, `backwards-counter-ignored`, `spin-bound-too-small`, `spin-bound-removed`, `spin-bound-passed-as-success`, `spin-token-reused` |
| Snapshot 2 reads again only what snapshot 1 read, in windows that had not aborted, behind its own gates, and the frame counter is no drift | `revisit()`, `s2_dpu_reason()`, `drift_report()` | `s2-dispcc-gate-removed`, `s2-dpu-gate-removed`, `s2-dpu-gate-judged-by-snapshot-1`, `s2-dead-window-visited`, `s2-reads-other-interface-words`, `drift-counts-the-frame-counter` |
| `DT` is the counter ticks between the two readings of the frame counter | `read_row()`, `s2_line()` | `dt-missing`, `dt-from-the-wrong-reading` |
| The `MAP` and `GOP` lines say what the loads used and what the runner drew in | `header_lines()` | `map-base-lies`, `map-intf-index-wrong`, `map-ctl-step-wrong`, `gop-swapped` |
| Every offset of the study's list is the pinned file's (the A16's neighbours are refused) | the register table, the harness's own list | `dahb-offset-next-word`, `gdsc-offset-drift`, `ahbc-offset-a16`, `mdpc-offset-a16`, `version-offset-drift`, `status-reads-avr-control`, `enable-offset-drift`, `config2-offset-drift`, `flc-offset-drift`, `timing-offset-f1` |
| The geometry of the DPU window is the catalog's | the register table | `ctl-register-offset-drift`, `ctl-first-page-drift`, `ctl-step-drift`, `intf-page-is-intf-6` |
| Every window is the device tree's, and every row names its own | the window table | `gcc-window-base-drift`, `dispcc-window-base-drift`, `mdss-window-base-drift`, `dpu-window-base-drift`, `dpu-window-size-drift`, `window-names-swapped`, `mdss-and-dispcc-rows-swapped` |
| A word that cannot be taken at its bit 31 says so | `cell_is_odd()`, `side()`, `put_bits()` | `cbcr-polarity`, `gdsc-polarity`, `all-ones-clock-decoded`, `enable-clear-decoded-as-on`, `fsm-on-clk-off-decoded`, `all-ones-gdsc-decoded`, `all-ones-field-decoded` |
| Every bit position is the pinned macro's | the header | `cbcr-clk-off-bit`, `cbcr-enable-bit`, `gdsc-pwr-on-bit`, `gdsc-sw-collapse-bit`, `gdsc-hw-control-bit`, `version-major-shift`, `version-minor-shift` |

## Tests

| Command | What it holds |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload-dispsnap.py` | `Harness`: the native host test under ASan and UBSan, the suites `unit`, `cold`, `gate`, `faults`, `storm`, `drift`, `stream`, `frames`, `counter`, `el` and `budget`, with smaller line and load caps (the `caps` suite), and with a small bound on the wait (the `spin` suite). `CompiledCode`: the IR audit (`tools/sp11_payload_dispsnap_audit.py`), the `dispsnap` policy on the linked binary, the stack, two builds that are the same bytes, the manifest chain. `Mutants`: 104 seeded bugs. `Doc`: both documents against the table, the pages, the numbers and the ledger |
| `python3 tools/test-q1n1-sp11-payload-dispsnap-refs.py` | the pinned Linux files: every digest, every cited file:line, every offset by name, the windows, the catalog numbers; a SKIP, never a pass, without them |
| `python3 tools/test-q1n1-sp11-payload-qemu-dispsnap.py` | the structural run behind the runner under QEMU's EDK2 shell |
| the Snapintosh tree's `python3 tools/test-sp11-dispsnap-parse.py` | the host parser and the study's function on hand-made pages and, with the q1n1 tree, on the pages of this host model |

The host model has one author with the payload (a common mode, stated in the payload's document); its list of addresses was written from the study's dump list, apart from the payload's table, and the pinned-copy test holds the table to the Linux files by name.

### What QEMU shows

Behind the runner under QEMU's EDK2 shell (`virt`, 512 MiB, a real ExitBootServices and a real EL2), none of the blocks exists: GCC's window lies in the machine's flash, which reads back the firmware's own bytes, and the display blocks lie in an address range the machine does not populate. What the page shows there is the firmware's and the machine's, not a model of the display, and the test pins no value of it; it holds what the payload must do for the words that were printed (which blocks are read, the gate lines, the loads, the counters of the runner). The QEMU run has no fault that the unit's guard would have to recover as such. OBSERVED (QEMU, EDK2; EXPERIMENTAL, a model of nothing the unit does):

<!-- qemu-lines -->
```
PAYLOAD DISPSNAP READ ONLY EL=2 HZ=<HZ> GAP=8 S
PAYLOAD DISPSNAP KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=BIT 31 NOT TRUSTED NO STORE NO AUX NO IRQ STATUS
PAYLOAD DISPSNAP GOP W=<W> H=<H> STRIDE=<S> FMT=<F>
PAYLOAD DISPSNAP MAP GCC=0X100000 DISPCC=0XAF00000 MDSS=0XAE00000 DPU=0XAE01000
PAYLOAD DISPSNAP MAP INTF=5 AT=0X39000 CTL=0X15000 STEP=0X1000 REG=0XF4
PAYLOAD DISPSNAP NEXT GCC
PAYLOAD DISPSNAP NEXT WAIT 8 S
PAYLOAD DISPSNAP NEXT S2 GCC
PAYLOAD DISPSNAP END LOADS=<L> FAULTS=<F> SKIPS=<S> BLK=<B> CUTS=0 GAP_MS=<MS> LINES=<N>
```
<!-- /qemu-lines -->

`<HZ>`, `<W>`, `<H>`, `<S>`, `<F>`, `<L>`, `<B>`, `<MS>` and `<N>` stand for values the firmware or the run gives, which are not stable.

## The pinned files

Linux at `7475ea8b58616b33c04afb976cf0fbaad9dd63fb`. The files outside the Snapintosh fork's log refs were fetched read-only from `raw.githubusercontent.com/torvalds/linux/<revision>/<path>` and their digests re-computed; those the study lists equal its 16-digit prefixes; `drivers/clk/qcom/clk-branch.c` and `drivers/clk/qcom/common.c` are in no table. Only facts (offsets, field positions, names, numbers) are used; no text or code is copied. The prefixes of the document's citations: `dt` hamoa.dtsi, `gcc` gcc-x1e80100.c, `dc` dispcc-x1e80100.c, `gdsc` gdsc.c, `cb` clk-branch.h, `cbc` clk-branch.c, `cmn` common.c, `hi` dpu_hw_intf.c, `hc` dpu_hw_ctl.c, `cat` dpu_9_2_x1e80100.h, `mm` msm_mdss.c.

| File | Path | SHA-256 |
| --- | --- | --- |
| `hamoa.dtsi` | `arch/arm64/boot/dts/qcom/hamoa.dtsi` | `d5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0` |
| `gcc-x1e80100.c` | `drivers/clk/qcom/gcc-x1e80100.c` | `f1c3779c7bc273dfe170ea2ff4d40f975083ee149e3b02a4f42d5939596eb775` |
| `clk-branch.h` | `drivers/clk/qcom/clk-branch.h` | `bac7dcf51a0da5b27eaa0d4dc276f540fec80013bd4862cfbbc115a50161ef72` |
| `gdsc.c` | `drivers/clk/qcom/gdsc.c` | `a5a73fcc890f658b48a1e2dc015f3d47316d77b8c7853bbf999828f25a8c86b1` |
| `dispcc-x1e80100.c` | `drivers/clk/qcom/dispcc-x1e80100.c` | `d1c30db5bfda8b410c4052b9ebb4850ba93d71adce84d147aa074f972f071a03` |
| `dpu_hw_intf.c` | `drivers/gpu/drm/msm/disp/dpu1/dpu_hw_intf.c` | `bfba5fb9089248f07e9e43b3dbc5a5a9c791ac24426efa1c237e053b033d8e21` |
| `dpu_hw_ctl.c` | `drivers/gpu/drm/msm/disp/dpu1/dpu_hw_ctl.c` | `d9c585e20e88d47a79911f15100eec2beaac0a5a6c202f6e80fa30e7fcf79909` |
| `dpu_9_2_x1e80100.h` | `drivers/gpu/drm/msm/disp/dpu1/catalog/dpu_9_2_x1e80100.h` | `4676efe547032286419aef9addc847318cb52114e4581033ca70b96d4e8cfc1e` |
| `msm_mdss.c` | `drivers/gpu/drm/msm/msm_mdss.c` | `e6186a1bf87e87b5c5b2f46d4b6fe46934b3fcd44542ab790c8b1de300d72700` |
| `clk-branch.c` | `drivers/clk/qcom/clk-branch.c` | `d29259eb77a5d1d6a07adf4aa835588f8e04d1fa3c14be2b7d4162cce737abfa` |
| `common.c` | `drivers/clk/qcom/common.c` | `ebefa181817ee8218b314218bbd94315ba239ff4f816a6565af3ec6aeed14226` |
