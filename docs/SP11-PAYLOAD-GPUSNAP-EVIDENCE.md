<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `gpusnap`: the evidence (safety rules and their seeded bugs, tests, QEMU, the pinned files)

The evidence behind [SP11-PAYLOAD-GPUSNAP.md](SP11-PAYLOAD-GPUSNAP.md), which says what the payload reads, what its page means and how it is chained. The two documents are held to the sources together by
`tools/test-q1n1-sp11-payload-gpusnap.py`. Evidence labels as there: VERIFIED (a pinned Linux file says so; never "it was run"), OBSERVED, INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN.
**EXPERIMENTAL; hardware NOT RUN:** every result named here is a host, compiled-code or QEMU result, and none says anything about the unit.

## Safety rules, each with the seeded bug that must be refused

| Rule | How it is kept | Seeded bugs (`tools/sp11_payload_gpusnap_mutants.py`) the suites must reject, each for its own reason |
| --- | --- | --- |
| no store but to the payload's own stack, and no load but through `load32` | no store sink exists in the source; the IR audit demands no `inttoptr` (a load through one as well as a store), an alloca or parameter root for every store and no pointer kept in memory; the host test traps any access that reaches a window except through `load32`; the `gpusnap` policy (`read_only`) proves the same from the disassembly | `store-to-window`, `unguarded-load`, `store-through-args`, `writable-global` |
| no system register but CurrentEL and CNTFRQ_EL0, no `smc`, no barrier | the model rejects any other register; the policy checks the binary and refuses the other payloads' binaries | `barrier-inserted`, `smc-inserted`, `msr-inserted`, `extra-sysreg` |
| only the registers of the table, in the window and at the offset the pinned file gives; no register of the GPU window | the host test holds every load to its own list of (window, offset) and the loads of a run to exactly that list (the harness's list and the payload's table share one author: common mode; an independent reviewer checked the register list against the pinned sources for v1.1 only); the pinned-copy test reads every offset by name; a window number the table does not have is refused before the table is indexed | `gx-register-read`, `unlisted-offset`, `window-range-unchecked`, `gcc-offset-drift`, `gpucc-offset-drift`, `rscc-offset-drift`, `tcs-offset-without-seqmem`, `smmu-offset-drift`, `cxmisc-offset-drift`, `gmu-window-offset-drift`, `window-size-drift` |
| a wrong base is refused for **every** window, and so is a swap of two windows or roles | the same list; the pinned-copy test checks each window against the device tree and each row against the window it names | `gcc-window-base-drift`, `gpucc-window-base-drift`, `cxmisc-window-base-drift`, `gmu-window-base-drift`, `rscc-window-base-drift`, `smmu-window-base-drift`, `gmu-rscc-windows-swapped`, `gpucc-cxmisc-windows-swapped`, `cx-gdscr-status-offsets-swapped`, `window-names-swapped`, `ahb-gate-reads-wrong-word` |
| GPUCC is read only while the CFG AHB clock runs, in either snapshot | the model reads `CFGA` in both snapshots and rejects any GPUCC load while it does not run | `ahb-gate-removed`, `s2-gpucc-gate-removed` |
| the blocks behind the CX domain are read only on `CX=ON`; an input that was not read is never a pass | the gate tests in both directions: each input flipped alone must close it, and the all-ones, aborted and skipped inputs give `CX=UNK`; a context nobody initialised (all zero) opens no CX block, because `UNK` is the zero verdict | `cx-gate-removed`, `cx-gate-ignores-hwctl`, `cx-gate-ignores-swcollapse`, `cx-gate-ignores-pwr-on`, `cx-gate-needs-one-clock`, `cx-gate-unknown-is-known`, `cx-verdict-zero-is-on`, `word-ok-accepts-all-ones`, `gated-reason-swapped` |
| a gate input that could not be read is never reported as the thing it gates on | an abort at `CFGA`, at an SMMU clock and at a clock of the seven must print `AHBERR`, `SMERR` and `CX=UNK` | `ahb-failed-read-reported-as-off`, `smmu-failed-read-reported-as-clock-off` |
| "running" is positive proof of the clock, and the flags of the table are the pinned structs' | the model's own statement of the rule; the pinned-copy test checks the hardware gating and halt-skip flags of each row against the clock structs | `clock-ignores-clk-off`, `clock-ignores-enable`, `hwcg-exemption-for-all`, `nohalt-ignored`, `hwcg-flag-dropped`, `nohalt-flag-dropped`, `hwcg-flag-on-gpucc`, `cbcr-clk-off-bit`, `cbcr-enable-bit` |
| the clock lists of the two nodes are the device tree's, in its order | the pinned-copy test reads the node's clocks in order and zips them with the enum names | `gmu-clock-order`, `smmu-clock-list`, `smmu-clock-gate-removed` |
| a `NEXT` line before each block, each snapshot-2 read, the wait and each late block; a line out before the next line's loads; the verdict and the SMMU decode right after their words | the model checks the last line at the first load of each block, window and late block and at the start of the wait, and that a line is printed between the loads of different lines; a block whose `NEXT` cannot be printed is not read | `no-next-line`, `no-next-gcc`, `no-next-wait`, `no-next-late`, `read-without-next`, `block-read-then-printed`, `r4-printed-late`, `smmu-decode-printed-late`, `s2-without-next`, `s2-note-dropped` |
| a block starts with a word Linux reads; the words no Linux code reads are read last, after the wait and the drift report, and only on a state that still holds | the model carries its own flag per word and rejects a late word outside the late phase and a word Linux reads inside it; the late gates are judged on snapshot 2's words; the pinned-copy test derives the late set from the pinned driver | `late-word-first-in-block`, `late-words-read-in-snapshot-one`, `late-before-the-wait`, `late-gate-uses-snapshot-1`, `late-cx-gate-removed`, `late-ahb-gate-removed`, `late-without-snapshot-2`, `late-reads-unread-block`, `late-lines-crowded-out` |
| an abort ends its window; nothing is retried; snapshot 2 re-reads only GCC and GPUCC | the model rejects any load in a window after an abort in it (a fault at every one of the 52 addresses, every window aborting) and counts the drift only over visited windows | `retry-after-fault`, `dead-window-ignored`, `s2-dead-window-visited`, `s2-reads-the-cx-blocks`, `drift-counts-skipped-window` |
| at most 34 lines and 128 loads, the end line whenever the payload gets to the end | every run is checked for both caps, the ABI limits and the `END` line; smaller line and load caps are built too; a page with a full drift list and every late line checks the room kept back | `line-overflow`, `closing-crowded-out`, `load-cap-ignored` |
| one wait of 8 s, bounded far above what it needs; a bound that is hit is not a dead counter | the model counter measures the gap; a counter that stands still, runs backwards or is absent says `NO_COUNTER`; a slow counter that needs 3.84 million reads still gets its wait; a build with a bound of 3 million reads says `SPIN` | `wait-zero`, `unbounded-wait`, `backwards-counter-ignored`, `spin-bound-too-small`, `spin-bound-removed`, `spin-bound-passed-as-success`, `spin-token-reused` |
| the decodes and the bit positions are the pinned files' | the golden pages of the fixtures; the pinned-copy test evaluates the BIT and GENMASK macros of the headers and compares each shift and mask | `cbcr-polarity`, `rcg-polarity`, `pwr-polarity`, `gx-state-polarity`, `gx-state-mask`, `tcs-polarity`, `fault-code-lost`, `gdsc-pwr-on-bit`, `gdsc-sw-collapse-bit`, `gdsc-hw-control-bit`, `vote-bit-drift`, `rcg-source-shift`, `smmu-ubs-shift` |
| a decode checks the mode bits that make it valid, else the cell says `.ODD` | the gate suite feeds each word that is all ones or has the mode bits set, a clock with CLK_OFF and CLK_ENABLE both clear (a window of zeros), and the same bits on a clock without that mode; an odd data-path clock still opens the CX gate by Linux's own exemption | `all-ones-clock-decoded`, `enable-clear-decoded-as-on`, `all-ones-gdsc-decoded`, `all-ones-field-decoded`, `hwcg-clk-off-decoded`, `fsm-on-clk-off-decoded`, `rcg-command-word-judged-as-a-branch`, `gx-reserved-bits-trusted`, `tcs-all-ones-idle` |

## Tests

| Command | What it shows |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload-gpusnap.py` | `Harness`: the native host test under ASan and UBSan at the shipped caps (the suites `unit`, `cold`, `gate`, `faults`, `storm`, `drift`, `late`, `stream`, `smmu`, `counter`, `el`, `budget`: the golden pages, the gates in both directions (a zero-initialised context opens no CX block, a window of zeros is `.ODD`), a window the table does not have, an abort at every address, every window aborting, all ones, zero and random memories, snapshot 2, the late words, the order of lines and loads, the SMMU decode, the counter (stuck, absent, backwards, slow), EL and arguments, the widest page), at line caps of 20, 12 and 6 and load caps of 30 (`caps`) and with a bound of 3 million reads on the wait (`spin`); `CompiledCode`: the IR audit on the source and on eleven faulty IR texts, the `gpusnap` policy on the linked binary, the other payloads' binaries refused by it, the stack, two builds byte for byte the same, the manifest tool on `gpusnap` then `xhci0` and `xhci1`; `Mutants`: 111 seeded bugs, each rejected by the suites it names for the reason it names; `Doc`: both documents against the register table, the model's pages, excerpts and numbers, the ledger of citations, the chain budget, the outcome table's coverage of every token the payload can print (and that a removed row is noticed) and the list of what could not be verified |
| `python3 tools/test-q1n1-sp11-payload-gpusnap-refs.py` | the pinned copies: every digest, every citation of the main document at its line, every offset of the register table by name, which words are late (those no pinned driver line reads) and that each block starts with one Linux reads, every shift and mask against the macros, the windows against `hamoa.dtsi`, the gate inputs against the nodes' clock lists. A SKIP without the copies (`GPUSNAP_REFS_DIR`, or `SNAPINTOSH_DIR` naming a tree with `build/sp11-stick-log/refs/`, or `build/sp11-gpusnap/refs/` here) |
| `python3 tools/test-q1n1-sp11-payload-qemu-gpusnap.py` | QEMU/EDK2 at EL2: `gpusnap` alone and after `state` ([What QEMU shows](#what-qemu-shows)) |
| `python3 tools/test-q1n1-sp11-payload-build.py` | its `PayloadBinary` class builds every payload that has a policy, `gpusnap` included, and checks entry, size, relocations, reproducibility and the allow-list |

The host test cannot show what the binary does on a core, what the registers hold, or whether a load hangs the bus; QEMU cannot show the unit's windows.

## What QEMU shows

QEMU (`virt,virtualization=on`, `-cpu max`, TCG, EDK2) has none of the GPU's blocks: every window of the table lies below `0x08000000`, in the machine's flash, which reads back the firmware's own bytes. The words the
page prints under QEMU are therefore the firmware's and not a model of the GPU, and whether the `CFGA` gate opens is the firmware's doing. The test reads the words the page printed and holds the page and the runner's
counters to its **own** statement of the gates (written from the main document, not from the payload, by the same author: common mode): which blocks must be read and which gated, what `R4` must say, that the late words follow the drift report and only for the
blocks that were read, how many loads were made, the end line and the gap on the real counter. It leaves out of the block below the lines that depend on the flash. With the firmware found here `CFGA` read `.OFF`: GPUCC and
everything behind it were `GATED BY AHB`, 14 loads, no fault, no late lines (OBSERVED once under QEMU; the gates that open, the late phase and the abort path are exercised by the host test only). The runner reports a normal
`DONE` with no refused destination, alone and after `state`. The other lines, with the frequency, the counts, the gap and the line count as placeholders:

<!-- qemu-lines -->
```
PAYLOAD GPUSNAP READ ONLY EL=2 HZ=<HZ> GAP=8 S
PAYLOAD GPUSNAP KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=BIT 31 NOT TRUSTED NO GPU-WINDOW REGISTER IS READ
PAYLOAD GPUSNAP NEXT GCC
PAYLOAD GPUSNAP NEXT WAIT 8 S
PAYLOAD GPUSNAP NEXT S2 GCC
PAYLOAD GPUSNAP END LOADS=<L> FAULTS=<F> SKIPS=<S> BLK=<B> CUTS=0 GAP_MS=<MS> LINES=<N>
```
<!-- /qemu-lines -->

What that proves: the binary runs at EL2 behind the runner, uses only its ops, keeps its stores on its own stack (the runner refuses a load destination outside it), takes its second snapshot after a real 8 s on the
counter and does not read what a word that does not prove the clock runs closes. What it does not: anything about the unit.

## The pinned files

Linux revision `7475ea8b58616b33c04afb976cf0fbaad9dd63fb`; a file is fetched from `https://raw.githubusercontent.com/torvalds/linux/<revision>/<path>`. The citations of the main document are `prefix:line` into these files. "Pinned in" says where
the digest was already recorded: the stick log section 10, the plan's Appendix B (`docs/SP11-GPU-PORT-PLAN.md`), the study's Appendix B (`docs/SP11-GPU-A7XX-STUDY.md`), or nowhere (recorded here only).

| Prefix | Linux path | SHA-256 | Pinned in |
| --- | --- | --- | --- |
| `dt` | `arch/arm64/boot/dts/qcom/hamoa.dtsi` | `d5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0` | stick log |
| `gcc` | `drivers/clk/qcom/gcc-x1e80100.c` | `f1c3779c7bc273dfe170ea2ff4d40f975083ee149e3b02a4f42d5939596eb775` | stick log |
| `cb` | `drivers/clk/qcom/clk-branch.h` | `bac7dcf51a0da5b27eaa0d4dc276f540fec80013bd4862cfbbc115a50161ef72` | stick log |
| `gdsc` | `drivers/clk/qcom/gdsc.c` | `a5a73fcc890f658b48a1e2dc015f3d47316d77b8c7853bbf999828f25a8c86b1` | stick log |
| `smmu` | `drivers/iommu/arm/arm-smmu/arm-smmu.h` | `b7221ee9b767594ba79cfc139fca838236f81ba949fb5e0be81e31ef42b1911c` | stick log |
| `gpucc` | `drivers/clk/qcom/gpucc-x1e80100.c` | `c2914ffd395e82984c5c46e9d44239cc148c7fa7b6f72c2637ba58322fc6131b` | plan |
| `rcg` | `drivers/clk/qcom/clk-rcg2.c` | `b173e0f4d0b962f777c668422f5b1ca22137334b62de766f01f3ef5faf5d93b6` | plan |
| `gmu` | `drivers/gpu/drm/msm/adreno/a6xx_gmu.c` | `22bc34dafafff83827901221873c6aa770e20f9c17c60294593245324eee8272` | study |
| `gmuh` | `drivers/gpu/drm/msm/adreno/a6xx_gmu.h` | `b9af7b6c0bdf0f4f3fabf70f59ba821bc783109b48cf7a8c04e6b7d07fef1b92` | study |
| `xml` | `drivers/gpu/drm/msm/registers/adreno/a6xx_gmu.xml` | `f13f07aa3c975c1d671c1a7f5ba62ddaaf525aedb7a0e481186cbfffe461f88b` | study |
| `gpuc` | `drivers/gpu/drm/msm/adreno/a6xx_gpu.c` | `9b725c1c56a9b6b804de0daa899fa03f51ddb6c8253904c77814540d5142f4cd` | study |
| `gpuh` | `drivers/gpu/drm/msm/adreno/a6xx_gpu.h` | `3d11d36a6ec3f16876baaf6f8b76fcfcaa8e0b2991892e886fbe850682f87c70` | study |
| `a6x` | `drivers/gpu/drm/msm/registers/adreno/a6xx.xml` | `6e20d0347b06f26220f6b87d8600e94790331fec45363a167c5e63ea6ad8f9c2` | study |
| `cat` | `drivers/gpu/drm/msm/adreno/a7xx_catalog.c` | `6941242f183b76143464237896f8b0b97f9a6533cb1efb6f834f2da4dcb6c799` | study |
| `agh` | `drivers/gpu/drm/msm/adreno/adreno_gpu.h` | `c8fe321c6df3a4b2fc2f3f186cf6b3952fd0196f7e5c32b5d7b2740405dd3be6` | study |
| `cbc` | `drivers/clk/qcom/clk-branch.c` | `d29259eb77a5d1d6a07adf4aa835588f8e04d1fa3c14be2b7d4162cce737abfa` | nowhere |
| `cmn` | `drivers/clk/qcom/common.c` | `ebefa181817ee8218b314218bbd94315ba239ff4f816a6565af3ec6aeed14226` | nowhere |
