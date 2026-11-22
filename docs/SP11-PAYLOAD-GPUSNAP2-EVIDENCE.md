<!-- SPDX-License-Identifier: MIT -->
# Payload `gpusnap2`: the pins, the seeded bugs, the other pages and QEMU

Companion of [SP11-PAYLOAD-GPUSNAP2.md](SP11-PAYLOAD-GPUSNAP2.md) (what the payload reads, its page, its hazards). **Status: EXPERIMENTAL; hardware NOT RUN.** Nothing here is a statement about the unit.

## A. Pinned files

Linux tag v7.4-rc2, which `git ls-remote https://github.com/torvalds/linux` peels to commit `7475ea8b58616b33c04afb976cf0fbaad9dd63fb` (read 2026-11-17). Each file was read at that commit from
`https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/<path>` and is pinned by the SHA-256 below (GPL-2.0 for the drivers, GPL-2.0 OR MIT for the binding header, BSD-3-Clause for the
device tree; read for facts, offsets, names and constants, nothing copied). STICK: pinned by `docs/SP11-STICK-LOG.md` section 10 of the Snapintosh tree; GPUSNAP: by `SP11-PAYLOAD-GPUSNAP-EVIDENCE.md`; TSNAP: by
`SP11-PAYLOAD-TSNAP.md` section 8; THIS: fetched for this payload and pinned only here and in `tools/sp11_payload_gpusnap2_refs.py`. The Adreno catalog the document calls `cat` is `a7xx_catalog.c`; `a6xx_catalog.c` lies beside it in the same directory and is another file, which is not pinned here.

| File | Path in the Linux tree | SHA-256 | Pinned by |
| --- | --- | --- | --- |
| `hamoa.dtsi` | `arch/arm64/boot/dts/qcom/hamoa.dtsi` | `d5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0` | STICK |
| `gcc-x1e80100.c` | `drivers/clk/qcom/gcc-x1e80100.c` | `f1c3779c7bc273dfe170ea2ff4d40f975083ee149e3b02a4f42d5939596eb775` | STICK |
| `clk-branch.h` | `drivers/clk/qcom/clk-branch.h` | `bac7dcf51a0da5b27eaa0d4dc276f540fec80013bd4862cfbbc115a50161ef72` | STICK |
| `gdsc.c` | `drivers/clk/qcom/gdsc.c` | `a5a73fcc890f658b48a1e2dc015f3d47316d77b8c7853bbf999828f25a8c86b1` | STICK |
| `clk-branch.c` | `drivers/clk/qcom/clk-branch.c` | `d29259eb77a5d1d6a07adf4aa835588f8e04d1fa3c14be2b7d4162cce737abfa` | STICK |
| `common.c` | `drivers/clk/qcom/common.c` | `ebefa181817ee8218b314218bbd94315ba239ff4f816a6565af3ec6aeed14226` | STICK |
| `gpucc-x1e80100.c` | `drivers/clk/qcom/gpucc-x1e80100.c` | `c2914ffd395e82984c5c46e9d44239cc148c7fa7b6f72c2637ba58322fc6131b` | GPUSNAP |
| `a7xx_catalog.c` | `drivers/gpu/drm/msm/adreno/a7xx_catalog.c` | `6941242f183b76143464237896f8b0b97f9a6533cb1efb6f834f2da4dcb6c799` | GPUSNAP |
| `a6xx_gmu.c` | `drivers/gpu/drm/msm/adreno/a6xx_gmu.c` | `22bc34dafafff83827901221873c6aa770e20f9c17c60294593245324eee8272` | GPUSNAP |
| `clk-rcg2.c` | `drivers/clk/qcom/clk-rcg2.c` | `b173e0f4d0b962f777c668422f5b1ca22137334b62de766f01f3ef5faf5d93b6` | GPUSNAP |
| `tsens-v2.c` | `drivers/thermal/qcom/tsens-v2.c` | `0f0d41735b468d247f9d648980b31b30d91df4976d9f74c48767014c0ec74a12` | TSNAP |
| `rpmh-rsc.c` | `drivers/soc/qcom/rpmh-rsc.c` | `1efe0d45d2c8ab11a494bad594e3204582670f30087ee3d925b3f5c31a3982d6` | THIS |
| `rpmh-internal.h` | `drivers/soc/qcom/rpmh-internal.h` | `39ad1ed46118821882e72f777378d5974bfaad984d19060ac22f892866b21674` | THIS |
| `cmd-db.c` | `drivers/soc/qcom/cmd-db.c` | `8393e57616c2aa58f5779afab86b31cb252f4300351722a5eef5e639541267cf` | THIS |
| `cmd-db.h` | `include/soc/qcom/cmd-db.h` | `5fbe09d09bd9e892079340672a61148b46b1d5319ac1665bce4c3b85beefee56` | THIS |
| `qfprom.c` | `drivers/nvmem/qfprom.c` | `db979c91348c0572f6689238d1e5c1ccf2984e2a8ceb21715fddf8c750522dfa` | THIS |
| `clk-alpha-pll.c` | `drivers/clk/qcom/clk-alpha-pll.c` | `9a93019436b59ce3020940e0b91615bcaddc233da37951dcf492b2f09a9de433` | THIS |
| `qcom,rpmh-rsc.h` | `include/dt-bindings/soc/qcom,rpmh-rsc.h` | `d57710164c227cf9d080d2885c44fe75a51cdc1b81ffd6aa27fc6ae0b70c1b73` | THIS |

What the device tree says besides the windows (`dt:9664-9856`, VERIFIED): the eight `gpuss` zones read tsens3 sensors 5 to 12, one each. The status word's fields are in `ts2:126-138`, and **no pinned file names bits 26:22 or
31:27 of it**: the sensor number is evidence of one film of one unit and no more (INFERRED, **UV5**). The unit's firmware tables are cited only as DERIVED numbers (the shape of the final memory map: section 3 of the main document).

## B. The seeded bugs

<!-- mutants -->
257 seeded bugs, each an exact once-only replacement in `payloads/gpusnap2.c` or `payloads/gpusnap2-regs.h`: 235 rejected by the host program, 5 by the host program built with small caps, 9 by the IR audit, 7 by the
binary policy and 1 by the stack check. Each names the stage that must reject it, the suites that must be among the ones that fail and the text of the diagnostic that must be in the output (`tools/sp11_payload_gpusnap2_mutants.py`;
the driver runs every one of them and refuses a pattern that is not in the source exactly once).
<!-- /mutants -->

Not seeded, because no test can tell them from the shipped code: the defensive window, range and slot tests of the read primitive (the shipped tables never trip them) and a reserved mask that starts at bit 26 in place of
27 (bit 26 is covered twice: the sensor number checks it). Families, by what they break:

* **Windows, offsets and tables** (31, refused by the harness's own list of what may be read): `tsrot-window-moved` `ttm-window-moved` `gcc-window-moved` `gpucc-window-moved` `cmddb-window-moved` `rsc-window-is-drv-1`
  `rsc-window-is-drv-0` `qfprom-window-moved` `sensors-start-one-low` `nine-sensors` `status-words-one-word-high` `ctrl-is-the-measure-period` `hw-ver-is-ctrl` `qfprom-word-unaligned` `qfprom-word-one-high`
  `gpucc-offset-beyond-the-window` `cfga-register-moved` `ahb-register-moved` `cxgd-register-moved` `cxhw-register-moved` `pll0-opmode-is-status-register-moved` `pll0-l-is-user-ctl-register-moved`
  `pll1-opmode-is-state-register-moved` `pll1-l-is-status-register-moved` `ff-rcg-config-is-the-next-word-register-moved` `critical-cb-is-gx-vsense-register-moved` `memnoc-is-gx-mnd1x-0-register-moved`
  `sleep-is-gx-mnd1x-1-register-moved` `pll0-mode-is-the-other-pll-register-moved` `xo-divider-moved-register-moved` `crc-is-the-next-clock-register-moved`
* **The speed bin and the clock decode tables** (16): `fuse-field-without-the-byte-fixup` `fuse-field-seven-bits` `speed-bin-of-59-is-2` `speed-bin-of-146-is-3` `clk-off-bit-30` `clk-enable-bit-1`
  `noc-fsm-status-shifted` `noc-fsm-on-is-1` `gdsc-pwr-on-bit-30` `gdsc-sw-collapse-bit-1` `gdsc-hw-control-bit-2` `pll-outctrl-bit-1` `pll-lock-det-bit-30` `pll-run-bit-1` `rcg-source-select-shifted`
  `rcg-source-select-two-bits`
* **The status word's fields and the control word** (12): `sensor-number-shifted` `sensor-number-four-bits` `reserved-bits-from-28` `valid-bit-20` `critical-flags-one-bit` `temperature-eleven-bits`
  `plausible-minimum-minus-30` `plausible-maximum-130` `sensor-enable-shift-2` `code-or-temp-bit-20` `ctrl-enable-is-bit-1` `sw-reset-is-bit-2`
* **The memory map's fields and limits** (11): `map-type-is-the-next-word` `map-start-is-the-virtual-start` `map-pages-one-word-low` `map-attribute-one-word-high` `map-stride-minimum-32`
  `map-stride-maximum-136` `map-of-321-descriptors` `nine-hits-allowed` `reserved-is-type-7` `page-size-8k` `address-limit-49-bits`
* **The database's constants** (13): `magic-byte-order` `entries-start-at-0x80` `entries-are-32-bytes` `entry-cap-129` `scan-cap-257` `rails-are-vrm` `bcms-are-vrm` `resource-headers-20-bytes`
  `resource-headers-start-at-12` `nine-levels-printed` `cx-looked-up-as-a-bcm` `gmxc-looked-up-as-gmxc-lvx` `five-rails`
* **The RSC's registers, layouts and TCSs** (22): `tcs-base-moved` `tcs-stride-680` `irq-status-is-irq-clear` `irq-enable-moved` `solver-config-moved` `child-config-moved` `tcs-count-of-drv-1` `eight-tcss`
  `wake-tcss-are-sleep-tcss` `three-wake-tcss` `seventeen-commands` `version-major-in-the-minor-field` `version-minor-shift-0` `tcs-count-five-bits` `ncpt-shift-26` `layout-2-7-enable-moved`
  `layout-2-7-address-is-data` `layout-2-7-command-stride-24` `layout-3-0-enable-moved` `layout-3-0-data-is-status` `layout-3-0-command-stride-20` `major-3-uses-the-2-7-layout`
* **The page's limits** (3): `line-cap-raised` `load-cap-raised` `end-line-not-reserved`
* **Gates and the order of reading** (6 + 7 + 4): `gpucc-gate-always-open` `gpucc-gate-not-asked` `clk-off-ignored-by-the-gate` `enable-ignored-by-the-gate` `ahb-and-ahberr-swapped`
  `gpucc-read-all-before-printing` `tsens-read-before-its-next-line` `gcc-read-before-its-next-line` `gpucc-read-before-its-next-line` `cmddb-read-before-its-next-line` `rsc-read-before-its-next-line`
  `qfprom-read-before-its-next-line` `block-read-when-its-next-line-was-dropped` `rsc-before-the-database` `qfprom-before-the-rsc` `gpucc-before-gcc` `sensors-last`
* **The sensors' code** (20): `no-identity-gate` `all-ones-identity-passes` `zero-identity-passes` `software-reset-passes-the-control-gate` `disabled-block-passes-the-control-gate`
  `sensor-number-not-checked` `reserved-bits-not-checked` `sensor-number-checked-after-valid` `adc-codes-decoded` `minimum-is-valid` `maximum-is-valid` `temperature-is-unsigned`
  `cells-check-the-slot-not-the-sensor` `aggregate-checks-the-slot-not-the-sensor` `flags-of-odd-words-counted` `minimum-takes-the-last-tie` `maximum-takes-the-last-tie` `code-block-not-flagged`
  `cells-line-after-a-dead-window` `raw-words-in-runner-hex`
* **The clock decodes** (11): `zero-clock-word-not-odd` `all-ones-clock-word-not-odd` `noc-fsm-clock-not-odd` `branch-decode-swapped` `rcg-decode-swapped` `gdsc-decode-swapped` `pll-enabled-on-either-bit`
  `pll-all-ones-not-odd` `pll-verdict-from-the-mode-twice` `field-of-all-ones-printed` `lock-detect-not-printed`
* **The memory map's verdict, which is the command database's gate** (18): `map-gate-only-for-bad` `descriptor-end-inclusive` `nine-hits-overrun-the-table` `type-ignored` `cover-not-checked`
  `touching-halves-do-not-join` `one-pass-of-coverage` `zero-page-descriptors-count` `misaligned-start-accepted` `end-wraparound-accepted` `page-count-wraparound-accepted`
  `hits-overflow-is-not-a-damaged-map` `map-base-alignment-not-checked` `map-stride-alignment-not-checked` `map-size-not-a-multiple-accepted` `map-end-overflow-not-checked` `map-past-48-bits-accepted`
  `map-attribute-not-printed`
* **The database walk** (24): `magic-not-checked` `magic-verdict-inverted` `header-list-has-no-end` `header-count-is-the-data-offset` `header-offset-is-the-slave-id` `arc-count-is-the-last-list`
  `vrm-list-walked` `cap-not-reported` `list-not-capped` `scan-cap-not-reported` `list-offset-ignored` `other-kinds-match-too` `later-duplicates-win` `first-word-only-matches`
  `address-is-the-priority-word` `length-and-offset-swapped` `aux-data-without-the-header` `aux-data-without-the-list-offset` `cut-and-absent-swapped` `abort-leaves-the-targets-unread`
  `header-abort-leaves-the-targets-unread` `header-abort-not-shown` `unaligned-list-read-anyway` `abort-does-not-end-the-window`
* **The level tables** (11): `levels-are-bytes` `levels-not-capped` `upper-half-start-not-handled` `level-words-undercounted` `level-halves-swapped` `level-separator-before-the-first` `empty-table-is-a-table`
  `odd-offset-read` `table-end-not-checked` `table-start-rounded-wrong` `only-two-rails-on-the-level-lines`
* **The RSC's code** (16): `rsc-id-not-checked` `any-major-from-3-is-layout-3` `version-not-checked` `tcs-count-gate-off-by-one` `all-ones-child-config-passes` `disabled-commands-read`
  `data-read-for-every-command` `address-zero-is-a-rail` `first-vote-wins` `votes-above-255-in-hex` `command-count-is-sixteen` `odd-mask-not-marked` `abort-not-carried-to-the-rails`
  `child-config-not-shown-as-a-count` `tcs-count-of-all-ones-shown` `wake-tcss-last-on-the-enable-line`
* **The speed bin's code** (2): `unmapped-fuse-prints-a-bin` `last-bin-not-searched`
* **The primitives** (13): `load-cap-not-checked` `line-cap-not-checked` `end-line-crowded-out` `loads-not-counted` `end-line-lines-off-by-one` `aborts-not-counted` `abort-code-not-kept`
  `not-at-el2-not-checked` `missing-load32-not-checked` `map-arguments-dropped` `small-numbers-in-hex` `item-that-just-fits-is-dropped` `overlong-item-truncated-not-dropped`
* **The compiled code** (17, never run natively: some store to a device address): `a-word-is-read-without-the-guard` `the-map-is-read-through-its-pointer` `store-to-a-device-address`
  `store-to-the-command-database` `store-through-the-arguments` `store-through-a-pointer-read-back-from-memory` `explicit-memset-libcall` `writable-global` `atomic-counter` `smc-call` `data-barrier`
  `instruction-barrier` `reads-the-counter-frequency` `reads-the-counter` `writes-a-system-register` `translation-request` `frame-larger-than-the-stack-allows`

**The safety rules, and what refuses a breach.** Every rule below is held by at least one seeded bug above and by the host program's own model:

| Rule | Held by |
| --- | --- |
| only loads, and every load through the runner's guarded load (no pointer to a device or to the database) | the IR audit and the binary check: `a-word-is-read-without-the-guard`, `the-map-is-read-through-its-pointer`, `store-to-a-device-address`, `store-to-the-command-database` |
| no store but to the payload's own stack, none through the arguments, no writable global | the IR audit: `store-through-the-arguments`, `store-through-a-pointer-read-back-from-memory`, `writable-global` |
| no barrier, no `at`, no SMC, no counter, no system register write | the binary policy: `data-barrier`, `instruction-barrier`, `translation-request`, `smc-call`, `reads-the-counter`, `reads-the-counter-frequency`, `writes-a-system-register` |
| only the seven windows and the register list the pinned drivers name; nothing behind CX | the model's own list: the `*-window-moved` and `*-register-moved` bugs |
| a block is announced before its first load; a line is read whole and printed before the next | `*-read-before-its-next-line`, `gpucc-read-all-before-printing`, `block-read-when-its-next-line-was-dropped` |
| GPUCC only behind a CFG AHB word that reads and says `.ON` | `gpucc-gate-always-open`, `gpucc-gate-not-asked`, `clk-off-ignored-by-the-gate`, `enable-ignored-by-the-gate` |
| the command database only behind a map that describes all of it as reserved memory | `map-gate-only-for-bad`, `cover-not-checked`, `type-ignored`, `descriptor-end-inclusive` |
| nothing of the database behind a bad magic; bounded lists and level tables inside the region | `magic-not-checked`, `list-not-capped`, `levels-not-capped`, `table-end-not-checked` |
| the first abort in a window ends its reads | `abort-does-not-end-the-window` |
| a TCS data word only when its command's address is a rail's from the database | `data-read-for-every-command`, `address-zero-is-a-rail`, `disabled-commands-read` |
| the caps: 2048 loads, 34 lines, the end line never crowded out | `load-cap-not-checked`, `line-cap-not-checked`, `end-line-crowded-out`, `load-cap-raised`, `line-cap-raised` |

## C. The gated page and the abort page

Two more pages of the host model. The first is the model's world in which every gate closes where the words say so: the CFG AHB word reads `0X80000001.OFF` (GPUCC gated by AHB), the memory map describes the
region as another type (the database gated by MAP) and the RSC's major is 4 (gated by VER). The second is a world in which the RSC and QFPROM windows abort on their first load. Both are made up, **not the unit's
pages**.

<!-- page-gated -->
```
PAYLOAD GPUSNAP2 READ ONLY EL=2 CAP=2048/34
PAYLOAD GPUSNAP2 KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=NOT TRUSTED NA=NOT READ -=NO VOTE TEMP=0.1 C
PAYLOAD GPUSNAP2 NEXT TSENS3
PAYLOAD GPUSNAP2 T3 VER=0X20080000 CTL=0X9D63FFF9 SEN=0X7FFF
PAYLOAD GPUSNAP2 T3 R5 0160018E 01A00186 01E00181 02200184 02600180 02A00187 02E0018B 03200185
PAYLOAD GPUSNAP2 T3 C5 398 390 385 388 384 391 395 389 V=8 MIN=384(S9) MAX=398(S5)
PAYLOAD GPUSNAP2 NEXT GCC
PAYLOAD GPUSNAP2 GCC CFGA=0X80000001.OFF
PAYLOAD GPUSNAP2 GPUCC GATED BY AHB
PAYLOAD GPUSNAP2 NEXT CMDDB
PAYLOAD GPUSNAP2 CMDDB MAP DESC=227 HITS=1 T=7 ATTR=1 TYPE
PAYLOAD GPUSNAP2 CMDDB GATED BY MAP
PAYLOAD GPUSNAP2 NEXT RSC2
PAYLOAD GPUSNAP2 RSC2 ID=0X40701 VER=4.7
PAYLOAD GPUSNAP2 RSC2 GATED BY VER
PAYLOAD GPUSNAP2 NEXT QFPROM
PAYLOAD GPUSNAP2 QFPROM W118=0X1D9234 FUSE=59 SB=1
PAYLOAD GPUSNAP2 END LOADS=923 FAULTS=0 SKIPS=0 BLK=0X38 CUTS=0 LINES=18
```
<!-- /page-gated -->

<!-- page-aborts -->
```
PAYLOAD GPUSNAP2 READ ONLY EL=2 CAP=2048/34
PAYLOAD GPUSNAP2 KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=NOT TRUSTED NA=NOT READ -=NO VOTE TEMP=0.1 C
PAYLOAD GPUSNAP2 NEXT TSENS3
PAYLOAD GPUSNAP2 T3 VER=0X20080000 CTL=0X9D63FFF9 SEN=0X7FFF
PAYLOAD GPUSNAP2 T3 R5 0160018E 01A00186 01E00181 02200184 02600180 02A00187 02E0018B 03200185
PAYLOAD GPUSNAP2 T3 C5 398 390 385 388 384 391 395 389 V=8 MIN=384(S9) MAX=398(S5)
PAYLOAD GPUSNAP2 NEXT GCC
PAYLOAD GPUSNAP2 GCC CFGA=1.ON
PAYLOAD GPUSNAP2 NEXT GPUCC
PAYLOAD GPUSNAP2 GPUCC AHB=0.ODD CXGD=0X22F801 SC=1 HW=0 CXHW=0XDFF4.OFF
PAYLOAD GPUSNAP2 GPUCC PLL0 MODE=0 OP=0 L=0X29 AL=0XA000 EN=OFF LK=0
PAYLOAD GPUSNAP2 GPUCC PLL1 MODE=0 OP=0 L=0X16 AL=0XEAAA EN=OFF LK=0
PAYLOAD GPUSNAP2 GPUCC FFC=0X80000000.OFF FFF=0X100 S=1 XDIV=0 DDIV=1
PAYLOAD GPUSNAP2 GPUCC CRC=0X80000000.OFF CXFF=0X80000000.OFF FM=0X80000000.OFF
PAYLOAD GPUSNAP2 GPUCC MEM=0X80000000.OFF SLP=0X80000000.OFF CB=0X80000001.OFF
PAYLOAD GPUSNAP2 NEXT CMDDB
PAYLOAD GPUSNAP2 CMDDB MAP DESC=227 HITS=1 T=0 ATTR=1 OPEN
PAYLOAD GPUSNAP2 CMDDB HDR VER=1 MAGIC=OK HDRS=3 ARC=8 BCM=6
PAYLOAD GPUSNAP2 CMDDB ADDR CX=0X30000 MX=0X30004 GFX=0X3000C GMXC=0X30010 GBX=0X30014
PAYLOAD GPUSNAP2 CMDDB BCM SH0=0X50008 MC0=0X50004 ACV=0X50000
PAYLOAD GPUSNAP2 CMDDB LVL CX=9:16/48/64/128/192/256/320/384 MX=8:16/48/64/128/192/256/384/416
PAYLOAD GPUSNAP2 CMDDB LVL GFX=7:16/48/64/128/192/256/384 GMXC=4:16/64/128/256
PAYLOAD GPUSNAP2 NEXT RSC2
PAYLOAD GPUSNAP2 RSC2 ID=FAULT:6
PAYLOAD GPUSNAP2 RSC2 GATED BY ID
PAYLOAD GPUSNAP2 NEXT QFPROM
PAYLOAD GPUSNAP2 QFPROM W118=FAULT:6
PAYLOAD GPUSNAP2 END LOADS=1005 FAULTS=2 SKIPS=0 BLK=0X60 CUTS=0 LINES=28
```
<!-- /page-aborts -->

## D. What QEMU shows

QEMU's `virt` machine has none of the windows the payload reads. The two TSENS windows (0x0c2xxxxx) lie in its platform bus, the RSC and the QFPROM (0x1752xxxx, 0x221cxxxx) in its PCIe range, where nothing is mapped; GCC and
GPUCC (0x001xxxxx, 0x03dxxxxx) lie in its flash, which reads back the firmware's own bytes where the firmware is and zeros in the padding after it; and the command database (0x81c6xxxx) lies beyond the RAM the emulator
was given, so the runner's memory map does not describe it. The test (`tools/test-q1n1-sp11-payload-qemu-gpusnap2.py`) does not pin the words that depend on the flash or on the memory map: it reads the words the page
printed and decides, by its own statement of the rules, what the page must show, how many loads the payload made and how many aborted, and holds the runner's `DONE` line to the same numbers. The lines below are what
QEMU showed (the versions are given under the block); the words that depend on the flash and on the map are placeholders.

<!-- qemu-lines -->
```
PAYLOAD GPUSNAP2 READ ONLY EL=2 CAP=2048/34
PAYLOAD GPUSNAP2 KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=NOT TRUSTED NA=NOT READ -=NO VOTE TEMP=0.1 C
PAYLOAD GPUSNAP2 NEXT TSENS3
PAYLOAD GPUSNAP2 T3 VER=FAULT:6 GATED
PAYLOAD GPUSNAP2 NEXT GCC
PAYLOAD GPUSNAP2 GCC CFGA=<W>
PAYLOAD GPUSNAP2 GPUCC GATED BY AHB
PAYLOAD GPUSNAP2 NEXT CMDDB
PAYLOAD GPUSNAP2 CMDDB MAP DESC=<N> HITS=<H> NONE
PAYLOAD GPUSNAP2 CMDDB GATED BY MAP
PAYLOAD GPUSNAP2 NEXT RSC2
PAYLOAD GPUSNAP2 RSC2 ID=0XFFFFFFFF
PAYLOAD GPUSNAP2 RSC2 GATED BY ID
PAYLOAD GPUSNAP2 NEXT QFPROM
PAYLOAD GPUSNAP2 QFPROM W118=0XFFFFFFFF FUSE=255 SB=?
PAYLOAD GPUSNAP2 END LOADS=<L> FAULTS=<F> SKIPS=0 BLK=<B> CUTS=0 LINES=<N>
```
<!-- /qemu-lines -->

OBSERVED under QEMU 11.1.3 (`virt,virtualization=on`, `-cpu max`, TCG, EDK2 AArch64 stable202408), alone and after `state`, the same page both times: the first load of the TSROT window faults (`T3 VER=FAULT:6 GATED`, so
nothing else of tsens3 is read); GCC answers with the flash's word at 0x171004 (`CFGA=<W>`: a word that is not a running clock, so GPUCC is gated by AHB); the runner's memory map (38 descriptors, none overlapping
0x81c60000) gives `NONE`, so the command database is not read; the RSC's ID reads all ones (`GATED BY ID`) and so does the QFPROM word (`FUSE=255 SB=?`). The runner's own `DONE` line for the same run reads
`LOADS=156 FAULTS=1 REFUSED=0 LINES=16 DROPPED=0`, as the END line does: 156 loads are the TSROT word, the CFG AHB word, four words of each of the 38 descriptors, the RSC ID and the QFPROM word.

That shows the binary at EL2 behind the real runner (its guarded loads and its stack under the runner's checks), a faulted load reported as `FAULT:6`, every block announced before its first load or gated, the command
database not read behind a map that does not describe it, and the counters of the runner agreeing with the page. It does **not** show the command database, the RSC, a decoded temperature, the PLL words or any value of
the unit: no window of QEMU answers like the unit's, so those paths are exercised only by the host test's model.
