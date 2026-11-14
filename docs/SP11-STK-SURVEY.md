<!-- SPDX-License-Identifier: MIT -->
# SP11 stick-log survey, stage S0: the read-only USB-controller survey

Stage S0 of `docs/SP11-STICK-LOG.md` in the Snapintosh repository (sections 3.5, 3.6 and 6, Appendix A). One
boot, no device write, to learn the state of the USB controller the boot stick sits on: its power domain and
clocks, the xHCI identity and operational state, the ports, the slot contexts the firmware left behind and the
SMMU stream mapping. The answer decides whether an EL2 stick log writer is feasible.

Evidence labels follow the Snapintosh `AGENTS.md`. The survey is **EXPERIMENTAL**: built and tested on a host and
on QEMU's EDK2. **It ran once on the unit** (2026-11-14, autorun step 2, build `8235433AAD59`, one boot, photographs):
it reached `STK AT DONE` and its verdict with no fault, no hang and no write, so its format and its guards worked
there; the values it printed are **OBSERVED** once and are recorded in section 12 of the Snapintosh
`docs/SP11-STICK-LOG.md`, not repeated here. Register offsets are **VERIFIED** only as what the pinned Linux source
says (the design document lists the lines); that the unit behaves so is **INFERRED** wherever the run did not show it.

## Build

The survey is a second image, built from the same tree with a compile-time gate that is off by default:

```sh
make -f platform/uefi/Makefile SP11=1 STK_SURVEY=1 \
    SP11_USB_TABLE_C=<file from sp11_usb_ports.py emit-c> \
    SP11_STAGE_TABLE_C=<file defining q1n1_sp11_stage_table_get()> \
    stk-survey                       # -> $(OUT)/q1n1-stk.efi   (OUT defaults to build/uefi)
```

* `Q1N1_SP11_STK_SURVEY` (default 0) needs `SNAP_PLATFORM_SP11=1` and is an `#error` without it, in `main.c` and
  in every `platform/uefi/sp11-stk-*` file. `STK_SURVEY=1` without `SP11=1` is refused by the Makefile.
* Only `main-stk.obj` and the `sp11-stk-*.obj` objects are compiled with the gate. `q1n1.efi`, the stages and
  every object they use are what a build without `STK_SURVEY` makes, byte for byte (see "Default-off proof").
  `make ... STK_SURVEY=1 all` also builds the normal artefacts beside `q1n1-stk.efi`.
* Put the image on the stick as `Q1N1-STK.EFI` beside `Q1N1.EFI` and run it with the same argument:
  `Q1N1-STK.EFI --el2`. There is no new runtime option and the argument parsing is unchanged; the survey runs
  only in the `--el2` flow (never `--boot`, `--uart` alone or `--uart-proxy`). Allow-listing the new image name
  in any autorun is outside this change.

## What it prints

Lines are `key=value` text in the page font (capitals, digits, `: - . / = ? ( ) _`), numbers as `0X` hex with the
fewest digits (decimal for counts), flags 0/1, `?` for a value that could not be read, `NONE` for absent, at most
100 characters per line (a field that would pass 100 starts a continuation line with the same prefix) and at most
60 lines in all. Every line is mirrored to the UART and drawn right of the existing page (below it on a narrow
panel); the page's own lines are not touched. No vendor, product or serial identifier, and no device string, is
ever read or printed.

**P2, before ExitBootServices** (firmware protocols; kept and printed again at EL2, so one photograph holds both):
`STK P2 BUILD`, `SELF`, `HUB`, `BLK`, `USBIO`, `HC` (with `HC<i>` per handle) and `STK P2 U<i>`, the optional
baseline. The baseline is read through the firmware's PCI I/O `Mem.Read` (loads only), only on the host
controller whose device path is the front of the stick's own path, and only after its capability registers look
like xHCI. q1n1's recoverable-fault guard does not exist before ExitBootServices, so a raw load is not made there.
`STK P2 UX` is that line when BAR 0 matches neither of the two Surface windows.

**EL2, after the bounce**, each block preceded by `STK NEXT <BLOCK>` (`MAP`, `GCC`, `U0`, `U1`, `FWRINGS0`,
`FWRINGS1`, `SMMU`), so that after a hang the last NEXT line names the culprit: `STK P3 MAP`, `GCC` (both
controllers and `SHARED`), `GATE`, then per controller **only if the gate is ON** `ID`, `XECP`, `OP`, `PORT<n>`
(at most 4), `DWC3`, `GLUE`, `FWRINGS`, `SLOT<n>` (at most 3, each endpoint `EP<d>=<state>.<type>.<mps>`), then
`STK P3 SMMU`, `STK P3 SMMU S1420` / `S1460` and `STK P3 VERDICT U0=.. U1=.. SMMU=..`.

Gate: `ON` is GDSC power bit set and all nine clocks running (bit 31 clear); `OFF` is the power bit clear;
`PARTIAL` is power on and a clock off; a register that could not be read makes it `?` and the controller is
not read. The voted clocks are also hardware clock gated, so a clock that is off but unneeded reads `PARTIAL`:
the rule is conservative on purpose.

### Differences from Appendix A

| Item | Appendix A | Here | Why |
| --- | --- | --- | --- |
| Controller verdicts | seven names | adds `UNREAD` (gate or ID unknown) and `CONNECTED-NO-SLOT` (a connected port, no firmware slot on it) | `IDLE` would be false for the second; the first is not a fault |
| SMMU global line | decoded fields | on an all-ones block (what the bus returns for nothing) the raw words stay, the decoded fields print `?`, and `SKIPPED=NOT_SMMU` is added | no SMMU has such an ID0 or sCR0 |
| Extra fields | - | `MPSOUT`, `PATHERR`, `MORE`, `MORESLOTS`, `MULTI`, `TRUNC`, `FAULT=<reg>`, `SKIPPED=<reason>` | said once, where a value is missing or bounded |
| Extra lines | - | `STK P3 TRUNC DROPPED=<n>`, `STK P2 DROPPED N=<n>`, `STK P3 SKIPPED=NOT_AT_EL2` | a budget or an EL1 landing must be visible |
| In-place marker | - | `STK AT <where>`, screen only, not a line, never mirrored or counted | places a hang finer than the NEXT lines |
| Baseline access | "MMIO" | firmware PCI I/O `Mem.Read` | see above |

## Safety

* **Loads only.** The one memory primitive is `stk_ops.guarded`, backed in `main.c` by `live_guarded` (q1n1's
  recoverable-fault copy); the survey asks only for the load kind, and the shim refuses any other kind.
* **Every MMIO load** is inside its window, 32-bit aligned, after the memory map was checked (a window the map
  calls RAM or firmware is refused), through a page mapped Device at stage 1 (`q1n1_mmu_attr`), and within a
  total budget of 2000 loads. A guarded abort prints `FAULT=<register>`, stops further MMIO to that controller
  and the survey continues; a block that cannot be produced prints `SKIPPED=<reason>`.
* **Controller registers are read only when the gate is ON**: reading a power- or clock-gated block can hang the
  bus, and a hang is recovered only by a power cycle. That is why the NEXT lines come first.
* **Every walk is bounded**: ext-cap list (16 caps, 4 protocols), ports (4), slots (8 scanned, 3 shown), endpoint
  contexts (31), SMR scan (256). Device-supplied offsets are added in 64 bits and refused when outside the window.
* **No pointer is followed unless the saved UEFI memory map shows it as RAM** (and no overlapping descriptor says
  otherwise), 64-byte aligned for the DCBAA and device contexts.

## Tests

All native tests run under ASan and UBSan; none runs on a Surface Pro 11.

```sh
python3 -B tools/test-q1n1-sp11-stk.py        # 4 native programs, 27 seeded-bug mutants + control, source audits
python3 -B tools/test-q1n1-sp11-entry.py      # existing tests plus the default-off proof for this gate
python3 -B tools/test-q1n1-sp11-qemu.py       # QEMU/EDK2: the plain image, then the survey image (fail-closed)
```

Environment: `Q1N1_SP11_BASE_DIR` (a pristine checkout of the commit before the survey; SKIP without),
`Q1N1_HOSTLINK_BASE_DIR`, `SLBOUNCE_SP11_DIR`, `SNAPINTOSH_DIR` (the design document comparisons; SKIP without).

## Default-off proof

`tools/test-q1n1-sp11-entry.py` (class `DefaultOff`): with the gate 0 `main.c` preprocesses to the same text, with
and without SP11; at 1 without SP11 it is an `#error` everywhere; every survey file compiles to an object with
no symbols; the default and plain-SP11 `make -n` lines are unchanged; and, against `Q1N1_SP11_BASE_DIR`, the plain
SP11=1 `q1n1.efi`, the stages and `main.c`'s preprocessed text are byte-identical to the tree before the survey.
The survey build leaves every other artefact byte-identical and is the only image with the survey's text in it.

## Not done here

Anything that writes to hardware, xHCI initialisation, rings or enumeration (stages S1 and later); the stick log
writer; autorun allow-lists; any change to `--boot`, `--uart` or `--uart-proxy`.

## Gaps the run on the unit showed

None of these changes the survey image. The payload `usbsmmu` (`docs/SP11-PAYLOAD-USBSMMU.md`) covers the first and the
third without a new survey boot; the second and the fourth stay open.

* `USBSTS` bit 12 (HCE, host controller error) is not decoded, and the verdict ignores it. The unit's xHC read `0x1019`
  after the bounce, HCE among the bits, and the survey printed only the raw value; `HSE` (bit 2) is the one it names.
* The firmware lists four xHCI handles and the survey shows three (`STK_P2_HC_SHOWN`); the line says `MORE=1`.
* The SMMU stream lines say a stream translates through a context bank (bank 3 on the unit) and nothing about the
  bank: its type, tables and what it maps are not read.
* The endpoint buffer of the USB descriptor read is 7 bytes: right for packed descriptors, one byte short if a
  firmware copies an unpacked 8-byte structure. Low priority.
