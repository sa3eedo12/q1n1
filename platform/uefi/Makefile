# SPDX-License-Identifier: MIT
# Invoke from the repository root: make -f platform/uefi/Makefile
LLVM ?= /opt/homebrew/opt/llvm/bin
CC := $(if $(wildcard $(LLVM)/clang),$(LLVM)/clang,clang)
LD := lld-link
OUT ?= build/uefi
# -MMD -MP is not a nicety here. These objects share structs that live in shared
# memory across a chainload, so when a header changes and only some objects are
# rebuilt, the survivors disagree about where the fields are -- and the failure
# is silent: counters read as pointers, a stage adopts a block it cannot parse,
# and the corruption looks like a driver bug. That cost two separate debugging
# sessions before anyone suspected the build.
CFLAGS := --target=aarch64-pc-windows-msvc -O2 -ffreestanding -fno-builtin \
          -fno-stack-protector -fshort-wchar -mgeneral-regs-only -mno-outline-atomics \
          -Wall -Wextra -Werror -Iplatform/uefi -MMD -MP

LLD := $(if $(wildcard $(LLVM)/lld),$(LLVM)/lld -flavor gnu,ld.lld)
OBJCOPY := $(if $(wildcard $(LLVM)/llvm-objcopy),$(LLVM)/llvm-objcopy,llvm-objcopy)
# A chainloaded stage is a flat ELF-linked binary, not a PE image: no firmware
# loads it, the running payload uploads it over the proxy and jumps to it.
STAGE_CFLAGS := --target=aarch64-unknown-none-elf -O2 -ffreestanding -fno-builtin \
    -fno-stack-protector -mgeneral-regs-only -mno-outline-atomics -fno-pic -mcmodel=small \
    -Wall -Wextra -Werror -Iplatform/uefi -DQ1N1_STAGE -MMD -MP
STAGE_OBJS := $(addprefix $(OUT)/stage/,main.obj entry.obj q1n1-proxy.obj proxy-asm.obj \
    qcom-dwc3.obj usb-ports.obj gicv3.obj console.obj sysinfo.obj fbcon.obj xhci.obj ncm.obj ncm-proxy.obj preload.obj sha256.obj \
    battery.obj smem.obj glink-smem.obj pmic-router.obj live-battery.obj gpu-el2.obj call-service.obj)

# Surface Pro 11 build (default off): SP11=1 SP11_USB_TABLE_C=<file written by Snapintosh tools/sp11_usb_ports.py
# emit-c>. The table is build input generated from the board descriptor; nothing here supplies a default for it.
# Without SP11=1 none of this is read and every command line above is unchanged.
#
# SP11_STAGE_TABLE_C=<C file defining q1n1_sp11_stage_table_get()> (platform/uefi/sp11-stage-table.h): the
# board-config-supplied chainload candidate list (docs/SP11-Q1N1-BOOT-STUDY.md section 9.1). No generator tool
# exists yet for this one (section 12 item 3 is still an open question this patch's REPORT.md records); a real build
# needs this file from whatever carrier is eventually chosen, same fail-closed posture as SP11_USB_TABLE_C --
# tools/testdata/sp11-stage-table-fixture.c is a test-only example, not a default.
SP11 ?= 0
SP11_OBJS :=
ifeq ($(SP11),1)
ifeq ($(strip $(SP11_USB_TABLE_C)),)
$(error SP11=1 needs SP11_USB_TABLE_C=<C file from sp11_usb_ports.py emit-c>)
endif
ifeq ($(strip $(SP11_STAGE_TABLE_C)),)
$(error SP11=1 needs SP11_STAGE_TABLE_C=<C file defining q1n1_sp11_stage_table_get(), see sp11-stage-table.h>)
endif
CFLAGS += -DSNAP_PLATFORM_SP11=1
STAGE_CFLAGS += -DSNAP_PLATFORM_SP11=1
# SP11_BUILD_STAMP is drawn on the post-ExitBootServices page so a photograph says which commit ran. The page font
# has capital letters, digits and '-' only, so the stamp is folded to those. `git describe --dirty` marks a tree
# whose tracked files differ from the commit and `--exclude='*'` keeps tags out of it (the bare commit is what a
# photograph needs); outside a git checkout it falls back to UNSTAMPED. Override with
# SP11_BUILD_STAMP=... for a build that is not from a checkout. Inside this SP11 block, so the default build's
# command lines are unchanged.
SP11_BUILD_STAMP ?= $(or $(shell git describe --always --dirty --abbrev=12 --exclude='*' 2>/dev/null | tr 'a-z' 'A-Z' | tr -c 'A-Z0-9\n-' '-'),UNSTAMPED)
CFLAGS += -DSP11_BUILD_STAMP=\"$(SP11_BUILD_STAMP)\"
SP11_OBJS := $(OUT)/sp11-usb-ports.obj $(OUT)/sp11-usb-table.obj $(OUT)/sp11-fbgop.obj \
    $(OUT)/sp11-stage-table.obj $(OUT)/sp11-stage-candidates.obj
STAGE_OBJS += $(OUT)/stage/sp11-usb-ports.obj $(OUT)/stage/sp11-usb-table.obj

$(OUT)/sp11-usb-ports.obj: platform/uefi/sp11-usb-ports.c platform/uefi/sp11-usb-ports.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/sp11-usb-table.obj: $(SP11_USB_TABLE_C) platform/uefi/sp11-usb-ports.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -Iplatform/uefi -c $< -o $@

$(OUT)/stage/sp11-usb-table.obj: $(SP11_USB_TABLE_C) platform/uefi/sp11-usb-ports.h
	@mkdir -p $(OUT)/stage
	$(CC) $(STAGE_CFLAGS) -c $< -o $@

# EFI-image-only (docs/SP11-Q1N1-BOOT-STUDY.md sections 8/9.1): the GOP two-tier selection and the
# chainload candidate table are both pre-EBS logic inside main.c's own #ifndef Q1N1_STAGE block, and
# neither is needed by a chainloaded stage (F15: a stage inherits bootinfo; it does not itself pick
# where to load), so unlike the USB port driver above, these are not added to STAGE_OBJS.
$(OUT)/sp11-fbgop.obj: platform/uefi/sp11-fbgop.c platform/uefi/sp11-fbgop.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/sp11-stage-table.obj: platform/uefi/sp11-stage-table.c platform/uefi/sp11-stage-table.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/sp11-stage-candidates.obj: $(SP11_STAGE_TABLE_C) platform/uefi/sp11-stage-table.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -Iplatform/uefi -c $< -o $@
endif

# Surface Pro 11 stick-log survey (default off), stage S0 of docs/SP11-STICK-LOG.md in the Snapintosh
# repository: a read-only look at the USB controller the boot stick sits on, printed as STK lines. It is a second
# image, $(OUT)/q1n1-stk.efi (Q1N1-STK.EFI on the stick, beside the normal Q1N1.EFI), run with the same --el2
# argument, built from its own main-stk.obj and sp11-stk-*.obj with -DQ1N1_SP11_STK_SURVEY=1. Nothing else is
# compiled with that define, so q1n1.efi, the stages and every object they use are the ones a build without
# STK_SURVEY makes, byte for byte. It needs SP11=1: the survey reads the Surface Pro 11's windows. Build it with
#   make -f platform/uefi/Makefile SP11=1 STK_SURVEY=1 SP11_USB_TABLE_C=... SP11_STAGE_TABLE_C=... stk-survey
STK_SURVEY ?= 0
ifeq ($(STK_SURVEY),1)
ifneq ($(SP11),1)
$(error STK_SURVEY=1 needs SP11=1 (with SP11_USB_TABLE_C and SP11_STAGE_TABLE_C): the survey reads the Surface Pro 11's windows)
endif
endif

.PHONY: all clean usb-probe usb-role-probe usb-role-fixture usb-role-change usb-serial usb-typec-probe usb-ucsi-probe
all: $(OUT)/q1n1.efi stage
stage: $(OUT)/q1n1-stage.bin $(OUT)/q1n1-stage-alt.bin $(OUT)/q1n1-stage-qemu.bin $(OUT)/q1n1-stage-qemu-alt.bin
.PHONY: stage
usb-probe: $(OUT)/q1n1-usb-probe.efi
usb-role-probe: $(OUT)/q1n1-usb-role-probe.efi
usb-role-fixture: $(OUT)/usb-role-fixture.efi
usb-role-change: $(OUT)/q1n1-usb-role-change.efi
usb-controller-probe: $(OUT)/q1n1-usb-controller-probe.efi
.PHONY: usb-controller-probe
usb-serial: $(OUT)/q1n1-usb-serial.efi
usb-serial-v3: $(OUT)/q1n1-usb-serial-v3.efi
.PHONY: usb-serial-v3
usb-ebs-prep: $(OUT)/q1n1-usb-ebs-prep.efi
usb-ebs: $(OUT)/q1n1-usb-ebs.efi
.PHONY: usb-ebs-prep usb-ebs
usb-typec-probe: $(OUT)/q1n1-usb-typec-probe.efi
usb-ucsi-probe: $(OUT)/q1n1-usb-ucsi-probe.efi
usb-usbc-probe: $(OUT)/q1n1-usb-usbc-probe.efi
.PHONY: usb-usbc-probe
usb-ucsi-reg-probe: $(OUT)/q1n1-usb-ucsi-reg-probe.efi
.PHONY: usb-ucsi-reg-probe
usb-ucsi-status: $(OUT)/q1n1-usb-ucsi-status.efi
.PHONY: usb-ucsi-status
usb-ucsi-status-v2: $(OUT)/q1n1-usb-ucsi-status-v2.efi
.PHONY: usb-ucsi-status-v2
usb-ucsi-device0: $(OUT)/q1n1-usb-ucsi-device0.efi
.PHONY: usb-ucsi-device0

$(OUT)/usb-ucsi-device0.obj: platform/uefi/usb-ucsi-device0.c platform/uefi/usb-ucsi-status-v2.c platform/uefi/usb-ucsi-status.c platform/uefi/usb-ucsi-reg-probe.c platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-ucsi-device0.efi: $(OUT)/usb-ucsi-device0.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-ucsi-status-v2.obj: platform/uefi/usb-ucsi-status-v2.c platform/uefi/usb-ucsi-status.c platform/uefi/usb-ucsi-reg-probe.c platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-ucsi-status-v2.efi: $(OUT)/usb-ucsi-status-v2.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-ucsi-status.obj: platform/uefi/usb-ucsi-status.c platform/uefi/usb-ucsi-reg-probe.c platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-ucsi-status.efi: $(OUT)/usb-ucsi-status.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-ucsi-reg-probe.obj: platform/uefi/usb-ucsi-reg-probe.c platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-ucsi-reg-probe.efi: $(OUT)/usb-ucsi-reg-probe.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-usbc-probe.obj: platform/uefi/usb-usbc-probe.c platform/uefi/usb-ucsi-probe.c platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-usbc-probe.efi: $(OUT)/usb-usbc-probe.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-ucsi-probe.obj: platform/uefi/usb-ucsi-probe.c platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-ucsi-probe.efi: $(OUT)/usb-ucsi-probe.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-typec-probe.obj: platform/uefi/usb-typec-probe.c platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-typec-probe.efi: $(OUT)/usb-typec-probe.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-ebs-prep.obj: platform/uefi/usb-ebs-prep.c platform/uefi/usb-ebs.h platform/uefi/qcom-dwc3.h platform/uefi/usb-serial.c platform/uefi/usb-role-change.c platform/uefi/usbfn.h platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-ebs-prep.efi: $(OUT)/usb-ebs-prep.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

# QEMU-only fixture (fake controller in RAM). Never include in a hardware kit.
usb-ebs-fixture: $(OUT)/usb-ebs-fixture.efi
.PHONY: usb-ebs-fixture
$(OUT)/usb-ebs-fixture.obj: platform/uefi/usb-ebs.c platform/uefi/usb-ebs.h platform/uefi/qcom-dwc3.h platform/uefi/fbcon.h platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -DUSB_EBS_QEMU_FIXTURE -c $< -o $@

$(OUT)/usb-ebs-fixture.efi: $(OUT)/usb-ebs-fixture.obj $(OUT)/qcom-dwc3.obj $(OUT)/fbcon.obj $(OUT)/entry.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-ebs.obj: platform/uefi/usb-ebs.c platform/uefi/usb-ebs.h platform/uefi/qcom-dwc3.h platform/uefi/fbcon.h platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/qcom-dwc3.obj: platform/uefi/qcom-dwc3.c platform/uefi/qcom-dwc3.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/sysinfo.obj: platform/uefi/sysinfo.c platform/uefi/sysinfo.h platform/uefi/console.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/console.obj: platform/uefi/console.c platform/uefi/console.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/fbcon.obj: platform/uefi/fbcon.c platform/uefi/fbcon.h platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-ebs.efi: $(OUT)/usb-ebs.obj $(OUT)/qcom-dwc3.obj $(OUT)/fbcon.obj $(OUT)/entry.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-serial-v3.obj: platform/uefi/usb-serial-v3.c platform/uefi/usb-serial.c platform/uefi/usb-role-change.c platform/uefi/usbfn.h platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-serial-v3.efi: $(OUT)/usb-serial-v3.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-serial.obj: platform/uefi/usb-serial.c platform/uefi/usb-role-change.c platform/uefi/usbfn.h platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-serial.efi: $(OUT)/usb-serial.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-controller-probe.obj: platform/uefi/usb-controller-probe.c platform/uefi/usb-role-change.c platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-controller-probe.efi: $(OUT)/usb-controller-probe.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-role-change.obj: platform/uefi/usb-role-change.c platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-role-change.efi: $(OUT)/usb-role-change.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-role-probe.obj: platform/uefi/usb-probe.c platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -DA16_USB_ROLE_PROBE=1 -c $< -o $@

$(OUT)/q1n1-usb-role-probe.efi: $(OUT)/usb-role-probe.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

# Synthetic protocol data for QEMU tests only. Never include in a hardware kit.
$(OUT)/usb-role-fixture.obj: tools/uefi-usb-role-fixture.c platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/usb-role-fixture.efi: $(OUT)/usb-role-fixture.obj
	$(LD) /subsystem:efi_boot_service_driver /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/usb-probe.obj: platform/uefi/usb-probe.c platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-usb-probe.efi: $(OUT)/usb-probe.obj
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

$(OUT)/main.obj: platform/uefi/main.c platform/uefi/efi.h platform/uefi/fbcon.h platform/uefi/boot-window.h \
    platform/uefi/usb-ebs.h platform/uefi/qcom-dwc3.h platform/uefi/q1n1-proxy.h platform/uefi/gicv3.h \
    platform/uefi/q1n1-bootinfo.h platform/uefi/live-battery.h platform/uefi/glink-smem.h \
    platform/uefi/pmic-router.h platform/uefi/smem.h platform/uefi/battery.h platform/uefi/gpu-el2.h \
    platform/uefi/call-service.h platform/uefi/ncm-proxy.h platform/uefi/usb-ports.h \
    platform/uefi/sp11-ebs-ranges.h platform/uefi/sp11-fbgop.h platform/uefi/sp11-stage-table.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/entry.obj: platform/uefi/entry.S data/bootlogo_256.bin data/asahi_bootlogo_256.bin font/font_retina.bin
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

# q1n1.efi uses recoverable exception vectors; the older test apps keep entry.obj.
$(OUT)/entry-frame.obj: platform/uefi/entry.S data/bootlogo_256.bin data/asahi_bootlogo_256.bin font/font_retina.bin
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -DQ1N1_EXCEPTION_FRAME -c $< -o $@

# The boot window reuses the serial-v3 firmware USB code; its echo helpers stay unused.
$(OUT)/boot-window.obj: platform/uefi/boot-window.c platform/uefi/boot-window.h platform/uefi/usb-ebs.h \
    platform/uefi/qcom-dwc3.h platform/uefi/usb-serial.c platform/uefi/usb-role-change.c platform/uefi/usbfn.h \
    platform/uefi/ucsi-console.h platform/uefi/battery.h platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -Wno-unused-function -c $< -o $@

$(OUT)/battery.obj: platform/uefi/battery.c platform/uefi/battery.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

# The live battery path: SMEM parser, GLINK-over-SMEM client, PMIC router and
# the P_CALL entry. Their structs cross a chainload (bootinfo battery_session).
$(OUT)/smem.obj: platform/uefi/smem.c platform/uefi/smem.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/glink-smem.obj: platform/uefi/glink-smem.c platform/uefi/glink-smem.h platform/uefi/smem.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/pmic-router.obj: platform/uefi/pmic-router.c platform/uefi/pmic-router.h platform/uefi/glink-smem.h \
    platform/uefi/smem.h platform/uefi/battery.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/live-battery.obj: platform/uefi/live-battery.c platform/uefi/live-battery.h platform/uefi/pmic-router.h \
    platform/uefi/glink-smem.h platform/uefi/smem.h platform/uefi/battery.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

# Adreno Stage 3: the GPU arena and the allow-listed SMC (bootinfo gpu_call).
$(OUT)/gpu-el2.obj: platform/uefi/gpu-el2.c platform/uefi/gpu-el2.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

# The UCSI console reuses the tested PmicGlink transport; its one-shot helpers stay unused.
$(OUT)/ucsi-console.obj: platform/uefi/ucsi-console.c platform/uefi/ucsi-console.h platform/uefi/usb-ucsi-status.c \
    platform/uefi/usb-ucsi-reg-probe.c platform/uefi/battery.h platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -Wno-unused-function -c $< -o $@

$(OUT)/gicv3.obj: platform/uefi/gicv3.c platform/uefi/gicv3.h platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/xhci.obj: platform/uefi/xhci.c platform/uefi/xhci.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/ncm.obj: platform/uefi/ncm.c platform/uefi/ncm.h platform/uefi/xhci.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/ncm-proxy.obj: platform/uefi/ncm-proxy.c platform/uefi/ncm-proxy.h platform/uefi/ncm.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/call-service.obj: platform/uefi/call-service.c platform/uefi/call-service.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/usb1-device.obj: platform/uefi/usb1-device.c platform/uefi/usb1-device.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/usb-ports.obj: platform/uefi/usb-ports.c platform/uefi/usb-ports.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/q1n1-proxy.obj: platform/uefi/q1n1-proxy.c platform/uefi/q1n1-proxy.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/proxy-asm.obj: platform/uefi/proxy-asm.S
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/preload.obj: platform/uefi/preload.c platform/uefi/preload.h platform/uefi/sha256.h platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/gpt-survey.obj: platform/uefi/gpt-survey.c platform/uefi/gpt-survey.h platform/uefi/efi.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/sha256.obj: platform/uefi/sha256.c platform/uefi/sha256.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

Q1N1_IMAGE_OBJS := $(OUT)/entry-frame.obj $(OUT)/boot-window.obj $(OUT)/ucsi-console.obj $(OUT)/battery.obj \
    $(OUT)/q1n1-proxy.obj $(OUT)/proxy-asm.obj $(OUT)/qcom-dwc3.obj $(OUT)/usb-ports.obj $(OUT)/gicv3.obj \
    $(OUT)/console.obj $(OUT)/sysinfo.obj $(OUT)/fbcon.obj $(OUT)/xhci.obj $(OUT)/ncm.obj $(OUT)/ncm-proxy.obj \
    $(OUT)/preload.obj $(OUT)/gpt-survey.obj $(OUT)/sha256.obj $(OUT)/smem.obj $(OUT)/glink-smem.obj $(OUT)/pmic-router.obj \
    $(OUT)/live-battery.obj $(OUT)/gpu-el2.obj $(OUT)/call-service.obj
$(OUT)/q1n1.efi: $(OUT)/main.obj $(Q1N1_IMAGE_OBJS) $(SP11_OBJS)
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

ifeq ($(STK_SURVEY),1)
STK_OBJS := $(addprefix $(OUT)/,sp11-stk-text.obj sp11-stk-path.obj sp11-stk-rules.obj sp11-stk-p2fmt.obj \
    sp11-stk-el2.obj sp11-stk-p2.obj)
STK_HEADERS := platform/uefi/sp11-stk-survey.h platform/uefi/sp11-stk-efi.h platform/uefi/sp11-fbgop.h \
    platform/uefi/efi.h

$(STK_OBJS): $(OUT)/%.obj: platform/uefi/%.c $(STK_HEADERS)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -DQ1N1_SP11_STK_SURVEY=1 -c $< -o $@

$(OUT)/main-stk.obj: platform/uefi/main.c $(STK_HEADERS) platform/uefi/fbcon.h platform/uefi/boot-window.h \
    platform/uefi/usb-ebs.h platform/uefi/qcom-dwc3.h platform/uefi/q1n1-proxy.h platform/uefi/gicv3.h \
    platform/uefi/q1n1-bootinfo.h platform/uefi/live-battery.h platform/uefi/gpu-el2.h platform/uefi/call-service.h \
    platform/uefi/ncm-proxy.h platform/uefi/usb-ports.h platform/uefi/sp11-ebs-ranges.h platform/uefi/sp11-stage-table.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -DQ1N1_SP11_STK_SURVEY=1 -c $< -o $@

$(OUT)/q1n1-stk.efi: $(OUT)/main-stk.obj $(Q1N1_IMAGE_OBJS) $(SP11_OBJS) $(STK_OBJS)
	$(LD) /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 \
	    /dynamicbase /out:$@ $^

.PHONY: stk-survey
stk-survey: $(OUT)/q1n1-stk.efi
all: $(OUT)/q1n1-stk.efi
endif

$(OUT)/stage/%.obj: platform/uefi/%.c
	@mkdir -p $(OUT)/stage
	$(CC) $(STAGE_CFLAGS) -c $< -o $@

$(OUT)/stage/%.obj: platform/uefi/%.S data/bootlogo_256.bin data/asahi_bootlogo_256.bin font/font_retina.bin
	@mkdir -p $(OUT)/stage
	$(CC) $(STAGE_CFLAGS) -DQ1N1_EXCEPTION_FRAME -c $< -o $@

# Two link addresses: the A16 reserves 0xb0000000, QEMU's virt machine has RAM
# at 0x40000000, so the payload reserves whichever it can and reports it.
$(OUT)/q1n1-stage.bin: $(STAGE_OBJS) platform/uefi/stage.ld
	$(LLD) -T platform/uefi/stage.ld --defsym=STAGE_BASE=0xb0000000 -o $(OUT)/stage/hardware.elf $(STAGE_OBJS)
	$(OBJCOPY) -O binary $(OUT)/stage/hardware.elf $@

$(OUT)/q1n1-stage-qemu.bin: $(STAGE_OBJS) platform/uefi/stage.ld
	$(LLD) -T platform/uefi/stage.ld --defsym=STAGE_BASE=0x4c000000 -o $(OUT)/stage/qemu.elf $(STAGE_OBJS)
	$(OBJCOPY) -O binary $(OUT)/stage/qemu.elf $@

# A second slot in the same reserved region: a running stage cannot be replaced
# in place, so successive chainloads alternate between the two.
$(OUT)/q1n1-stage-alt.bin: $(STAGE_OBJS) platform/uefi/stage.ld
	$(LLD) -T platform/uefi/stage.ld --defsym=STAGE_BASE=0xb0800000 -o $(OUT)/stage/hardware-alt.elf $(STAGE_OBJS)
	$(OBJCOPY) -O binary $(OUT)/stage/hardware-alt.elf $@

$(OUT)/q1n1-stage-qemu-alt.bin: $(STAGE_OBJS) platform/uefi/stage.ld
	$(LLD) -T platform/uefi/stage.ld --defsym=STAGE_BASE=0x4c800000 -o $(OUT)/stage/qemu-alt.elf $(STAGE_OBJS)
	$(OBJCOPY) -O binary $(OUT)/stage/qemu-alt.elf $@

# Every object's header list, as the compiler saw it. Missing on a first build,
# which is what the leading dash is for.
-include $(wildcard $(OUT)/*.d) $(wildcard $(OUT)/stage/*.d)

clean:
	rm -f $(OUT)/*.d $(OUT)/stage/*.d $(OUT)/stage/*.obj $(OUT)/stage/*.elf \
	    $(OUT)/q1n1-stage.bin $(OUT)/q1n1-stage-alt.bin \
	    $(OUT)/q1n1-stage-qemu.bin $(OUT)/q1n1-stage-qemu-alt.bin
	rm -f $(OUT)/*.obj $(OUT)/q1n1.efi $(OUT)/q1n1-stk.efi $(OUT)/q1n1-usb-probe.efi \
	    $(OUT)/q1n1-usb-role-probe.efi $(OUT)/usb-role-fixture.efi \
	    $(OUT)/q1n1-usb-role-change.efi $(OUT)/q1n1-usb-serial.efi $(OUT)/q1n1-usb-typec-probe.efi \
	    $(OUT)/q1n1-usb-ucsi-probe.efi $(OUT)/q1n1-usb-usbc-probe.efi $(OUT)/q1n1-usb-ucsi-reg-probe.efi \
	    $(OUT)/q1n1-usb-ucsi-status.efi $(OUT)/q1n1-usb-ucsi-status-v2.efi $(OUT)/q1n1-usb-ucsi-device0.efi \
	    $(OUT)/q1n1-usb-controller-probe.efi $(OUT)/q1n1-usb-serial-v3.efi \
	    $(OUT)/q1n1-usb-ebs-prep.efi $(OUT)/q1n1-usb-ebs.efi $(OUT)/usb-ebs-fixture.efi
