/* SPDX-License-Identifier: MIT */
/* The scenarios of the nvmesnap host test (tools/test-q1n1-sp11-payload-nvmesnap.c): the good world with one thing changed, what the payload must
 * say of it, and the runner that holds every scenario to the discipline of the world model. A scenario names the WHY the verdict must give; a world
 * whose controller registers must not be read is run with a judge that allows no load there and no load of RAM, so that a stray load is a failure
 * whatever the payload printed. Evidence: EXPERIMENTAL (host model only). */
#pragma once

struct scen {
    const char *name;
    void (*apply)(struct world *w);
    const char *why;                    /* the WHY of the verdict; "NONE" for a world whose registers are still read */
    unsigned caps;                      /* 1: the capability groups ran (a NEXT CAPS line), 0: the header gate said no first */
    unsigned gate;                      /* 1: the GATE line is printed */
};

#define RPo(o) (RP_PAGE + (o))
#define EPo(o) (EP_PAGE + (o))
#define NVo(o) (BAR_GOOD + (o))
#define SCEN(name, body) static void name(struct world *w) { (void)w; body; }

SCEN(a_none, (void)0)
SCEN(a_rp_absent, bus_set(RPo(0), 0xffffffffu))
SCEN(a_rp_vendor_ffff, bus_set(RPo(0), 0x0222ffffu))
SCEN(a_rp_id_fault, bus_fault(RPo(0)))
SCEN(a_rp_cmd_fault, bus_fault(RPo(0x04)))
SCEN(a_rp_class_fault, bus_fault(RPo(0x08)))
SCEN(a_rp_hdr_fault, bus_fault(RPo(0x0c)))
SCEN(a_rp_class_storage, bus_set(RPo(0x08), 0x01080001u))
SCEN(a_rp_class_host_bridge, bus_set(RPo(0x08), 0x06000001u))
SCEN(a_rp_class_isa_bridge, bus_set(RPo(0x08), 0x06010001u))
SCEN(a_rp_hdr_type0, bus_set(RPo(0x0c), 0x00000010u))
SCEN(a_rp_hdr_type2, bus_set(RPo(0x0c), 0x00020010u))
SCEN(a_rp_hdr_multifunction, bus_set(RPo(0x0c), 0x00810010u))
SCEN(a_rp_buses_fault, bus_fault(RPo(0x18)))
SCEN(a_rp_memwin_fault, bus_fault(RPo(0x20)))
SCEN(a_rp_primary_1, bus_set(RPo(0x18), 0x00010101u))
SCEN(a_rp_secondary_2, bus_set(RPo(0x18), 0x00020200u))
SCEN(a_rp_secondary_0, bus_set(RPo(0x18), 0x00010000u))
SCEN(a_rp_subordinate_0, bus_set(RPo(0x18), 0x00000100u))
SCEN(a_rp_subordinate_255, bus_set(RPo(0x18), 0x00ff0100u))
SCEN(a_ep_absent, bus_set(EPo(0), 0xffffffffu))
SCEN(a_ep_vendor_ffff, bus_set(EPo(0), 0xfeedffffu))
SCEN(a_ep_id_fault, bus_fault(EPo(0)))
SCEN(a_ep_cmd_fault, bus_fault(EPo(0x04)))
SCEN(a_ep_class_fault, bus_fault(EPo(0x08)))
SCEN(a_ep_hdr_fault, bus_fault(EPo(0x0c)))
SCEN(a_ep_class_network, bus_set(EPo(0x08), 0x02000001u))
SCEN(a_ep_class_sata, bus_set(EPo(0x08), 0x01060101u))
SCEN(a_ep_class_nvmhci, bus_set(EPo(0x08), 0x01080101u))
SCEN(a_ep_class_other_sub, bus_set(EPo(0x08), 0x01090201u))
SCEN(a_ep_class_other_prog, bus_set(EPo(0x08), 0x01080301u))
SCEN(a_ep_hdr_type1, bus_set(EPo(0x0c), 0x00010010u))
SCEN(a_ep_hdr_multifunction, bus_set(EPo(0x0c), 0x00800010u))
SCEN(a_ep_bar0_fault, bus_fault(EPo(0x10)))
SCEN(a_ep_bar1_fault, bus_fault(EPo(0x14)))
SCEN(a_rp_no_cap_list, bus_set(RPo(0x04), 0x00000007u))
SCEN(a_rp_cap_loop, bus_set(RPo(0x40), 0x00004001u))
SCEN(a_rp_cap_ptr_low, bus_set(RPo(0x34), 0x00000030u))
SCEN(a_rp_cap_ptr_high, bus_set(RPo(0x34), 0x00000100u))
SCEN(a_rp_cap_ptr_unaligned, bus_set(RPo(0x34), 0x00000041u))
SCEN(a_rp_cap_ptr_fault, bus_fault(RPo(0x34)))
SCEN(a_rp_cap_fault, bus_fault(RPo(0x50)))
SCEN(a_rp_linkcap_fault, bus_fault(RPo(0x7c)))
SCEN(a_rp_linksta_fault, bus_fault(RPo(0x80)))
SCEN(a_rp_link_unreported, bus_set(RPo(0x7c), 0x00000c44u))
SCEN(a_rp_link_down, bus_set(RPo(0x80), 0x00440043u))
SCEN(a_rp_link_training, bus_set(RPo(0x80), 0x28440043u))
SCEN(a_rp_link_training_down, bus_set(RPo(0x80), 0x08440043u))
SCEN(a_ep_ptr_fault, bus_fault(EPo(0x34)))
SCEN(a_ep_mem_off, bus_set(EPo(0x04), 0x00100404u))
SCEN(a_ep_bme_off, bus_set(EPo(0x04), 0x00100402u))
SCEN(a_ep_d1, bus_set(EPo(0x44), 0x00000009u))
SCEN(a_ep_d2, bus_set(EPo(0x44), 0x0000000au))
SCEN(a_ep_d3, bus_set(EPo(0x44), 0x0000000bu))
SCEN(a_ep_no_pm, bus_set(EPo(0x40), 0x00007005u))
SCEN(a_ep_pm_csr_fault, bus_fault(EPo(0x44)))
SCEN(a_ep_cap_fault, bus_fault(EPo(0x50)))
SCEN(a_ep_no_pcie, bus_set(EPo(0x70), 0x00000011u))
SCEN(a_ep_link_fault, bus_fault(EPo(0x90)))
SCEN(a_bar_io, bus_set(EPo(0x10), 0x70300005u))
SCEN(a_bar_type1, bus_set(EPo(0x10), 0x70300002u))
SCEN(a_bar_type3, bus_set(EPo(0x10), 0x70300006u))
SCEN(a_bar_32bit, bus_set(EPo(0x10), 0x70300000u); bus_set(EPo(0x14), 0x12345678u))
SCEN(a_bar_prefetchable, bus_set(EPo(0x10), 0x7030000cu))
SCEN(a_bar_high, bus_set(EPo(0x14), 0x00000001u))
SCEN(a_bar_unaligned, bus_set(EPo(0x10), 0x70300014u))
SCEN(a_bar_unaligned_low, bus_set(EPo(0x10), 0x70300104u))
SCEN(a_bar_below_platform, bus_set(EPo(0x10), 0x702ff004u))
SCEN(a_bar_at_platform_end, bus_set(EPo(0x10), 0x74000004u))
SCEN(a_bar_zero, bus_set(EPo(0x10), 0x00000004u))
SCEN(a_bar_last_page, bus_set(EPo(0x10), 0x73fff004u); put_nvme(UINT64_C(0x73fff000), &good_nv);
     tr_map(UINT64_C(0x73fff000), UINT64_C(0x74000000), ATTR_DEVICE, SH_NONE))
SCEN(a_bridge_base_above, bus_set(RPo(0x20), 0x73f07040u))
SCEN(a_bridge_limit_below, bus_set(RPo(0x20), 0x70207030u))
SCEN(a_bridge_empty, bus_set(RPo(0x20), 0x70007ff0u))
SCEN(a_bridge_limit_at_bar, bus_set(RPo(0x20), 0x70307030u))
SCEN(a_bridge_low_bits_ignored, bus_set(RPo(0x20), 0x73f0703fu))
SCEN(a_bar_wb, tr_map(BAR_GOOD, BAR_GOOD + 0x4000, ATTR_WB, SH_INNER))
SCEN(a_bar_nc, tr_map(BAR_GOOD, BAR_GOOD + 0x4000, ATTR_NC, SH_OUTER))
SCEN(a_bar_wt, tr_map(BAR_GOOD, BAR_GOOD + 0x4000, ATTR_WT, SH_INNER))
SCEN(a_bar_unmapped, tr_fault(BAR_GOOD, BAR_GOOD + 0x4000, 0x07))
SCEN(a_bar_device_gre, tr_map(BAR_GOOD, BAR_GOOD + 0x4000, 0x0c, SH_NONE))
SCEN(a_bar_device_ngnre, tr_map(BAR_GOOD, BAR_GOOD + 0x4000, 0x04, SH_NONE))
SCEN(a_bar_attr_reserved, tr_map(BAR_GOOD, BAR_GOOD + 0x4000, 0x01, SH_NONE))
SCEN(a_map_bad_stride, w->a.map_stride = 4)
SCEN(a_map_zero_size, w->a.map_size = 0)
SCEN(a_map_stride_32, w->a.map_stride = 32; w->a.map_size = 160)
SCEN(a_rp_link_gen6, bus_set(RPo(0x80), 0x22060007))
SCEN(a_rp_link_speed7, bus_set(RPo(0x80), 0x23f70043))
SCEN(a_bar_unaligned_2k, bus_set(EPo(0x10), 0x70300804))
SCEN(a_bridge_window_below_bar, bus_set(RPo(0x20), 0x70207020))
SCEN(a_rp_next_unaligned, bus_set(RPo(0x40), 0x00035101))
SCEN(a_ep_two_pm, bus_set(EPo(0x50), 0x00807001); bus_set(EPo(0x54), 0x00000003))
SCEN(a_rp_mem_off, bus_set(RPo(0x04), 0x00100005u))
SCEN(a_rp_type_endpoint, bus_set(RPo(0x70), 0x00020010u))
SCEN(a_rp_type_legacy, bus_set(RPo(0x70), 0x00120010u))
SCEN(a_rp_type_downstream, bus_set(RPo(0x70), 0x00620010u))
SCEN(a_rp_type_pcie_pci_bridge, bus_set(RPo(0x70), 0x00720010u))
SCEN(a_ep_type_integrated, bus_set(EPo(0x80), 0x00920010u))
SCEN(a_ep_type_legacy, bus_set(EPo(0x80), 0x00120010u))
SCEN(a_ep_type_root_port, bus_set(EPo(0x80), 0x00420010u))
/* The endpoint's list with the PCI Express capability before the power management one (0x34 -> 0x80 -> 0x40): the power state is read after the link
 * registers, and a fault anywhere in the page ends it before the state is known. */
SCEN(a_ep_pcie_first, bus_set(EPo(0x34), 0x00000080u); bus_set(EPo(0x80), 0x00024010u))
SCEN(a_ep_pcie_first_pmcsr_fault, bus_set(EPo(0x34), 0x00000080u); bus_set(EPo(0x80), 0x00024010u); bus_fault(EPo(0x44)))
SCEN(a_ep_pcie_first_link_fault, bus_set(EPo(0x34), 0x00000080u); bus_set(EPo(0x80), 0x00024010u); bus_fault(EPo(0x90)))

static const struct scen gate_scens[] = {
    {"good", a_none, "NONE", 1, 1},
    {"rp-absent", a_rp_absent, "RP_ABSENT", 0, 0},
    {"rp-vendor-ffff", a_rp_vendor_ffff, "RP_ABSENT", 0, 0},
    {"rp-id-fault", a_rp_id_fault, "RP_NOT_READ", 0, 0},
    {"rp-cmd-fault", a_rp_cmd_fault, "RP_NOT_READ", 0, 0},
    {"rp-class-fault", a_rp_class_fault, "RP_NOT_READ", 0, 0},
    {"rp-hdr-fault", a_rp_hdr_fault, "RP_NOT_READ", 0, 0},
    {"rp-class-storage", a_rp_class_storage, "RP_NOT_BRIDGE", 0, 0},
    {"rp-class-host-bridge", a_rp_class_host_bridge, "RP_NOT_BRIDGE", 0, 0},
    {"rp-class-isa-bridge", a_rp_class_isa_bridge, "RP_NOT_BRIDGE", 0, 0},
    {"rp-hdr-type0", a_rp_hdr_type0, "RP_NOT_BRIDGE", 0, 0},
    {"rp-hdr-type2", a_rp_hdr_type2, "RP_NOT_BRIDGE", 0, 0},
    {"rp-hdr-multifunction", a_rp_hdr_multifunction, "NONE", 1, 1},
    {"rp-buses-fault", a_rp_buses_fault, "RP_NOT_READ", 0, 0},
    {"rp-memwin-fault", a_rp_memwin_fault, "RP_NOT_READ", 0, 0},
    {"rp-primary-1", a_rp_primary_1, "BRIDGE_BUSES", 0, 0},
    {"rp-secondary-2", a_rp_secondary_2, "BRIDGE_BUSES", 0, 0},
    {"rp-secondary-0", a_rp_secondary_0, "BRIDGE_BUSES", 0, 0},
    {"rp-subordinate-0", a_rp_subordinate_0, "BRIDGE_BUSES", 0, 0},
    {"rp-subordinate-255", a_rp_subordinate_255, "NONE", 1, 1},
    {"ep-absent", a_ep_absent, "EP_ABSENT", 0, 0},
    {"ep-vendor-ffff", a_ep_vendor_ffff, "EP_ABSENT", 0, 0},
    {"ep-id-fault", a_ep_id_fault, "EP_NOT_READ", 0, 0},
    {"ep-cmd-fault", a_ep_cmd_fault, "EP_NOT_READ", 0, 0},
    {"ep-class-fault", a_ep_class_fault, "EP_NOT_READ", 0, 0},
    {"ep-hdr-fault", a_ep_hdr_fault, "EP_NOT_READ", 0, 0},
    {"ep-class-network", a_ep_class_network, "EP_NOT_NVME", 0, 0},
    {"ep-class-sata", a_ep_class_sata, "EP_NOT_NVME", 0, 0},
    {"ep-class-nvmhci", a_ep_class_nvmhci, "EP_NOT_NVME", 0, 0},
    {"ep-class-other-sub", a_ep_class_other_sub, "EP_NOT_NVME", 0, 0},
    {"ep-class-other-prog", a_ep_class_other_prog, "EP_NOT_NVME", 0, 0},
    {"ep-hdr-type1", a_ep_hdr_type1, "EP_NOT_NVME", 0, 0},
    {"ep-hdr-multifunction", a_ep_hdr_multifunction, "NONE", 1, 1},
    {"ep-bar0-fault", a_ep_bar0_fault, "EP_NOT_READ", 0, 0},
    {"ep-bar1-fault", a_ep_bar1_fault, "EP_NOT_READ", 0, 0},
    {"rp-no-cap-list", a_rp_no_cap_list, "NO_LINK_CAPABILITY", 1, 1},
    {"rp-cap-loop", a_rp_cap_loop, "NO_LINK_CAPABILITY", 1, 1},
    {"rp-cap-ptr-low", a_rp_cap_ptr_low, "NO_LINK_CAPABILITY", 1, 1},
    {"rp-cap-ptr-high", a_rp_cap_ptr_high, "NO_LINK_CAPABILITY", 1, 1},
    {"rp-cap-ptr-unaligned", a_rp_cap_ptr_unaligned, "NONE", 1, 1},
    {"rp-cap-ptr-fault", a_rp_cap_ptr_fault, "CAPS_NOT_READ", 1, 1},
    {"rp-cap-fault", a_rp_cap_fault, "CAPS_NOT_READ", 1, 1},
    {"rp-linkcap-fault", a_rp_linkcap_fault, "CAPS_NOT_READ", 1, 1},
    {"rp-linksta-fault", a_rp_linksta_fault, "CAPS_NOT_READ", 1, 1},
    {"rp-link-unreported", a_rp_link_unreported, "LINK_UNPROVEN", 1, 1},
    {"rp-link-down", a_rp_link_down, "LINK_DOWN", 1, 1},
    {"rp-link-training", a_rp_link_training, "LINK_TRAINING", 1, 1},
    {"rp-link-training-down", a_rp_link_training_down, "LINK_DOWN", 1, 1},
    {"ep-cap-ptr-fault", a_ep_ptr_fault, "CAPS_NOT_READ", 1, 1},
    {"ep-mem-off", a_ep_mem_off, "MEMORY_SPACE_OFF", 1, 1},
    {"ep-bme-off", a_ep_bme_off, "NONE", 1, 1},
    {"ep-d1", a_ep_d1, "NOT_IN_D0", 1, 1},
    {"ep-d2", a_ep_d2, "NOT_IN_D0", 1, 1},
    {"ep-d3", a_ep_d3, "NOT_IN_D0", 1, 1},
    {"ep-no-pm", a_ep_no_pm, "NONE", 1, 1},
    {"ep-pm-csr-fault", a_ep_pm_csr_fault, "CAPS_NOT_READ", 1, 1},
    {"ep-cap-fault", a_ep_cap_fault, "CAPS_NOT_READ", 1, 1},
    {"ep-no-pcie", a_ep_no_pcie, "NONE", 1, 1},
    {"ep-link-fault", a_ep_link_fault, "NONE", 1, 1},
    {"bar-io", a_bar_io, "BAR0_NOT_MEMORY", 1, 1},
    {"bar-type-1", a_bar_type1, "BAR0_NOT_MEMORY", 1, 1},
    {"bar-type-3", a_bar_type3, "BAR0_NOT_MEMORY", 1, 1},
    {"bar-32bit", a_bar_32bit, "NONE", 1, 1},
    {"bar-prefetchable", a_bar_prefetchable, "NONE", 1, 1},
    {"bar-high-word", a_bar_high, "BAR0_OUTSIDE_PLATFORM_WINDOW", 1, 1},
    {"bar-unaligned", a_bar_unaligned, "BAR0_UNALIGNED", 1, 1},
    {"bar-unaligned-low", a_bar_unaligned_low, "BAR0_UNALIGNED", 1, 1},
    {"bar-below-platform", a_bar_below_platform, "BAR0_OUTSIDE_PLATFORM_WINDOW", 1, 1},
    {"bar-at-platform-end", a_bar_at_platform_end, "BAR0_OUTSIDE_PLATFORM_WINDOW", 1, 1},
    {"bar-zero", a_bar_zero, "BAR0_OUTSIDE_PLATFORM_WINDOW", 1, 1},
    {"bar-last-page", a_bar_last_page, "NONE", 1, 1},
    {"bridge-base-above", a_bridge_base_above, "BAR0_OUTSIDE_BRIDGE_WINDOW", 1, 1},
    {"bridge-limit-below", a_bridge_limit_below, "BAR0_OUTSIDE_BRIDGE_WINDOW", 1, 1},
    {"bridge-empty", a_bridge_empty, "BAR0_OUTSIDE_BRIDGE_WINDOW", 1, 1},
    {"bridge-limit-at-bar", a_bridge_limit_at_bar, "NONE", 1, 1},
    {"bridge-low-bits-ignored", a_bridge_low_bits_ignored, "NONE", 1, 1},
    {"bar-page-wb", a_bar_wb, "BAR0_PAGE_NOT_DEVICE", 1, 1},
    {"bar-page-nc", a_bar_nc, "BAR0_PAGE_NOT_DEVICE", 1, 1},
    {"bar-page-wt", a_bar_wt, "BAR0_PAGE_NOT_DEVICE", 1, 1},
    {"bar-page-unmapped", a_bar_unmapped, "BAR0_PAGE_UNMAPPED", 1, 1},
    {"bar-page-gre", a_bar_device_gre, "NONE", 1, 1},
    {"bar-page-device-ngnre", a_bar_device_ngnre, "NONE", 1, 1},
    {"bar-page-attr-01", a_bar_attr_reserved, "BAR0_PAGE_NOT_DEVICE", 1, 1},
    {"map-bad-stride", a_map_bad_stride, "MEMORY_MAP_UNREADABLE", 1, 1},
    {"map-zero-size", a_map_zero_size, "MEMORY_MAP_UNREADABLE", 1, 1},
    {"map-stride-32", a_map_stride_32, "MEMORY_MAP_UNREADABLE", 1, 1},
    {"rp-link-gen6-x32", a_rp_link_gen6, "NONE", 1, 1},
    {"rp-link-aspm-is-two-bits", a_rp_link_gen6, "NONE", 1, 1},
    {"rp-link-speed-7-x63", a_rp_link_speed7, "NONE", 1, 1},
    {"bar-unaligned-2k", a_bar_unaligned_2k, "BAR0_UNALIGNED", 1, 1},
    {"bridge-window-below-bar", a_bridge_window_below_bar, "BAR0_OUTSIDE_BRIDGE_WINDOW", 1, 1},
    {"rp-next-ptr-unaligned", a_rp_next_unaligned, "NONE", 1, 1},
    {"ep-two-pm", a_ep_two_pm, "NONE", 1, 1},
    {"rp-mem-off", a_rp_mem_off, "BRIDGE_MEMORY_OFF", 1, 1},
    {"rp-type-endpoint", a_rp_type_endpoint, "LINK_UNPROVEN", 1, 1},
    {"rp-type-legacy-endpoint", a_rp_type_legacy, "LINK_UNPROVEN", 1, 1},
    {"rp-type-pcie-pci-bridge", a_rp_type_pcie_pci_bridge, "LINK_UNPROVEN", 1, 1},
    {"rp-type-downstream", a_rp_type_downstream, "NONE", 1, 1},
    {"ep-type-integrated", a_ep_type_integrated, "NONE", 1, 1},
    {"ep-type-legacy", a_ep_type_legacy, "NONE", 1, 1},
    {"ep-type-root-port", a_ep_type_root_port, "NONE", 1, 1},
    {"ep-pcie-first", a_ep_pcie_first, "NONE", 1, 1},
    {"ep-pcie-first-pmcsr-fault", a_ep_pcie_first_pmcsr_fault, "CAPS_NOT_READ", 1, 1},
    {"ep-pcie-first-link-fault", a_ep_pcie_first_link_fault, "CAPS_NOT_READ", 1, 1},
};
#define GATE_SCENS (sizeof gate_scens / sizeof gate_scens[0])

/* What a scenario's page must also hold: a line that starts with `label` has the entry `token`. */
static const struct { const char *scenario, *label, *token; } scen_tokens[] = {
    {"good", P "GATE", "RPMEM=1"}, {"good", P "RP.LINK", "TYPE=4"}, {"good", P "EP.LINK", "TYPE=0"}, {"good", P "RP.LINK", "DLLA=1"},
    {"rp-link-training", P "RP.LINK", "LT=1"}, {"rp-link-training-down", P "RP.LINK", "LT=1"}, {"ep-d1", P "EP.PM", "D=1"},
    {"ep-d2", P "EP.PM", "D=2"}, {"ep-d3", P "EP.PM", "D=3"}, {"rp-link-gen6-x32", P "RP.LINK", "LINK=GEN6.X32"},
    {"rp-link-aspm-is-two-bits", P "RP.LINK", "ASPM=3"}, {"rp-link-speed-7-x63", P "RP.LINK", "LINK=SPEED7.X63"},
    {"rp-link-down", P "RP.LINK", "ODD"}, {"rp-link-down", P "RP.LINK", "DLLA=0"}, {"rp-link-training", P "RP.LINK", "ODD"},
    {"rp-link-training-down", P "RP.LINK", "ODD"}, {"rp-mem-off", P "GATE", "RPMEM=0"},
    {"rp-type-endpoint", P "RP.LINK", "TYPE=0"}, {"rp-type-endpoint", P "RP.LINK", "ODD"}, {"rp-type-legacy-endpoint", P "RP.LINK", "TYPE=1"},
    {"rp-type-legacy-endpoint", P "RP.LINK", "ODD"}, {"rp-type-pcie-pci-bridge", P "RP.LINK", "TYPE=7"}, {"rp-type-pcie-pci-bridge", P "RP.LINK", "ODD"},
    {"rp-type-downstream", P "RP.LINK", "TYPE=6"}, {"ep-type-integrated", P "EP.LINK", "TYPE=9"}, {"ep-type-integrated", P "EP.LINK", "ODD"},
    {"ep-type-legacy", P "EP.LINK", "TYPE=1"}, {"ep-type-root-port", P "EP.LINK", "TYPE=4"}, {"ep-type-root-port", P "EP.LINK", "ODD"},
    {"ep-two-pm", P "EP.PM", "D=0"}, {"ep-pcie-first", P "EP.PM", "D=0"}, {"ep-pcie-first", P "EP.LINK", "TYPE=0"},
};

/* What a scenario's page must not hold: a decode that does not hold is marked ODD, and one that does is not; the data link layer bits are not
 * shown for a function that does not report them. */
static const struct { const char *scenario, *label, *token; } scen_absent[] = {
    {"good", P "RP.LINK", "ODD"}, {"good", P "EP.LINK", "ODD"}, {"good", P "EP.LINK", "DLLA"}, {"rp-type-downstream", P "RP.LINK", "ODD"},
    {"ep-type-legacy", P "EP.LINK", "ODD"}, {"rp-link-unreported", P "RP.LINK", "DLLA"}, {"rp-link-unreported", P "RP.LINK", "LT"},
    {"rp-link-gen6-x32", P "RP.LINK", "ODD"}, {"rp-link-speed-7-x63", P "RP.LINK", "ODD"},
};

/* One scenario: the good world, the change, the run; what must have happened. `extra` descriptors are added to the standard memory map. */
static int run_scenario(const struct scen *s, const struct d *extra, unsigned nextra)
{
    struct d list[STD_COUNT + 4];
    struct world w;
    char token[64];
    int closed = strcmp(s->why, "NONE") != 0;
    memcpy(list, std_map, sizeof std_map);
    for (unsigned i = 0; i < nextra; i++) list[STD_COUNT + i] = extra[i];
    world_new(&w, list, STD_COUNT + nextra);
    put_rp();
    put_ep();
    put_nvme(BAR_GOOD, &good_nv);
    put_queues(ASQ_GOOD, ACQ_GOOD);
    allow_ram(ASQ_GOOD, ASQ_GOOD + 128);
    allow_ram(ACQ_GOOD, ACQ_GOOD + 32);
    s->apply(&w);
    if (closed) {
        nv_allowed = 0;
        ram_ok_n = 0;
    }
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    snprintf(token, sizeof token, "WHY=%s", s->why);
    if (!has_token(P "VERDICT", token, 1)) fprintf(stderr, "scenario %s: wanted %s\n", s->name, token);
    CHECK_TOKEN(P "VERDICT", token);
    CHECK_EQ(find_line(P "NEXT CAPS") >= 0, s->caps);
    CHECK_EQ(find_line(P "GATE") >= 0, s->gate);
    if (s->gate) CHECK_TOKEN(P "GATE", token);
    for (unsigned i = 0; i < sizeof scen_tokens / sizeof scen_tokens[0]; i++) {
        if (strcmp(scen_tokens[i].scenario, s->name)) continue;
        if (!has_token(scen_tokens[i].label, scen_tokens[i].token, 1))
            fprintf(stderr, "scenario %s: no %s on a '%s' line\n", s->name, scen_tokens[i].token, scen_tokens[i].label);
        CHECK_TOKEN(scen_tokens[i].label, scen_tokens[i].token);
    }
    for (unsigned i = 0; i < sizeof scen_absent / sizeof scen_absent[0]; i++) {
        if (strcmp(scen_absent[i].scenario, s->name)) continue;
        if (has_token(scen_absent[i].label, scen_absent[i].token, 0))
            fprintf(stderr, "scenario %s: a %s on a '%s' line\n", s->name, scen_absent[i].token, scen_absent[i].label);
        CHECK_NO_TOKEN(scen_absent[i].label, scen_absent[i].token);
    }
    CHECK(find_line(P "DONE") >= 0);
    if (closed) {
        CHECK_NO_LINE(P "NEXT NVME_REGS");
        CHECK_NO_LINE(P "NVME ");
        CHECK_NO_LINE(P "NEXT NVME_AQ");
        CHECK_NO_LINE(P "NVME.AQ ");
        CHECK_NO_LINE(P "NEXT ADMIN_QUEUES");
        CHECK_TOKEN(P "DONE", "NVME_GROUP_SKIPPED");
        CHECK_TOKEN(P "DONE", "NVME_TRIED=0");
        CHECK_NO_TOKEN(P "VERDICT", "CTRL=RUNNING");
    } else {
        CHECK_LINE(P "NEXT NVME_REGS AFTER 8 S");
        CHECK_LINE(P "NEXT NVME_AQ AFTER 8 S");
        CHECK_TOKEN(P "DONE", "NVME_GROUP_RAN");
    }
    world_free(&w);
    return 0;
}
