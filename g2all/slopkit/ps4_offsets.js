export const REQUIRED_KEYS = [
  "fw_status",
  "wk_expm1_builtin",
  "wk_JSFunction_m_function",
  "wk_POP_RDI_RET",
  "wk_POP_RSI_RET",
  "wk_POP_RDX_RET",
  "wk_POP_RCX_RET",
  "wk_POP_RAX_RET",
  "wk_POP_R8_RET",
  "wk_POP_R9_RET",
  "wk_LEAVE_RET",
  "wk_MOV_QWORD_PTR_RDI_RAX_RET",
  "wk_MOV_RDI_RSI_30_CALL",
  "wk_POP_RAX_MOV_RAX_JMP_18",
  "wk_PUSH_RBP_MOV_RBP_RSP_10",
  "wk_MOV_RDI_RAX_8_CALL_20",
  "wk_MOV_RDX_RAX_18_CALL_10",
  "wk_PUSH_RDX_POP_RSP_RET",
  "pivot_view_sp",
  "wk_ArrayBuffer_m_impl",
  "wk_ArrayBuffer_m_contents_m_data",
  "wk___imp___error",
  "k__error",
  "k_scan_stage1",
  "k_scan_stage2",
  "k_evf_cv",
  "k_sysent_661",
  "k_jmp_rsi",
];
export const OPTIONAL_KEYS = [
  "k_stubs",
  "wk___imp_pthread_create",
  "k_pthread_create",
  "kpatch",
  "alias_of",
  "k_idt_rsvd",
];

export const PS4 = {
  "11.00": {
    fw_status: "state=proven step4q=90/0 reboot=0 kernel_rvas=5/5-vs-dump",

    k_idt_rsvd: 0x2d2430,

    wk_expm1_builtin: 0x2193f30,

    wk_JSFunction_m_function: 0x28,

    wk_CSSFontFace_vtable: 0x3627aa8,

    wk___imp___error: 0x36e1c68,
    k__error: 0x3370,
    wk___imp_strerror: 0x36e1c98,
    c_strerror: 0x10d00,

    wk_POP_RDI_RET: 0x357a0,
    wk_POP_RAX_RET: 0x4e6a9,

    wk_MOV_RDI_RSI_30_CALL: 0x24dae58,

    wk_POP_RAX_MOV_RAX_JMP_18: 0x11d5d53,

    wk_PUSH_RBP_MOV_RBP_RSP_10: 0x2f1890,

    wk_MOV_RDI_RAX_8_CALL_20: 0x41a81,

    wk_MOV_RDX_RAX_18_CALL_10: 0x90ffe6,

    wk_PUSH_RDX_POP_RSP_RET: 0x1cc607a,

    wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x97db,
    wk_LEAVE_RET: 0x31f9d,

    wk_POP_RSI_RET: 0x249e2,
    wk_POP_RDX_RET: 0x10d11,
    wk_POP_RCX_RET: 0x71617,

    wk_POP_R8_RET: 0xe53a2,
    wk_POP_R9_RET: 0x6403a1,

    pivot_view_sp: 0x18,

    wk_ArrayBuffer_m_impl: 0x10,

    wk_ArrayBuffer_m_contents_m_data: 0x10,

    k_getpid: 0x1b280,

    k_scan_stage1: 0x40000,
    k_scan_stage2: 0x60000,

    k_evf_cv: 0x7fc26f,
    k_sysent_661: 0x1109350,
    k_jmp_rsi: 0x71a21,
  },

  "11.50": {
    fw_status:
      "state=proven step4q=90/0 reboot=0 webkit=step7-20/20-x2 " +
      "kernel_rvas=untested-vs-dump kstr_residue=0x318",

    wk_expm1_builtin: 0x2587bd0,
    wk_JSFunction_m_function: 0x28,

    wk_POP_RDI_RET: 0x2445241,
    wk_POP_RSI_RET: 0x2503c9e,
    wk_POP_RDX_RET: 0x24cfa22,
    wk_POP_RCX_RET: 0x24c7ebf,
    wk_POP_RAX_RET: 0x2554e3f,
    wk_POP_R8_RET: 0x23bb4bd,
    wk_POP_R9_RET: 0x1c2cda1,
    wk_LEAVE_RET: 0x23c3790,
    wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x2445d1a,

    wk_MOV_RDI_RSI_30_CALL: 0x29609f8,
    wk_POP_RAX_MOV_RAX_JMP_18: 0x1c8bbc3,
    wk_PUSH_RBP_MOV_RBP_RSP_10: 0x1645270,
    wk_MOV_RDI_RAX_8_CALL_20: 0x1e3f795,
    wk_MOV_RDX_RAX_18_CALL_10: 0x1dea16a,
    wk_PUSH_RDX_POP_RSP_RET: 0x2abe00a,

    pivot_view_sp: 0x38,
    wk_ArrayBuffer_m_impl: 0x10,
    wk_ArrayBuffer_m_contents_m_data: 0x10,

    wk___imp___error: 0x3cbcc98,
    k__error: 0x183c0,

    wk___imp_pthread_create: 0x3cbdbb8,
    k_pthread_create: 0xa1d0,

    k_stubs: {
      3: 0x2c170,
      4: 0x2b8d0,
      5: 0x2b970,
      6: 0x2d620,
      20: 0x2cb70,
      23: 0x2b6f0,
      24: 0x2d5e0,
      25: 0x2b4d0,
      30: 0x2c9d0,
      54: 0x2cff0,
      92: 0x2b650,
      97: 0x2d050,
      98: 0x2b5f0,
      104: 0x2d380,
      105: 0x2b490,
      106: 0x2d480,
      118: 0x2b2f0,
      135: 0x2c280,
      240: 0x2d4c0,
      331: 0x2c6b0,
      432: 0x2b510,
      466: 0x2cc70,
      487: 0x2ba80,
      488: 0x2bd10,
      538: 0x2b430,
      539: 0x2b4f0,
      544: 0x2beb0,
      545: 0x2ca30,
      632: 0x2d090,
      633: 0x2d840,
      662: 0x2ccb0,
      663: 0x2c3e0,
      664: 0x2d740,
      666: 0x2d540,
      669: 0x2bdf0,
    },
    k_scan_stage1: 0x40000,
    k_scan_stage2: 0x60000,

    k_evf_cv: 0x784318,
    k_sysent_661: 0x110a760,
    k_jmp_rsi: 0x704d5,
  },
  "12.00": {
    fw_status:
      "state=UNTESTED-on-hardware webkit=offline-from-sprx " +
      "anchor=findcaller-validated-on-11.50 " +
      "kernel_rvas=verified-vs-kernel_1202.elf kpatch=10/10-sites-verified",

    k_idt_rsvd: 0x1c1d00,

    wk_expm1_builtin: 0x2585090,
    wk_JSFunction_m_function: 0x28,

    wk_POP_RDI_RET: 0x4902f,
    wk_POP_RSI_RET: 0x10e37,
    wk_POP_RDX_RET: 0xf7a,
    wk_POP_RCX_RET: 0x53c0b,
    wk_POP_RAX_RET: 0x22f53,
    wk_POP_R8_RET: 0x22f52,
    wk_POP_R9_RET: 0x60b6c1,
    wk_LEAVE_RET: 0x11823,
    wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x2b5cb,
    wk_PUSH_RDX_POP_RSP_RET: 0x2abb03a,
    wk_MOV_RDI_RSI_30_CALL: 0x295dcd8,
    wk_POP_RAX_MOV_RAX_JMP_18: 0x8e4873,
    wk_PUSH_RBP_MOV_RBP_RSP_10: 0x285e10,
    wk_MOV_RDI_RAX_8_CALL_20: 0x6c7b0d,
    wk_MOV_RDX_RAX_18_CALL_10: 0xd37cca,

    pivot_view_sp: 0x38,
    wk_ArrayBuffer_m_impl: 0x10,
    wk_ArrayBuffer_m_contents_m_data: 0x10,

    wk___imp___error: 0x3cbcc48,
    k__error: 0x299c0,
    wk___imp_pthread_create: 0x3cbdb80,
    k_pthread_create: 0x24e00,

    k_stubs: {
      3: 0x2c160,
      4: 0x2b8c0,
      5: 0x2b960,
      6: 0x2d610,
      20: 0x2cb60,
      23: 0x2b6e0,
      24: 0x2d5d0,
      25: 0x2b4c0,
      30: 0x2c9c0,
      54: 0x2cfe0,
      92: 0x2b640,
      97: 0x2d040,
      98: 0x2b5e0,
      104: 0x2d370,
      105: 0x2b480,
      106: 0x2d470,
      118: 0x2b2e0,
      135: 0x2c270,
      240: 0x2d4b0,
      331: 0x2c6a0,
      432: 0x2b500,
      466: 0x2cc60,
      487: 0x2ba70,
      488: 0x2bd00,
      538: 0x2b420,
      539: 0x2b4e0,
      544: 0x2bea0,
      545: 0x2ca20,
      632: 0x2d080,
      633: 0x2d830,
      662: 0x2cca0,
      663: 0x2c3d0,
      664: 0x2d730,
      666: 0x2d530,
      669: 0x2bde0,
    },
    k_scan_stage1: 0x40000,
    k_scan_stage2: 0x60000,

    k_evf_cv: 0x784798,
    k_sysent_661: 0x110a760,
    k_jmp_rsi: 0x47b31,
  },
  "13.00": {
    fw_status:
      "state=proven step10=32/0-x3 reboot=0 webkit=step7-20/20 anchor=findcaller kernel_rvas=verified-on-hardware kpatch=1300.bin-10-sites-verified bug=poops",

    k_idt_rsvd: 0x1c1d40,

    wk_expm1_builtin: 0x2586880,
    wk_JSFunction_m_function: 0x28,

    wk_POP_RDI_RET: 0x5c480,
    wk_POP_RSI_RET: 0x6e45e,
    wk_POP_RDX_RET: 0x12c5ba,
    wk_POP_RCX_RET: 0x1bade,
    wk_POP_RAX_RET: 0x10504,
    wk_POP_R8_RET: 0x9b311,
    wk_POP_R9_RET: 0x1dcfb1,
    wk_LEAVE_RET: 0x182f7,
    wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x548b,
    wk_PUSH_RDX_POP_RSP_RET: 0x2abccaa,
    wk_MOV_RDI_RSI_30_CALL: 0x295f948,
    wk_POP_RAX_MOV_RAX_JMP_18: 0x1d989e3,
    wk_PUSH_RBP_MOV_RBP_RSP_10: 0x25bae0,
    wk_MOV_RDI_RAX_8_CALL_20: 0x4a0406,
    wk_MOV_RDX_RAX_18_CALL_10: 0x1ec3ada,

    pivot_view_sp: 0x38,
    wk_ArrayBuffer_m_impl: 0x10,
    wk_ArrayBuffer_m_contents_m_data: 0x10,

    wk___imp___error: 0x3cb8cc8,
    k__error: 0x26420,
    wk___imp_pthread_create: 0x3cb9c00,
    k_pthread_create: 0x10110,

    k_stubs: {
      3: 0x2c170,
      4: 0x2b8d0,
      5: 0x2b970,
      6: 0x2d620,
      20: 0x2cb70,
      23: 0x2b6f0,
      24: 0x2d5e0,
      25: 0x2b4d0,
      30: 0x2c9d0,
      54: 0x2cff0,
      92: 0x2b650,
      97: 0x2d050,
      98: 0x2b5f0,
      104: 0x2d380,
      105: 0x2b490,
      106: 0x2d480,
      118: 0x2b2f0,
      135: 0x2c280,
      240: 0x2d4c0,
      331: 0x2c6b0,
      432: 0x2b510,
      466: 0x2cc70,
      487: 0x2ba80,
      488: 0x2bd10,
      538: 0x2b430,
      539: 0x2b4f0,
      544: 0x2beb0,
      545: 0x2ca30,
      632: 0x2d090,
      633: 0x2d840,
      662: 0x2ccb0,
      663: 0x2c3e0,
      664: 0x2d740,
      666: 0x2d540,
      669: 0x2bdf0,
    },
    k_scan_stage1: 0x40000,
    k_scan_stage2: 0x60000,

    k_kl_lock: 0xe6c20,

    k_evf_cv: 0x0,
    k_sysent_661: 0x110a760,
    k_jmp_rsi: 0x47b31,

    k_oid_kern_file: 0x1a2f8a0,
    k_oid_maxfilesperproc: 0x1a2f950,
    k_oid_maxprocperuid: 0x1a3ba88,
    k_oid_maxfiles: 0x1a2f9a8,
    k_arg1_maxfilesperproc: 0x22cc47c,
    k_arg1_maxprocperuid: 0x22cc478,
    k_arg1_maxfiles: 0x22cc474,
    k_sysctl_handle_int: 0x3fa090,
    k_prison0: 0x1a5c0c0,
    k_rootvnode: 0x2136e90,
    k_sysent: 0x1102b70,
  },
  "12.50": {
    fw_status:
      "state=UNTESTED-on-hardware " +
      "webkit=addfw-from-decrypted-12.50-modules (15/15 gadgets, 35/35 stubs) " +
      "anchor=findcaller-offline (self-check reproduces the known 11.50 and " +
      "12.00 anchors) " +
      "kernel_rvas=asserted-by-supplied-table STILL-UNVERIFIED (no 12.50 kernel " +
      "dump) but CORROBORATED: all three byte-verified in the 13.00 hardware dump " +
      "AND in kernel_1202.elf at the identical RVAs, and 12.02<->13.00 share their " +
      "first megabyte 96.7% at ZERO shift (11.00<->12.02 is 3.7%), so 12.50/12.52 " +
      "sit between two builds whose low text does not move " +
      "kpatch=1250.bin bug=poops",

    wk_expm1_builtin: 0x2585110,
    wk_JSFunction_m_function: 0x28,

    wk_POP_RDI_RET: 0x4902f,
    wk_POP_RSI_RET: 0x10e37,
    wk_POP_RDX_RET: 0x771ea,
    wk_POP_RCX_RET: 0x5def9,
    wk_POP_RAX_RET: 0x22f53,
    wk_POP_R8_RET: 0x22f52,
    wk_POP_R9_RET: 0x60b6c1,
    wk_LEAVE_RET: 0x77caa,
    wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x2b5cb,
    wk_PUSH_RDX_POP_RSP_RET: 0x2abb0ba,
    wk_MOV_RDI_RSI_30_CALL: 0x295dd58,
    wk_POP_RAX_MOV_RAX_JMP_18: 0x8e4873,
    wk_PUSH_RBP_MOV_RBP_RSP_10: 0x285e10,
    wk_MOV_RDI_RAX_8_CALL_20: 0x6c7b0d,
    wk_MOV_RDX_RAX_18_CALL_10: 0xd37cca,

    pivot_view_sp: 0x38,
    wk_ArrayBuffer_m_impl: 0x10,
    wk_ArrayBuffer_m_contents_m_data: 0x10,

    wk___imp___error: 0x3cb4c48,
    k__error: 0xd9d0,
    wk___imp_pthread_create: 0x3cb5b80,
    k_pthread_create: 0x23d20,

    k_stubs: {
      3: 0x2c160,
      4: 0x2b8c0,
      5: 0x2b960,
      6: 0x2d610,
      20: 0x2cb60,
      23: 0x2b6e0,
      24: 0x2d5d0,
      25: 0x2b4c0,
      30: 0x2c9c0,
      54: 0x2cfe0,
      92: 0x2b640,
      97: 0x2d040,
      98: 0x2b5e0,
      104: 0x2d370,
      105: 0x2b480,
      106: 0x2d470,
      118: 0x2b2e0,
      135: 0x2c270,
      240: 0x2d4b0,
      331: 0x2c6a0,
      432: 0x2b500,
      466: 0x2cc60,
      487: 0x2ba70,
      488: 0x2bd00,
      538: 0x2b420,
      539: 0x2b4e0,
      544: 0x2bea0,
      545: 0x2ca20,
      632: 0x2d080,
      633: 0x2d830,
      662: 0x2cca0,
      663: 0x2c3d0,
      664: 0x2d730,
      666: 0x2d530,
      669: 0x2bde0,
    },
    k_scan_stage1: 0x40000,
    k_scan_stage2: 0x60000,

    k_evf_cv: 0x0,
    k_sysent_661: 0x110a760,
    k_jmp_rsi: 0x47b31,
    k_kl_lock: 0xe6c20,
  },
};

PS4["13.50"] = {
  fw_status:
    "state=663-JB-PROVEN-on-hw webkit=13.00-module libkernel=13.50-stubs " +
    "kernel_rvas=MEASURED-from-kernel_1350.elf (kderive 16/16, adversarial 16/16 GO) " +
    "kpatch=1350.bin-BUILT-10/10-neg-controls-pass-UNTESTED-on-hw bug=663",

  wk_expm1_builtin: 0x2586880,
  wk_JSFunction_m_function: 0x28,

  wk_POP_RDI_RET: 0x5c480,
  wk_POP_RSI_RET: 0x6e45e,
  wk_POP_RDX_RET: 0x12c5ba,
  wk_POP_RCX_RET: 0x1bade,
  wk_POP_RAX_RET: 0x10504,
  wk_POP_R8_RET: 0x9b311,
  wk_POP_R9_RET: 0x1dcfb1,
  wk_LEAVE_RET: 0x182f7,
  wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x548b,
  wk_PUSH_RDX_POP_RSP_RET: 0x2abccaa,
  wk_MOV_RDI_RSI_30_CALL: 0x295f948,
  wk_POP_RAX_MOV_RAX_JMP_18: 0x1d989e3,
  wk_PUSH_RBP_MOV_RBP_RSP_10: 0x25bae0,
  wk_MOV_RDI_RAX_8_CALL_20: 0x4a0406,
  wk_MOV_RDX_RAX_18_CALL_10: 0x1ec3ada,

  pivot_view_sp: 0x38,
  wk_ArrayBuffer_m_impl: 0x10,
  wk_ArrayBuffer_m_contents_m_data: 0x10,

  wk___imp___error: 0x3cb8cc8,
  k__error: 0x1a0f0,
  wk___imp_pthread_create: 0x3cb9c00,
  k_pthread_create: 0x21790,

  k_stubs: {
    3: 0x2c170,
    4: 0x2b8d0,
    5: 0x2b970,
    6: 0x2d620,
    20: 0x2cb70,
    23: 0x2b6f0,
    24: 0x2d5e0,
    25: 0x2b4d0,
    30: 0x2c9d0,
    54: 0x2cff0,
    92: 0x2b650,
    97: 0x2d050,
    98: 0x2b5f0,
    104: 0x2d380,
    105: 0x2b490,
    106: 0x2d480,
    118: 0x2b2f0,
    135: 0x2c280,
    240: 0x2d4c0,
    331: 0x2c6b0,
    432: 0x2b510,
    466: 0x2cc70,
    487: 0x2ba80,
    488: 0x2bd10,
    538: 0x2b430,
    539: 0x2b4f0,
    544: 0x2beb0,
    545: 0x2ca30,
    632: 0x2d090,
    633: 0x2d840,
    662: 0x2ccb0,
    663: 0x2c3e0,
    664: 0x2d740,
    666: 0x2d540,
    669: 0x2bdf0,
  },
  k_scan_stage1: 0x40000,
  k_scan_stage2: 0x60000,

  k_idt_rsvd: 0x1c1d60,
  k_sysctl_handle_int: 0x3fa4e0,
  k_jmp_rsi: 0x47b31,
  k_kl_lock: 0xe6c20,
  k_evf_cv: 0x784e18,
  k_sysent: 0x1102b70,
  k_sysent_661: 0x110a760,
  k_oid_kern_file: 0x1a2f8a0,
  k_oid_maxfilesperproc: 0x1a2f950,
  k_oid_maxprocperuid: 0x1a3ba88,
  k_oid_maxfiles: 0x1a2f9a8,
  k_arg1_maxfilesperproc: 0x22cc47c,
  k_arg1_maxprocperuid: 0x22cc478,
  k_arg1_maxfiles: 0x22cc474,
  k_prison0: 0x1a5c0c0,
  k_rootvnode: 0x2136e90,
  kpatch: "1350.bin",
};

PS4["13.52"] = Object.assign({}, PS4["13.50"], {
  alias_of: "13.50",

  k_idt_rsvd: 0x1c1e00,

  k_oid_kern_file: 0x1a2f8a0,
  k_oid_maxfilesperproc: 0x1a2f950,
  k_oid_maxprocperuid: 0x1a3ba88,
  k_oid_maxfiles: 0x1a2f9a8,
  k_arg1_maxfilesperproc: 0x22cc47c,
  k_arg1_maxprocperuid: 0x22cc478,
  k_arg1_maxfiles: 0x22cc474,
  k_sysctl_handle_int: 0x3fa8e0,
  k_prison0: 0x1a5c0c0,
  k_rootvnode: 0x2136e90,
  k_sysent: 0x1102b70,
  k_sysent_661: 0x110a760,
  k_jmp_rsi: 0x4d6d0,

  k_kl_lock: 0xe6c60,
  k_evf_cv: 0x785228,

  kpatch: "1352.bin",

  fw_status:
    "state=663-LIVE-on-hardware shares=13.50 (webkit+libkernel) " +
    "kernel_rvas=MEASURED-from-kernel_1352.elf (kdump5 tier1 36MB pass=39/0, " +
    "kderive 16/16 recipes) kpatch=1352.bin-24-sites-verified-OFFLINE-ONLY " +
    "bug=663",
});

PS4["13.02"] = Object.assign({}, PS4["13.00"], {
  alias_of: "13.00",

  k_idt_rsvd: 0x1c1d50,
  k_sysctl_handle_int: 0x3fa0a0,
  k_jmp_rsi: 0x47b31,
  k_kl_lock: 0xe6c20,
  k_evf_cv: 0x7849d8,
  k_sysent: 0x1102b70,
  k_sysent_661: 0x110a760,
  k_oid_kern_file: 0x1a2f8a0,
  k_oid_maxfilesperproc: 0x1a2f950,
  k_oid_maxprocperuid: 0x1a3ba88,
  k_oid_maxfiles: 0x1a2f9a8,
  k_arg1_maxfilesperproc: 0x22cc47c,
  k_arg1_maxprocperuid: 0x22cc478,
  k_arg1_maxfiles: 0x22cc474,
  k_prison0: 0x1a5c0c0,
  k_rootvnode: 0x2136e90,
  kpatch: "1302.bin",
  fw_status:
    "state=663-JB+KPATCH-PROVEN-on-hw-pass=51 shares=13.00 (webkit+libkernel, PRIMITIVE-OK) " +
    "kernel_rvas=MEASURED-from-kernel_1302.elf (16/16 GO) same-kernel-as=13.04 " +
    "kpatch=1302.bin-HW-PROVEN-KEXEC-rc0 bug=663",
});

PS4["13.04"] = Object.assign({}, PS4["13.00"], {
  alias_of: "13.00",

  k_idt_rsvd: 0x1c1d50,
  k_sysctl_handle_int: 0x3fa0a0,
  k_jmp_rsi: 0x47b31,
  k_kl_lock: 0xe6c20,
  k_evf_cv: 0x7849d8,
  k_sysent: 0x1102b70,
  k_sysent_661: 0x110a760,
  k_oid_kern_file: 0x1a2f8a0,
  k_oid_maxfilesperproc: 0x1a2f950,
  k_oid_maxprocperuid: 0x1a3ba88,
  k_oid_maxfiles: 0x1a2f9a8,
  k_arg1_maxfilesperproc: 0x22cc47c,
  k_arg1_maxprocperuid: 0x22cc478,
  k_arg1_maxfiles: 0x22cc474,
  k_prison0: 0x1a5c0c0,
  k_rootvnode: 0x2136e90,
  kpatch: "1302.bin",
  fw_status:
    "state=663-JB+KPATCH-via-13.02(pass=51) shares=13.00 (webkit+libkernel, PRIMITIVE-OK) " +
    "kernel_rvas=SAME-KERNEL-AS-13.02 (measured from kernel_1302.elf, 16/16 GO) " +
    "kpatch=1302.bin-shared-HW-PROVEN bug=663",
});

PS4["12.02"] = Object.assign({}, PS4["12.00"], {
  alias_of: "12.00",
  fw_status:
    "state=UNTESTED-on-hardware shares=12.00 " +
    "kernel_rvas=verified-vs-kernel_1202.elf (this firmware) " +
    "kpatch=1200.bin-10-sites-verified bug=lapse",
  kpatch: "1200.bin",
});

PS4["12.52"] = Object.assign({}, PS4["12.50"], {
  alias_of: "12.50",
  fw_status:
    "state=UNTESTED-on-hardware shares=12.50 " +
    "webkit=assumed-identical-to-12.50 (no 12.52 module dump) " +
    "kernel_rvas=STILL-UNVERIFIED but corroborated via 12.02+13.00 dumps " +
    "kpatch=1250.bin bug=poops",
  kpatch: "1250.bin",
});

PS4["11.52"] = Object.assign({}, PS4["11.50"], {
  alias_of: "11.50",
  fw_status:
    "state=UNTESTED-on-hardware shares=11.50 " +
    "webkit=assumed-identical-to-11.50 " +
    "kernel_rvas=untested-vs-dump " +
    "kpatch=1150.bin",
  kpatch: "1150.bin",
});

export function offsetsFor(uaString) {
  const m = (uaString || "").match(/PlayStation\s+4[\/ ](\d+)\.(\d+)/);
  if (!m) return { key: null, off: null };

  const key = m[1] + "." + parseInt(m[2], 16).toString(16).padStart(2, "0");
  return { key, off: PS4[key] || null };
}