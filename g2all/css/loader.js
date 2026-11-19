//#region Contants
const PF_X = 1;
const PF_W = 2;
const PF_R = 4;

const PROT_READ = 1;
const PROT_WRITE = 2;
const PROT_EXEC = 4;

const ET_DYN = 3;
const ET_EXEC = 2;

const MAP_SHARED = 1;
const MAP_PRIVATE = 2;
const MAP_FIXED = 0x10;
const MAP_ANONYMOUS = 0x1000;

const PT_LOAD = 1;
const SHT_RELA = 4;
const MADV_DONTNEED = 5;
const R_X86_64_RELATIVE = 8;

fn.pthread_create = new NativeFunction(webkit_base.add(constants.wk_pthread_create), "number");

fn.munmap = new NativeFunction(0x49, "number");
fn.mprotect = new NativeFunction(0x4A, "number");
fn.madvise = new NativeFunction(0x4B, "number");
fn.mmap = new NativeFunction(0x1DD, "bint");
fn.jitshm_create = new NativeFunction(0x215, "number");
fn.mname = new NativeFunction(0x24C, "number");
fn.kexec = new NativeFunction(0x295, "number");
//#endregion Constants
//#region Functions
function load_bin(data, exit) {
  const sz = data.length.alignUp(PAGE_SIZE);
  const prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  const flags = MAP_PRIVATE | MAP_ANONYMOUS;

  const entry_addr = fn.mmap.invoke(0, sz, prot, flags, -1, 0);
  logger.debug(`entry_addr: ${entry_addr}`);
  if (entry_addr.eq(-1)) {
    throw new SyscallError(`Unable to map memory with size ${sz} !!`);
  }

  mem.copy(entry_addr, data.buffer.data(), data.length);

  const pthread_addr_addr = mem.alloc(8);

  if (fn.pthread_create.invoke(pthread_addr_addr, 0, entry_addr, 0)) {
    throw new Error(`Unable to create bin thread !!`);
  }

  const pthread_addr = arw.view(pthread_addr_addr).getBInt(0, true);
  const pthread_id = arw.view(pthread_addr).getBInt(0, true);

  logger.info(`Created bin thread with id ${pthread_id} !!`);

  mem.free(pthread_addr_addr);

  if (exit) {
    fn.kill = new NativeFunction(0x25, "bigint");

    const pid = fn.getpid.invoke();

    fn.kill.invoke(pid, 9);
  }
}
//#endregion