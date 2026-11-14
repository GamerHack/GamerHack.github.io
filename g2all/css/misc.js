//#region Constants
const logger = {
  seq: 0,
  verbose: true,
  console: undefined,

  info(msg) {
    this.log("[+] " + msg);
  },
  error(msg) {
    this.log("[-] " + msg);
  },
  debug(msg) {
    if (this.verbose) {
      this.log("[*] " + msg);
    }
  },
  log(msg) {
    if (is_worker()) {
      self.postMessage({ type: "log", value: "[" + self.name + "]" + msg });
      return;
    }

    if (this.console === undefined) {
      var el = document.getElementById("console");
      if (!el) {
        el = document.createElement("pre");
        el.id = "console";
        el.setAttribute(
          "style",
          "position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;" +
            "overflow:hidden;opacity:0;pointer-events:none;"
        );
        document.body.appendChild(el);
      }
      this.console = el;
    }

    try {
      this.console.append(msg + "\n");
      this.console.scrollTop = this.console.scrollHeight;
    } catch (e) {}

    this.seq++;
  },
};

const version = {
  console: undefined,
  major: undefined,
  minor: undefined,
  init() {
    const ua = navigator.userAgent;

    const matches = ua.match(/PlayStation\s+(\d+)[/ ](\d+)\.(\d+)/);
    if (matches === null) {
      throw new Error(ua + " not supported !!");
    }

    this.console = parseInt(matches[1], 10);
    this.major = parseInt(matches[2], 10);
    this.minor = parseInt(matches[3], 16);
  },
  toString() {
    return this.major + "." + this.minor.toString(16).padStart(2, "0");
  },
};
//#endregion
//#region Classes
class BInt {
  /** @param  {[number, number]|number|string|BInt|ArrayLike<number>} */
  constructor() {
    let lo = 0;
    let hi = 0;

    switch (arguments.length) {
      case 0:
        break;
      case 1:
        let value = arguments[0];
        switch (typeof value) {
          case "boolean":
            lo = value ? 1 : 0;
            break;
          case "number":
            if (Number.isNaN(value)) {
              throw new TypeError("Number " + value + " is NaN");
            }

            if (Number.isInteger(value)) {
              if (!Number.isSafeInteger(value)) {
                throw new RangeError("Integer " + value + " outside safe 53-bit range");
              }

              lo = value >>> 0;
              hi = Math.floor(value / 0x100000000) >>> 0;
            } else {
              BInt.View.setFloat64(0, value, true);

              lo = BInt.View.getUint32(0, true);
              hi = BInt.View.getUint32(4, true);
            }

            break;
          case "string":
            if (value.startsWith("0x")) {
              value = value.slice(2);
            }

            if (value.length > 0x10) {
              throw new RangeError("String " + value + " is out of range !!");
            }

            value = value.padStart(16, "0");

            for (let i = 0; i < 8; i++) {
              const start = value.length - 2 * (i + 1);
              const end = value.length - 2 * i;
              const b = value.slice(start, end);
              BInt.View.setUint8(i, parseInt(b, 16));
            }

            lo = BInt.View.getUint32(0, true);
            hi = BInt.View.getUint32(4, true);

            break;
          case "object":
            if (value !== null) {
              if (Number.isInteger(value.lo) && Number.isInteger(value.hi)) {
                lo = value.lo;
                hi = value.hi;
                break;
              } else if (ArrayBuffer.isView(value) && value.byteLength === BInt.View.byteLength) {
                new Uint8Array(BInt.View.buffer).set(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));

                lo = BInt.View.getUint32(0, true);
                hi = BInt.View.getUint32(4, true);
                break;
              }
            }

          default:
            throw new TypeError("Unsupported value " + value + " !!");
        }
        break;
      case 2:
        hi = arguments[0];
        lo = arguments[1];

        if (!Number.isInteger(hi)) {
          throw new RangeError("hi value " + hi + " is not an integer !!");
        }

        if (!Number.isInteger(lo)) {
          throw new RangeError("lo value " + lo + " is not an integer !!");
        }

        hi >>>= 0;
        lo >>>= 0;

        break;
      default:
        throw new TypeError("Unsupported input !!");
    }

    this.lo = lo;
    this.hi = hi;
  }

  get i() {
    const hi = this.hi | 0;

    if (hi < -0x200000 || hi > 0x1fffff) {
      throw new RangeError(this + " outside safe 53-bit range");
    }

    return hi * 0x100000000 + this.lo;
  }

  get u() {
    const hi = this.hi;

    if (hi > 0x1fffff) {
      throw new RangeError(this + " outside safe 53-bit range");
    }

    return hi * 0x100000000 + this.lo;
  }

  get d() {
    const hi_word = this.hi >>> 16;
    if (hi_word === 0xffff || hi_word === 0xfffe) {
      throw new RangeError(this + " cannot be represented as double");
    }

    BInt.View.setUint32(0, this.lo, true);
    BInt.View.setUint32(4, this.hi, true);

    return BInt.View.getFloat64(0, true);
  }

  toString() {
    return "0x" + this.hi.toString(16).padStart(8, "0") + this.lo.toString(16).padStart(8, "0");
  }

  [Symbol.toPrimitive](hint) {
    if (hint === "string") {
      return this.toString();
    }

    return this.i;
  }

  getBit(idx) {
    if (idx < 0 || idx > 0x3f) {
      throw new RangeError("Bit " + idx + " is out of range !!");
    }

    return (idx < 0x20 ? this.lo >>> idx : this.hi >>> (idx - 0x20)) & 1;
  }

  setBit(idx, value) {
    if (idx < 0 || idx > 0x3f) {
      throw new RangeError("Bit " + idx + " is out of range !!");
    }

    if (idx < 0x20) {
      this.lo = (value ? this.lo | (1 << idx) : this.lo & ~(1 << idx)) >>> 0;
    } else {
      this.hi = (value ? this.hi | (1 << (idx - 0x20)) : this.hi & ~(1 << (idx - 0x20))) >>> 0;
    }
  }

  divmod(value) {
    value = value instanceof BInt ? value : new BInt(value);

    if (value === 0) {
      throw new Error("Division by zero");
    }

    let r = new BInt();
    const q = new BInt();
    for (let i = 0x3f; i >= 0; i--) {
      r = r.shl(1);

      if (this.getBit(i)) {
        r.setBit(0, true);
      }

      if (r.gte(value)) {
        r = r.sub(value);
        q.setBit(i, true);
      }
    }

    return { q, r };
  }

  cmp(value) {
    value = value instanceof BInt ? value : new BInt(value);
    return this.hi !== value.hi ? (this.hi > value.hi ? 1 : -1) : this.lo !== value.lo ? (this.lo > value.lo ? 1 : -1) : 0;
  }

  gt(value) {
    return this.cmp(value) > 0;
  }

  gte(value) {
    return this.cmp(value) >= 0;
  }

  lt(value) {
    return this.cmp(value) < 0;
  }

  lte(value) {
    return this.cmp(value) <= 0;
  }

  eq(value) {
    value = value instanceof BInt ? value : new BInt(value);
    return this.hi === value.hi && this.lo === value.lo;
  }

  neq(value) {
    value = value instanceof BInt ? value : new BInt(value);
    return this.hi !== value.hi || this.lo !== value.lo;
  }

  add(value) {
    value = value instanceof BInt ? value : new BInt(value);

    const lo = this.lo + value.lo;
    const c = lo > 0xffffffff ? 1 : 0;
    const hi = this.hi + value.hi + c;
    if (hi > 0xffffffff) {
      throw new RangeError("add overflowed !!");
    }

    return new BInt(hi, lo);
  }

  sub(value) {
    value = value instanceof BInt ? value : new BInt(value);

    if (this.lt(value)) {
      throw new RangeError("sub underflowed !!");
    }

    const b = this.lo < value.lo ? 1 : 0;
    const hi = this.hi - value.hi - b;
    const lo = this.lo - value.lo;

    return new BInt(hi, lo);
  }

  mul(value) {
    value = value instanceof BInt ? value : new BInt(value);

    const m00 = Math.imul(this.lo, value.lo);
    const m01 = Math.imul(this.lo, value.hi);
    const m10 = Math.imul(this.hi, value.lo);
    const m11 = Math.imul(this.hi, value.hi);

    const d = m01 + m10;
    const lo = m00 + (d >>> 0);
    const c = lo > 0xffffffff ? 1 : 0;
    const hi = m11 + Math.floor(d / 0x100000000) + c;
    if (hi > 0xffffffff) {
      throw new Error("mul overflowed !!");
    }

    return new BInt(hi, lo);
  }

  div(value) {
    return this.divmod(value).q;
  }

  mod(value) {
    return this.divmod(value).r;
  }

  xor(value) {
    value = value instanceof BInt ? value : new BInt(value);

    const lo = (this.lo ^ value.lo) >>> 0;
    const hi = (this.hi ^ value.hi) >>> 0;

    return new BInt(hi, lo);
  }

  and(value) {
    value = value instanceof BInt ? value : new BInt(value);

    const lo = (this.lo & value.lo) >>> 0;
    const hi = (this.hi & value.hi) >>> 0;

    return new BInt(hi, lo);
  }

  or(value) {
    value = value instanceof BInt ? value : new BInt(value);

    const lo = (this.lo | value.lo) >>> 0;
    const hi = (this.hi | value.hi) >>> 0;

    return new BInt(hi, lo);
  }

  not() {
    const lo = ~this.lo >>> 0;
    const hi = ~this.hi >>> 0;

    return new BInt(hi, lo);
  }

  shl(count) {
    if (count < 0 || count > 0x3f) {
      throw new RangeError("Shift " + count + " bits out of range !!");
    }

    if (count === 0) {
      return new BInt(this);
    }

    const lo = count < 0x20 ? (this.lo << count) >>> 0 : 0;
    const hi = count < 0x20 ? ((this.hi << count) | (this.lo >>> (0x20 - count))) >>> 0 : (this.lo << (count - 0x20)) >>> 0;

    return new BInt(hi, lo);
  }

  shr(count) {
    if (count < 0 || count > 63) {
      throw new RangeError("Shift " + count + " bits out of range !!");
    }

    if (count === 0) {
      return new BInt(this);
    }

    const lo = count < 0x20 ? ((this.lo >>> count) | (this.hi << (0x20 - count))) >>> 0 : this.hi >>> (count - 0x20);
    const hi = count < 0x20 ? this.hi >>> count : 0;

    return new BInt(hi, lo);
  }

  alignUp(alignment) {
    if (alignment <= 0 || (alignment & (alignment - 1)) !== 0) {
      throw new RangeError("alignment must be power of 2");
    }

    const mask = alignment - 1;

    let lo = this.lo + mask;
    let hi = this.hi;

    if (lo > 0xffffffff) {
      lo -= 0x100000000;
      hi++;
    }

    lo &= ~mask;

    return new BInt(hi, lo);
  }

  alignDown(alignment) {
    if (alignment <= 0 || (alignment & (alignment - 1)) !== 0) {
      throw new RangeError("alignment must be power of 2");
    }

    const mask = alignment - 1;

    const lo = this.lo & ~mask;
    const hi = this.hi;

    return new BInt(hi, lo);
  }
}
//#endregion
//#region Extensions
Number.prototype.hex = function (padded = false, maxLength = 16) {
  let str = this.toString(16).toUpperCase();

  if (padded) {
    str = str.padStart(maxLength, "0");
  }

  return "0x" + str;
};

Number.prototype.alignUp = function (alignment) {
  const mask = alignment - 1;
  return (this + mask) & ~mask;
};

Number.prototype.alignDown = function (alignment) {
  const mask = alignment - 1;
  return this & ~mask;
};

DataView.prototype.getBInt = function (byteOffset, littleEndian = false) {
  const lo = this.getUint32(byteOffset, littleEndian);
  const hi = this.getUint32(byteOffset + 4, littleEndian);
  return new BInt(hi, lo);
};

DataView.prototype.setBInt = function (byteOffset, value, littleEndian = false) {
  value = value instanceof BInt ? value : new BInt(value);

  this.setUint32(byteOffset, value.lo, littleEndian);
  this.setUint32(byteOffset + 4, value.hi, littleEndian);
};
//#endregion
//#region Static
BInt.View = new DataView(new ArrayBuffer(8));
//#endregion
//#region Functions
function is_worker() {
  return typeof WorkerGlobalScope !== "undefined" && self instanceof WorkerGlobalScope;
}
//#endregion