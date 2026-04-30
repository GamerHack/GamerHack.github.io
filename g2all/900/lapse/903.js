/* Copyright (C) 2025 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

// 9.03, 9.04

export const pthread_offsets = new Map(Object.entries({
    'pthread_create' : 0x25510,
    'pthread_join' : 0xafa0,
    'pthread_barrier_init' : 0x273d0,
    'pthread_barrier_wait' : 0xa320,
    'pthread_barrier_destroy' : 0xfea0,
    'pthread_exit' : 0x77a0,
}));

export const off_kstr = 0x7f4ce7;
export const off_cpuid_to_pcpu = 0x21eb2a0;

export const off_sysent_661 = 0x1103f00;
export const jmp_rsi = 0x5325b;

export const patch_elf_loc = "./900/kpatch/903.bin"; // Relative to `../../lapse.mjs`
