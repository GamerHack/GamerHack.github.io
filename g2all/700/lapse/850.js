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

// 8.50

export const pthread_offsets = new Map(
  Object.entries({
    pthread_create: 0xebb0,
    pthread_join: 0x29d50,
    pthread_barrier_init: 0x283c0,
    pthread_barrier_wait: 0xb8c0,
    pthread_barrier_destroy: 0x9c10,
    pthread_exit: 0x25310,
  }),
);

export const off_kstr = 0x7da91c;
export const off_cpuid_to_pcpu = 0x1cfc240;

export const off_sysent_661 = 0x11041b0;
export const jmp_rsi = 0xc810d;

export const patch_elf_loc = "./700/kpatch/850.bin";
