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

// 7.00, 7.01, 7.02

export const pthread_offsets = new Map(
  Object.entries({
    pthread_create: 0x256b0,
    pthread_join: 0x27d00,
    pthread_barrier_init: 0xa170,
    pthread_barrier_wait: 0x1ee80,
    pthread_barrier_destroy: 0xe2e0,
    pthread_exit: 0x19fd0,
  }),
);

export const off_kstr = 0x7f92cb;
export const off_cpuid_to_pcpu = 0x212cd10;

export const off_sysent_661 = 0x112d250;
export const jmp_rsi = 0x6b192;

export const patch_elf_loc = "./700/kpatch/700.bin";
