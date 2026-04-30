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

// 8.00, 8.01, 8.03

export const pthread_offsets = new Map(
  Object.entries({
    pthread_create: 0x25610,
    pthread_join: 0x27c60,
    pthread_barrier_init: 0xa0e0,
    pthread_barrier_wait: 0x1ee00,
    pthread_barrier_destroy: 0xe180,
    pthread_exit: 0x19eb0,
  }),
);

export const off_kstr = 0x7edcff;
export const off_cpuid_to_pcpu = 0x228e6b0;

export const off_sysent_661 = 0x11040c0;
export const jmp_rsi = 0xe629c;

export const patch_elf_loc = "./700/kpatch/800.bin";
