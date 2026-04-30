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

// 7.51, 7.55

export const pthread_offsets = new Map(
  Object.entries({
    pthread_create: 0x25800,
    pthread_join: 0x27e60,
    pthread_barrier_init: 0xa090,
    pthread_barrier_wait: 0x1ef50,
    pthread_barrier_destroy: 0xe290,
    pthread_exit: 0x1a030,
  }),
);

export const off_kstr = 0x79a96e;
export const off_cpuid_to_pcpu = 0x2261070;

export const off_sysent_661 = 0x1129f30;
export const jmp_rsi = 0x1f842;

export const patch_elf_loc = "./700/kpatch/750.bin";
// Not a mistake! Only ONE kernel offset differs between 7.50, 7.51, and 7.55.
// It's the `off_kstr` variable in THIS file, the kernel patches are the same.
// That's why 7.51/7.55 are seperate from 7.50, but using the same kpatch file.
