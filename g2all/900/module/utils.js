/* Copyright (C) 2023-2025 anonymous

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

import { Int } from './int64.js';

export class DieError extends Error {
    constructor(...args) {
        super(...args);
        this.name = this.constructor.name;
    }
}

export function die(msg = '') {
    throw new DieError(msg);
}

export function log(msg = '') {
    // Logs are silenced
}

export function clear_log() {
	// Function kept to avoid reference errors
}

export function align(a, alignment) {
    if (!(a instanceof Int)) {
        a = new Int(a);
    }
    const mask = -alignment & 0xffffffff;
    let type = a.constructor;
    let low = a.lo & mask;
    return new type(low, a.hi);
}

export async function send(url, buffer, file_name, onload = () => {}) {
    const file = new File(
        [buffer],
        file_name,
        { type: 'application/octet-stream' }
    );
    const form = new FormData();
    form.append('upload', file);

    log('send');
    const response = await fetch(url, { method: 'POST', body: form });

    if (!response.ok) {
        throw Error(`Network response was not OK, status: ${response.status}`);
    }
    onload();
}

export function sleep(ms = 0) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export function hex(number) {
    return `0x${number.toString(16)}`;
}

export function hex_np(number) {
    return number.toString(16);
}

export function hexdump(view) {
    // Inactive because log() is disabled
}

export function jstr(buffer) {
    let res = '';
    for (const item of buffer) {
        if (item === 0) break;
        res += String.fromCodePoint(item);
    }
    return String(res);
}