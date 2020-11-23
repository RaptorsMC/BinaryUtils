import type Buffer from 'https://deno.land/std@0.70.0/node/buffer.ts';
import { checkOffset, checkInt } from './utils.ts';

/**
 * Replicates Node's <Buffer>.writeUIntLE
 * @returns the new ending offset of the byte
 */
export function writeUIntLE(buffer: Buffer, value: number, offset: number, byteLength: number): number {
     // increase offset
     value = +value;
     // shift our integers (checking if it's unsigned)
     offset = offset >>> 0;
     byteLength = byteLength >>> 0;

     // this should be the maximum amount of bytes we can possibly write?
     let maxBytes: number = Math.pow(2, (8 * byteLength) - 1);
     // check to make sure we can actually write the bytes to this buffer.
     checkInt(buffer, value, offset, byteLength, maxBytes, 0);

     let i: number = 0;
     let multiplier: number = 1;
     buffer[offset] = value & 0xFF;
     // check if its less than the byte length, otherwise stop (IM SO DUMB!)
     while (++i < byteLength && (multiplier *= 0x100)) {
          // continue writing the bytes
          if (multiplier >= Infinity || multiplier <= -Infinity) throw 'Recursion detected in writing UIntLE. Breaking...';
          buffer[offset + i] = ((value / multiplier) >> 0) & 0xFF;
     }

     return offset + byteLength;
}

/**
 * Replicates Node's <Buffer>.writeUIntBE
 * @returns the new ending offset of the byte
 */
export function writeUIntBE(buffer: Buffer, value: number, offset: number, byteLength: number): number {
     // increase offset
     value = +value;
     // shift our integers (checking if it's unsigned)
     offset = offset >>> 0;
     byteLength = byteLength >>> 0;

     // this should be the maximum amount of bytes we can possibly write?
     let maxBytes: number = Math.pow(2, (8 * byteLength) - 1);
     // check to make sure we can actually write the bytes to this buffer.
     checkInt(buffer, value, offset, byteLength, maxBytes, 0);

     let i: number = byteLength - 1;
     let multiplier: number = 1;
     buffer[offset + i] = value & 0xFF;
     // In theory this should never cause issues, however it may, so in that case we're keeping recusive guard
     while (--i >= 0 && (multiplier *= 0x100)) {
          // continue writing the bytes
          if (multiplier >= Infinity || multiplier <= -Infinity) throw 'Recursion detected in writing UIntBE. Breaking...';
          buffer[offset + i] = ((value / multiplier) >> 0) & 0xFF;
     }

     return offset + byteLength;
}