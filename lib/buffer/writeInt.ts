import Buffer from 'https://deno.land/std/node/buffer.ts';
import { checkOffset, checkInt } from './utils.ts';

/**
 * Replicates Node's <Buffer>.writeIntLE
 * @returns the new ending offset of the byte
 */
export function writeIntLE(buffer: Buffer, value: number, offset: number, byteLength: number): number {
     // increase offset
     value = +value;
     // shift our integers (checking if it's unsigned)
     offset = offset >>> 0;

     // this should be the maximum amount of bytes we can possibly write?
     let maxBytes: number = Math.pow(2, (8 * byteLength) - 1)
     // check to make sure we can actually write the bytes to this buffer.
     checkInt(buffer, value, offset, byteLength, maxBytes - 1, -maxBytes);

     let i: number = 0;
     let multiplier: number = 1;
     let sub: number = 0;
     // write the initial byte
     buffer[offset] = value & 0xFF;
     while (i++ < byteLength && (multiplier *= 0x100)) {
          if (value < 0 && sub === 0 && buffer[offset + i - 1] !== 0) {
               sub = 1;
          }
          // continue writing the bytes
          buffer[offset + i] = ((value / multiplier) >> 0) - sub & 0xFF;
     }

     return offset + byteLength;
}

/**
 * Replicates Node's <Buffer>.writeIntBE
 * @returns the new ending offset of the byte
 */
export function writeIntBE(buffer: Buffer, value: number, offset: number, byteLength: number): number {
     // increase offset
     value = +value;
     // shift our integers (checking if it's unsigned)
     offset = offset >>> 0;

     // this should be the maximum amount of bytes we can possibly write?
     let maxBytes: number = Math.pow(2, (8 * byteLength) - 1)
     // check to make sure we can actually write the bytes to this buffer.
     checkInt(buffer, value, offset, byteLength, maxBytes - 1, -maxBytes);

     let i: number = byteLength - 1;
     let multiplier: number = 1;
     let sub: number = 0;
     // write the initial byte
     buffer[offset] = value & 0xFF;
     while (--i >= 0 && (multiplier *= 0x100)) {
          if (value < 0 && sub === 0 && buffer[offset + i - 1] !== 0) {
               sub = 1;
          }
          // continue writing the bytes
          buffer[offset + i] = ((value / multiplier) >> 0) - sub & 0xFF;
     }

     return offset + byteLength;
}