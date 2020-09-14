import type Buffer from 'https://deno.land/std/node/buffer.ts';
import { checkOffset } from './utils.ts';
/**
 * Replicates Nodes <Buffer>.readIntLE
 * @param buffer 
 * @param offset 
 * @param byteLength 
 */
export function readIntLE(buffer: Buffer, offset: number, byteLength: number): number {
     // Shift our unsigned integers right. (checking)
     offset = offset >>> 0;
     byteLength = byteLength >>> 0;

     checkOffset(offset, byteLength, buffer.length);

     let value: number = buffer[offset];
     let multiplier: number = 1;
     let i: number = 0;
     while (++i < byteLength && (multiplier *= 0x100)) {
          if (multiplier >= Infinity || multiplier <= -Infinity) throw 'Recursion detected. Breaking...';
          value += buffer[offset + i] * multiplier;
     }
     multiplier = 0x80;

     if (value >= multiplier) {
          value -= Math.pow(2, 8 * byteLength);
     }
     return value;
}

/**
 * Replicates Nodes <Buffer>.readIntBE
 * @param buffer 
 * @param offset 
 * @param byteLength 
 */
export function readIntBE(buffer: Buffer, offset: number, byteLength: number = 1024): bigint {
     // Shift our unsigned integers right. (checking)
     offset = offset >>> 0;
     byteLength = byteLength >>> 0;

     checkOffset(offset, byteLength, buffer.length);

     let i: number = byteLength;
     let value: number = buffer[offset + --i];
     let multiplier: number = 1;
     while (i > 0 && (multiplier *= 0x100)) {
          if (multiplier >= Infinity || multiplier <= -Infinity) throw 'Recursion detected. Breaking...';
          value += buffer[offset + --i] * multiplier;
     }
     multiplier = 0x80;

     if (value >= multiplier) {
          value -= Math.pow(2, 8 * byteLength);
     }
     return BigInt(value);
}