import type Buffer from 'https://deno.land/std/node/buffer.ts';
import { checkOffset } from './utils.ts';
/**
 * Replicates Nodes <Buffer>.readUIntLE
 * @param buffer 
 * @param offset 
 * @param byteLength 
 */
export function readUIntLE(buffer: Buffer, offset: number, byteLength: number): number {
     // Shift our unsigned integers right. (checking)
     offset = offset >>> 0;
     byteLength = byteLength >>> 0;

     checkOffset(offset, byteLength, buffer.length);

     let value: number = buffer[offset];
     let multiplier: number = 1;
     let i: number = 0;

     while (++i < byteLength && (multiplier *= 0x100)) {
          value += buffer[offset + i] * multiplier;
     }

     return value;
}

/**
 * Replicates Nodes <Buffer>.readUIntBE
 * @param buffer 
 * @param offset 
 * @param byteLength 
 */
export function readUIntBE(buffer: Buffer, offset: number, byteLength: number): bigint {
     // Shift our unsigned integers right. (checking)
     offset = offset >>> 0;
     byteLength = byteLength >>> 0;

     checkOffset(offset, byteLength, buffer.length);

     let i: number = byteLength;
     let value: number = buffer[offset + --i];
     let multiplier: number = 1;
     while (i > 0 && (multiplier *= 0x100)) {
          value += buffer[offset + --i] * multiplier;
     }

     return BigInt(value);
}