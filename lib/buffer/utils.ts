import type Buffer from 'https://deno.land/std@0.70.0/node/buffer.ts';

/**
 * Checks an offset to see whether it is out of bounds.
 */
export function checkOffset(offset: number, ext: number, length: number): void {
     if ((offset % 1) !== 0 || offset < 0) throw new RangeError('Offset is not an unsigned integer.');
     if (offset + ext > length) throw new RangeError('Byte out of buffer length');
}

/**
 * Checks whether a value can be written to a buffer
 */
export function checkInt (buffer: Buffer, value: number, offset: number, ext: number, max: number, min: number): void {
     if (value > max || value < min) throw new RangeError('"value" argument is out of bounds');
     if (offset + ext > buffer.length) throw new RangeError('Index out of range');
}