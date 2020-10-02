/**
 *    ______            _                 ___  ________ 
 *    | ___ \          | |                |  \/  /  __ \
 *    | |_/ /__ _ _ __ | |_ ___  _ __ ___ | .  . | /  \/
 *    |    // _` | '_ \| __/ _ \| '__/ __|| |\/| | |    
 *    | |\ \ (_| | |_) | || (_) | |  \__ \| |  | | \__/\
 *    \_| \_\__,_| .__/ \__\___/|_|  |___/\_|  |_/\____/
 *               | |                                    
 *               |_|      
 * 
 * Misuse or redistribution of this code is strictly prohibted.
 * This applies to, and is not limited to self projects and open source projects.
 * If you wish to use this projects code, please contact us.
 * © RaptorsMC 2020
 * 
 * @author RaptorsMC
 * @copyright https://github.com/RaptorsMC
 * @license RaptorsMC/CustomLicense
 */
import Buffer from 'https://deno.land/std/node/buffer.ts';

class BinaryStream {
    // These are exposed for ease, use this carefully.
    #buffer: Buffer;
    #offset: number;

    constructor(buffer: Buffer = Buffer.alloc(0), offset: number = 0) {
        this.#buffer = buffer;
        this.#offset = offset;
    }

    /**
     * Appends a buffer to the binary one.
     */
    public write(buffer: Buffer|Uint8Array): void {
        this.#buffer = Buffer.concat([this.#buffer, buffer]);
        this.addOffset(Buffer.byteLength(buffer));
    }

    /**
     * Reads a buffer slice with the given length
     * from the actual offset to the offset + len
     */
    public read(len: number): Buffer {
        return this.#buffer.slice(this.#offset, this.addOffset(len));
    }

    /**
     * Reads an unsigned byte (0 - 255)
     */
    public readByte(): number {
        return this.#buffer.readUInt8(this.addOffset(1));
    }

    /**
     * Reads a signed byte (-128 - 127)
     */
    public readSignedByte(): number {
        return this.#buffer.readInt8(this.addOffset(1));
    }

    /**
     * Writes an unsigned / signed byte 
     */
    public writeByte(v: number): void {
        this.write(Buffer.from([v & 0xff]));
    }

    /**
     * Reads a boolean byte
     */
    public readBool(): boolean {
        return this.readByte() !== 0;
    }

    /**
     * Writes a boolean byte
     */
    public writeBool(v: boolean): void {
        this.writeByte(v ? 1 : 0);
    }

    /**
     * Reads a 16 bit unsigned big endian number
     */
    public readShort(): number {
        return this.#buffer.readUInt16BE(this.addOffset(2));
    }

    /**
     * Reads a 16 bit signed big endian number
     */
    public readSignedShort(): number {
        return this.#buffer.readInt16BE(this.addOffset(2));
    }

    /**
     * Writes a 16 bit signed / unsigned big endian number
     */
    public writeShort(v: number): void {
        this.writeByte((v >> 8) & 0xff);
        this.writeByte(v & 0xff);
    }

    /**
     * Reads an unsigned 16 bit little endian number
     */
    public readLShort(): number {
        return this.#buffer.readUInt16LE(this.addOffset(2));
    }

    /**
     * Reads a signed 16 bit little endian number
     */
    public readSignedLShort(): number {
        return this.#buffer.readInt16LE(this.addOffset(2));
    }

    /**
     * Writes a 16 bit signed / unsigned little endian number
     */
    public writeLShort(v: number): void {
        this.writeByte(v & 0xff);
        this.writeByte((v >> 8) & 0xff);
    }

    /**
     * Reads a 3 byte unsigned big endian number
     */
    public readTriad(): bigint {
        // we need to replicate readUIntLE
        return this.readUIntBE(this.#buffer, this.addOffset(3), 3);
    }

    /**
     * Writes a 3 byte unsigned big endian number
     */
    public writeTriad(v: number): void {
        let buffer = Buffer.alloc(3);
        this.writeUIntBE(buffer, v, 0, 3);
        this.write(buffer);
    }

    /**
     * Reads a 3 byte unsigned little endian number
     */
    public readLTriad(): number {
        return this.readUIntLE(this.#buffer, this.addOffset(3), 3);
    }

    /**
     * Reads a 3 byte unsigned little endian number
     */
    public writeLTriad(v: number) {
        let buffer = Buffer.alloc(3);
        this.writeUIntLE(buffer, v, 0, 3);
        this.write(buffer);
    }

    /**
     * Reads a 4 byte signed integer
     */
    public readInt(): number {
        return this.#buffer.readInt32BE(this.addOffset(4));
    }

    /**
     * Writes a 4 byte signed integer
     */
    public writeInt(v: number): void {
        let buffer = Buffer.alloc(4);
        buffer.writeInt32BE(v);
        this.write(buffer);
    }

    /**
     * Reads a 4 byte signed little endian integer
     */
    public readLInt(): number {
        return this.#buffer.readInt32LE(this.addOffset(4));
    }

    /**
     * Writes a 32 bit signed little endian integer
     */
    public writeLInt(v: number): void {
        let buffer = Buffer.alloc(4);
        buffer.writeInt32LE(v);
        this.write(buffer);
    }

    public readUIntLE(buffer: Buffer, offset: number, byteLength: number): number {
        offset = offset >>> 0;
        byteLength = byteLength >>> 0;

        this.checkOffset(offset, byteLength, buffer.length);

        let value: number = buffer[offset];
        let multiplier: number = 1;
        let i: number = 0;

        while (++i < byteLength && (multiplier *= 0x100)) {
            value += buffer[offset + i] * multiplier;
        }

        return value;
    }


    /**
     * Replicates Node's <Buffer>.writeUIntLE
     * @returns the new ending offset of the byte
     */
    public writeUIntLE(buffer: Buffer, value: number, offset: number, byteLength: number): number {
        // increase offset
        value = +value;
        // shift our integers (checking if it's unsigned)
        offset = offset >>> 0;
        byteLength = byteLength >>> 0;

        // this should be the maximum amount of bytes we can possibly write?
        let maxBytes: number = Math.pow(2, (8 * byteLength) - 1);
        // check to make sure we can actually write the bytes to this buffer.
        this.checkInt(buffer, value, offset, byteLength, maxBytes, 0);

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

    public readUIntBE(buffer: Buffer, offset: number, byteLength: number): bigint {
		offset = offset >>> 0;
		byteLength = byteLength >>> 0;

		this.checkOffset(offset, byteLength, buffer.length);

		let i: number = byteLength;
		let value: number = buffer[offset + --i];
		let multiplier: number = 1;
		while (i > 0 && (multiplier *= 0x100)) {
			value += buffer[offset + --i] * multiplier;
		}

		return BigInt(value);
    }

    /**
    * Replicates Node's <Buffer>.writeUIntBE
    * @returns the new ending offset of the byte
    */
    public writeUIntBE(buffer: Buffer, value: number, offset: number, byteLength: number): number {
        value = +value;
        offset = offset >>> 0;
        byteLength = byteLength >>> 0;

        // this should be the maximum amount of bytes we can possibly write?
        let maxBytes: number = Math.pow(2, (8 * byteLength) - 1);
        // TODO 
        this.checkInt(buffer, value, offset, byteLength, maxBytes, 0);

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

    public readIntLE(buffer: Buffer, offset: number, byteLength: number): number {
        // Shift our unsigned integers right. (checking)
        offset = offset >>> 0;
        byteLength = byteLength >>> 0;

        this.checkOffset(offset, byteLength, buffer.length);

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

    public writeIntLE(buffer: Buffer, value: number, offset: number, byteLength: number): number {
        // increase offset
        value = +value;
        // shift our integers (checking if it's unsigned)
        offset = offset >>> 0;
   
        // this should be the maximum amount of bytes we can possibly write?
        let maxBytes: number = Math.pow(2, (8 * byteLength) - 1)
        // check to make sure we can actually write the bytes to this buffer.
        this.checkInt(buffer, value, offset, byteLength, maxBytes - 1, -maxBytes);
   
        let i: number = 0;
        let multiplier: number = 1;
        let sub: number = 0;
        // write the initial byte
        buffer[offset] = value & 0xFF;
        while (i++ < byteLength && (multiplier *= 0x100)) {
             if (multiplier >= Infinity || multiplier <= -Infinity) throw 'Recursion detected in writing writeIntLE. Breaking...';
             if (value < 0 && sub === 0 && buffer[offset + i - 1] !== 0) {
                  sub = 1;
             }
             // continue writing the bytes
             buffer[offset + i] = ((value / multiplier) >> 0) - sub & 0xFF;
        }
   
        return offset + byteLength;
   }   

    /**
    * Replicates Nodes <Buffer>.readIntBE
    * @param buffer 
    * @param offset 
    * @param byteLength 
    */
    public readIntBE(buffer: Buffer, offset: number, byteLength: number = 1024): bigint {
        // Shift our unsigned integers right. (checking)
        offset = offset >>> 0;
        byteLength = byteLength >>> 0;

        this.checkOffset(offset, byteLength, buffer.length);

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

    public writeIntBE(buffer: Buffer, value: number, offset: number, byteLength: number): number {
        // increase offset
        value = +value;
        // shift our integers (checking if it's unsigned)
        offset = offset >>> 0;
   
        // this should be the maximum amount of bytes we can possibly write?
        let maxBytes: number = Math.pow(2, (8 * byteLength) - 1)
        // check to make sure we can actually write the bytes to this buffer.
        this.checkInt(buffer, value, offset, byteLength, maxBytes - 1, -maxBytes);
   
        let i: number = byteLength - 1;
        let multiplier: number = 1;
        let sub: number = 0;
        // write the initial byte
        buffer[offset] = value & 0xFF;
        while (--i >= 0 && (multiplier *= 0x100)) {
             if (multiplier >= Infinity || multiplier <= -Infinity) throw 'Recursion detected in writing writeIntBE. Breaking...';
             if (value < 0 && sub === 0 && buffer[offset + i - 1] !== 0) {
                  sub = 1;
             }
             // continue writing the bytes
             buffer[offset + i] = ((value / multiplier) >> 0) - sub & 0xFF;
        }
   
        return offset + byteLength;
   }

    /**
     * Reads a 4 byte floating-point number
     */
    public readFloat(): number {
        return this.#buffer.readFloatBE(this.addOffset(4));
    }

    /**
     * Reads a 4 byte floating-point number, rounded to the specified precision
     */
    public readRoundedFloat(precision: number): string {
        return Math.fround(this.readFloat()).toPrecision(precision);
    }

    /**
     * Writes a 4 byte floating-point number
     */
    public writeFloat(v: number): void {
        let buffer = Buffer.alloc(4);
        buffer.writeFloatBE(v);
        this.write(buffer);
    }

    /**
     * Reads a 4 byte little endian floating-point number
     */
    public readLFloat(): number {
        return this.#buffer.readFloatLE(this.addOffset(4));
    }

    /**
     * Reads a 4 byte little endian floating-point number, rounded to the specified precision
     */
    public readRoundedLFloat(precision: number): string {
        return Math.fround(this.readLFloat()).toPrecision(precision);
    }

    /**
     * Writes a 4 byte little endian floating-point number
     */
    public writeLFloat(v: number): void {
        let buffer = Buffer.alloc(4);
        buffer.writeFloatLE(v);
        this.write(buffer);
    }

    /**
     * Reads an 8 byte floating-point number
     */
    public readDouble(): number {
        return this.#buffer.readDoubleBE(this.addOffset(8));
    }

    /**
     * Writes an 8 byte floating-point number
     */
    public writeDouble(v: number): void {
        let buffer = Buffer.alloc(8);
        buffer.writeDoubleBE(v);
        this.write(buffer);
    }

    /**
     * Reads an 8 byte little endian floating-point number
     */
    public readLDouble(): number {
        return this.#buffer.readDoubleLE(this.addOffset(8));
    }

    /**
     *  Writes an 8 byte little endian floating-poinr number
     */
    public writeLDouble(v: number): void {
        let buffer = Buffer.alloc(8);
        buffer.writeDoubleLE(v);
        this.write(buffer);
    }

    /**
     * Reads an 8 byte integer
     */
    public readLong(): bigint {
        return this.#buffer.readBigInt64BE(this.addOffset(8));
    }

    /**
     * Writes an 8 byte integer
     */
    public writeLong(v: bigint): void {
        let buffer = Buffer.alloc(8);
        buffer.writeBigInt64BE(v);
        this.write(buffer);
    }

    /**
     * Reads an 8 byte little endian integer
     */
    public readLLong(): bigint {
        return this.#buffer.readBigInt64LE(this.addOffset(8));
    }

    /**
     * Writes an 8 byte little endian integer
     */
    public writeLLong(v: bigint): void {
        let buffer = Buffer.alloc(8);
        buffer.writeBigInt64LE(v);
        this.write(buffer);
    }

    /**
     * Reads a 32 bit zigzag-encoded integer
     */
    public readVarInt() {
        let raw = this.readUnsignedVarInt() ;
        let temp = (((raw << 63) >> 63) ^ raw) >> 1;
        return temp ^ (raw & (1 << 63));
    }

    /**
     * Reads a 32 bit unsigned integer
     */
    public readUnsignedVarInt() {
        let value = 0;
        for (let i = 0; i <= 28; i += 7) {
            if (typeof this.#buffer[this.#offset] === 'undefined') {
                // safety lock
                throw new Error('No bytes left in buffer');
            }
            let b = this.readByte();
            value |= ((b & 0x7f) << i);

            if ((b & 0x80) === 0) {
                return value;
            }
        }

        throw new Error('VarInt did not terminate after 5 bytes!');
    }

    /**
     * Writes a 32 bit integer as a zig-zag encoded integer
     */
    public writeVarInt(v: number): void {
        v = (v << 32 >> 32);
        return this.writeUnsignedVarInt((v << 1) ^ (v >> 31));
    }

    /**
     * Writes a 32 bit unsigned integer
     */
    public writeUnsignedVarInt(v: number): void {
        let stream = new BinaryStream();
        v &= 0xffffffff;

        for (let i = 0; i < 5; i++) {
            if ((v >> 7) !== 0) {
                stream.writeByte(v | 0x80);
            } else {
                stream.writeByte(v & 0x7f);
                this.write(stream.buffer);
                return;
            }
            v >>= 7;
        }

        this.write(stream.buffer);
    }

    /**
     * Reads a 64 bit zigzag-encoded long
     */
    public readVarLong(): number {
        let raw = this.readUnsignedVarLong();
        let tmp = (((raw << 63) >> 63) ^ raw) >> 1;
        return tmp ^ (raw & (1 << 63));
    }

    /**
     * Reads a 64 bit unsigned long
     */
    public readUnsignedVarLong(): number {
        let value = 0;
        for (let i = 0; i <= 63; i += 7) {
            if (typeof this.#buffer[this.#offset] === 'undefined') {
                throw new Error('No bytes left in buffer');
            }
            let b = this.readByte();
            value |= ((b & 0x7f) << i);

            if ((b & 0x80) === 0) {
                return value;
            }
        }
        
        throw new Error('VarInt did not terminate after 10 bytes!');
    }

    /**
     * Writes a 64 bit integer as zigzag-encoded long
     */
    public writeVarLong(v: number): void {
        return this.writeUnsignedVarLong((v << 1) ^ (v >> 63));
    }

    /**
     * Writes a 64 bit unsigned integer long
     */
    public writeUnsignedVarLong(v: number) {
        for (let i = 0; i < 10; i++) {
            if ((v >> 7) !== 0) {
                this.writeByte(v | 0x80);
            } else {
                this.writeByte(v & 0x7f);
                break;
            }
            v >>= 7;
        }
    }

    /**
     * Increase offset value by the given bytes.
     */
    public addOffset(v: number, r = false): number {
        return r ? this.#offset += v : (this.#offset += v) - v;
    }

    /**
     * Returns whether the offset has reached the end of the buffer.
     */
    public feof() {
        return this.#offset <= this.#buffer.byteLength;
    }

    /**
     * Returns the remaining o
     */
    public readRemaining(): Buffer {
        let buffer = this.#buffer.slice(this.#offset);
        this.#offset = this.#buffer.length;
        return buffer;
    }

    /**
     * Resets the offset to 0
     */
    public reset(): void {
        this.#buffer = Buffer.alloc(0);
        this.#offset = 0;
    }

    public get buffer(): Buffer {
        return this.#buffer;
    }

    public set buffer(buffer: Buffer) {
        this.#buffer = buffer;
    }

    public get offset(): number {
        return this.#offset;
    }

    public set offset(offset: number) {
        this.#offset = offset;
    }

    /**
     * Checks the byte offset to ensure we can write, throws an error if we can not.
     * @param offset 
     * @param byteLength 
     */
    private checkOffset(offset: number, ext: number, byteLength: number): void {
        // check if its an unsigned varint, we need this because floats can not be added to a buffer
        if ((offset % 1) !== 0 || offset < 0) throw new RangeError("Offset out of bounds.");
        if (offset + ext > byteLength) throw new RangeError("Not enough bytes left in buffer");
    }

    private checkInt(buffer: Buffer, value: number, offset: number, ext: number, max: number, min: number): void {
        // checks whether a value can be wwritten
        if (value > max || value < min) throw new RangeError('"value" argument is out of bounds');
        if (offset + ext > buffer.length) throw new RangeError('Index out of range');
    }
}
export default BinaryStream;