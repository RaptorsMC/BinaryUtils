import Buffer from 'https://deno.land/std/node/buffer.ts';
import { readIntBE, readIntLE } from './readInt.ts';
import { readUIntBE, readUIntLE } from './readUInt.ts';

class ExtendedBuffer extends Buffer {
     constructor(...params: any[]) {
          // @ts-ignore
          super(...params);
     }

     /**
      * Read an signed little endian
      */
     public readIntLE(offset: number, byteLength: number): number {
          return readIntLE(this, offset, byteLength);
     }

     /**
      * Read an signed big endian
      */
     public readIntBE(offset: number, byteLength: number): bigint {
          return readIntBE(this, offset, byteLength);
     }

     /**
      * Read an unsigned little endian
      */
     public readUIntLE(offset: number, byteLength: number): number {
          return readUIntLE(this, offset, byteLength);
     }

     /**
      * Read an unsigned big endian
      */
     public readUIntBE(offset: number, byteLength: number): bigint {
          return readUIntBE(this, offset, byteLength);
     }
}
export { ExtendedBuffer };
export default ExtendedBuffer;