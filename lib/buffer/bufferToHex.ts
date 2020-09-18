export function bufferToHex(buffer: Uint8Array): string {
     const buffArr: number[] = Array.from(buffer);
     const arrParts: string[] = buffArr.map((x: number) => ('00' + x.toString(16).slice(-2)));
     return arrParts.join('');
}