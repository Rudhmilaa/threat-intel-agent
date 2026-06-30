// Add interface for DataView-like objects
interface DataViewLike {
    buffer: ArrayBuffer;
    byteOffset: number;
    getInt8(offset: number): number;
    getUint8(offset: number): number;
    getInt16(offset: number, littleEndian?: boolean): number;
    getUint16(offset: number, littleEndian?: boolean): number;
    getInt32(offset: number, littleEndian?: boolean): number;
    getUint32(offset: number, littleEndian?: boolean): number;
    getFloat32(offset: number, littleEndian?: boolean): number;
    getFloat64(offset: number, littleEndian?: boolean): number;
    setInt8(offset: number, value: number): void;
    setUint8(offset: number, value: number): void;
    setInt16(offset: number, value: number, littleEndian?: boolean): void;
    setUint16(offset: number, value: number, littleEndian?: boolean): void;
    setInt32(offset: number, value: number, littleEndian?: boolean): void;
    setUint32(offset: number, value: number, littleEndian?: boolean): void;
    setFloat32(offset: number, value: number, littleEndian?: boolean): void;
    setFloat64(offset: number, value: number, littleEndian?: boolean): void;
}

const rechk = /^([<>])?(([1-9]\d*)?([xcbB?hHiIfdsp]))*$/
const refmt = /([1-9]\d*)?([xcbB?hHiIfdsp])/g
const str = (v: DataViewLike, o: number, c: number) => String.fromCharCode(
    ...new Uint8Array(v.buffer, v.byteOffset + o, c))
const rts = (v: DataViewLike, o: number, c: number, s: string) => new Uint8Array(v.buffer, v.byteOffset + o, c)
    .set(s.split('').map(str => str.charCodeAt(0)))
const pst = (v: DataViewLike, o: number, c: number) => str(v, o + 1, Math.min(v.getUint8(o), c - 1))
const tsp = (v: DataViewLike, o: number, c: number, s: string) => { v.setUint8(o, s.length); rts(v, o + 1, c - 1, s) }
const lut = (le: boolean): {
    [key: string]: (c: number) => [number, number, ((o: number) => {
        u: (v: DataViewLike) => any;
        p: (v: DataViewLike, val: any) => void;
    }) | number]
} => ({
    x: (c: number) => [1, c, 0],
    c: (c: number) => [c, 1, (o: number) => ({
        u: (v: DataViewLike) => str(v, o, 1),
        p: (v: DataViewLike, c: string) => rts(v, o, 1, c)
    })],
    '?': (c: number) => [c, 1, (o: number) => ({
        u: (v: DataViewLike) => Boolean(v.getUint8(o)),
        p: (v: DataViewLike, B: boolean) => v.setUint8(o, B ? 1 : 0)
    })],
    b: (c: number) => [c, 1, (o: number) => ({
        u: (v: DataViewLike) => v.getInt8(o),
        p: (v: DataViewLike, b: number) => v.setInt8(o, b)
    })],
    B: (c: number) => [c, 1, (o: number) => ({
        u: (v: DataViewLike) => v.getUint8(o),
        p: (v: DataViewLike, B: number) => v.setUint8(o, B)
    })],
    h: (c: number) => [c, 2, (o: number) => ({
        u: (v: DataViewLike) => v.getInt16(o, le),
        p: (v: DataViewLike, h: number) => v.setInt16(o, h, le)
    })],
    H: (c: number) => [c, 2, (o: number) => ({
        u: (v: DataViewLike) => v.getUint16(o, le),
        p: (v: DataViewLike, H: number) => v.setUint16(o, H, le)
    })],
    i: (c: number) => [c, 4, (o: number) => ({
        u: (v: DataViewLike) => v.getInt32(o, le),
        p: (v: DataViewLike, i: number) => v.setInt32(o, i, le)
    })],
    I: (c: number) => [c, 4, (o: number) => ({
        u: (v: DataViewLike) => v.getUint32(o, le),
        p: (v: DataViewLike, I: number) => v.setUint32(o, I, le)
    })],
    f: (c: number) => [c, 4, (o: number) => ({
        u: (v: DataViewLike) => v.getFloat32(o, le),
        p: (v: DataViewLike, f: number) => v.setFloat32(o, f, le)
    })],
    d: (c: number) => [c, 8, (o: number) => ({
        u: (v: DataViewLike) => v.getFloat64(o, le),
        p: (v: DataViewLike, d: number) => v.setFloat64(o, d, le)
    })],
    s: (c: number) => [1, c, (o: number) => ({
        u: (v: DataViewLike) => str(v, o, c),
        p: (v: DataViewLike, s: string) => rts(v, o, c, s.slice(0, c))
    })],
    p: (c: number) => [1, c, (o: number) => ({
        u: (v: DataViewLike) => pst(v, o, c),
        p: (v: DataViewLike, s: string) => tsp(v, o, c, s.slice(0, c - 1))
    })]
})

const errbuf = new RangeError("Structure larger than remaining buffer")
const errval = new RangeError("Not enough values for structure")

export const struct = (format: string) => {
    let fns: Array<{ u: (v: DataViewLike) => any, p: (v: DataViewLike, val: any) => void }> = [], size = 0;
    let m = rechk.exec(format)
    if (!m) { throw new RangeError("Invalid format string") }
    const t = lut('<' === m[1]);
    const lu = (n: string | undefined, c: string): [number, number, ((o: number) => {
        u: (v: DataViewLike) => any;
        p: (v: DataViewLike, val: any) => void;
    }) | number] => t[c](n ? parseInt(n, 10) : 1);
    while ((m = refmt.exec(format))) {
        const args = m.slice(1) as [string | undefined, string];
        const [r, s, f] = lu(...args);
        for (let i = 0; i < r; ++i, size += s) {
            if (f && typeof f === 'function') {
                fns.push(f(size))
            }
        }
    }
    const unpack_from = (arrb: ArrayBuffer, offs: number) => {
        if (arrb.byteLength < (offs | 0) + size) { throw errbuf }
        let v = new DataView(arrb, offs | 0)
        return fns.map(f => f.u(v))
    }
    const pack_into = (arrb: ArrayBuffer, offs: number, ...values: any[]) => {
        if (values.length < fns.length) { throw errval }
        if (arrb.byteLength < offs + size) { throw errbuf }
        const v = new DataView(arrb, offs)
        new Uint8Array(arrb, offs, size).fill(0)
        fns.forEach((f, i) => f.p(v, values[i]))
    }
    const pack = (...values: any[]) => {
        let b = new ArrayBuffer(size)
        pack_into(b, 0, ...values)
        return b
    }
    const unpack = (arrb: ArrayBuffer) => unpack_from(arrb, 0)
    function* iter_unpack(arrb: ArrayBuffer) {
        for (let offs = 0; offs + size <= arrb.byteLength; offs += size) {
            yield unpack_from(arrb, offs);
        }
    }
    return Object.freeze({
        unpack, pack, unpack_from, pack_into, iter_unpack, format, size
    })
} 