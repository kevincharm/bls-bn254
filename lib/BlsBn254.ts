import {
    dataSlice,
    hexlify,
    getBytes,
    concat,
    keccak256,
    zeroPadValue,
    toBeArray,
    toBeHex,
    randomBytes,
} from 'ethers'
const mcl = require('mcl-wasm')
import type { G1, G2, Fr, Fp, Fp2 } from 'mcl-wasm'

/**
 * Mcl wrapper for BLS operations
 * Mostly copied from: https://github.com/kilic/evmbls
 */
export class BlsBn254 {
    static readonly FIELD_ORDER =
        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n

    public readonly G1: G1
    public readonly G2: G2

    private constructor() {
        this.G1 = new mcl.G1()
        const g1x: Fp = new mcl.Fp()
        const g1y: Fp = new mcl.Fp()
        const g1z: Fp = new mcl.Fp()
        g1x.setStr('01', 16)
        g1y.setStr('02', 16)
        g1z.setInt(1)
        this.G1.setX(g1x)
        this.G1.setY(g1y)
        this.G1.setZ(g1z)
        this.G2 = new mcl.G2()
        const g2x = createFp2(
            '0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed',
            '0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2',
        )
        const g2y = createFp2(
            '0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa',
            '0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b',
        )
        const g2z = createFp2('0x01', '0x00')
        this.G2.setX(g2x)
        this.G2.setY(g2y)
        this.G2.setZ(g2z)
    }

    public static async create() {
        await mcl.init(mcl.BN_SNARK1)
        mcl.setETHserialization(true)
        mcl.setMapToMode(0) // FT
        return new BlsBn254()
    }

    public newG1(): G1 {
        return new mcl.G1()
    }

    public newFp(): Fp {
        return new mcl.Fp()
    }

    public mapToPoint(eHex: `0x${string}`) {
        const e0 = BigInt(eHex)
        let e1: Fp = new mcl.Fp()
        e1.setStr(mod(e0, BlsBn254.FIELD_ORDER).toString())
        return e1.mapToG1()
    }

    public expandMsg(domain: Uint8Array, msg: Uint8Array, outLen: number): Uint8Array {
        if (domain.length > 255) {
            throw new Error('bad domain size')
        }

        const b_in_bytes = 32n
        const r_in_bytes = b_in_bytes * 2n
        const ell = ceilDiv(outLen, b_in_bytes)
        if (ell > 255) {
            throw new Error('invalid xmd length')
        }
        const DST_prime = concat([domain, new Uint8Array([domain.byteLength])])
        const Z_pad = new Uint8Array(Number(r_in_bytes))
        const l_i_b_str = new Uint8Array([(outLen >> 8) & 0xff, outLen & 0xff])
        const b: bigint[] = []
        const b_0 = BigInt(
            keccak256(concat([Z_pad, msg, l_i_b_str, new Uint8Array([0]), DST_prime])),
        )
        b[0] = BigInt(
            keccak256(concat([zeroPadValue(toBeArray(b_0), 32), new Uint8Array([1]), DST_prime])),
        )
        for (let i = 1; i < ell; i++) {
            b[i] = BigInt(
                keccak256(
                    concat([
                        zeroPadValue(toBeArray(b_0 ^ b[i - 1]), 32),
                        new Uint8Array([i + 1]),
                        DST_prime,
                    ]),
                ),
            )
        }
        return getBytes(concat(b.map((v) => zeroPadValue(toBeHex(v), 32))))
    }

    public hashToField(domain: Uint8Array, msg: Uint8Array, count: number): bigint[] {
        const u = 48
        const _msg = this.expandMsg(domain, msg, count * u)
        const els: bigint[] = []
        for (let i = 0; i < count; i++) {
            const el = mod(BigInt(hexlify(_msg.slice(i * u, (i + 1) * u))), BlsBn254.FIELD_ORDER)
            els.push(el)
        }
        return els
    }

    public hashToPoint(domain: Uint8Array, msg: Uint8Array): G1 {
        const hashRes = this.hashToField(domain, msg, 2)
        const e0 = hashRes[0]
        const e1 = hashRes[1]
        const p0 = this.mapToPoint(toHex(e0))
        const p1 = this.mapToPoint(toHex(e1))
        const p = mcl.add(p0, p1)
        p.normalize()
        return p
    }

    public serialiseFp(p: Fp | Fp2): `0x${string}` {
        // NB: big-endian
        return ('0x' +
            Array.from(p.serialize())
                .reverse()
                .map((value) => value.toString(16).padStart(2, '0'))
                .join('')) as `0x${string}`
    }

    public serialiseG1Point(p: G1): [bigint, bigint] {
        p.normalize()
        const x = BigInt(this.serialiseFp(p.getX()))
        const y = BigInt(this.serialiseFp(p.getY()))
        return [x, y]
    }

    public serialiseG2Point(p: G2): [bigint, bigint, bigint, bigint] {
        const x = this.serialiseFp(p.getX())
        const y = this.serialiseFp(p.getY())
        return [
            BigInt(dataSlice(x, 32)),
            BigInt(dataSlice(x, 0, 32)),
            BigInt(dataSlice(y, 32)),
            BigInt(dataSlice(y, 0, 32)),
        ]
    }

    public g1FromEvm(g1X: bigint, g1Y: bigint) {
        const x = g1X.toString(16).padStart(64, '0')
        const Mx = this.newFp()
        Mx.setStr(x, 16)
        const y = g1Y.toString(16).padStart(64, '0')
        const My = this.newFp()
        My.setStr(y, 16)
        const Mz = this.newFp()
        Mz.setInt(1)
        const M: G1 = this.newG1()
        M.setX(Mx)
        M.setY(My)
        M.setZ(Mz)
        return M
    }

    public createKeyPair(_secretKey?: `0x${string}`) {
        if (!_secretKey) {
            _secretKey = hexlify(randomBytes(31)) as `0x${string}`
        }

        const secretKey: Fr = new mcl.Fr()
        secretKey.setHashOf(_secretKey)
        const pubKey: G2 = mcl.mul(this.G2, secretKey)
        pubKey.normalize()
        return {
            secretKey,
            _secretKey,
            pubKey,
        }
    }

    public sign(M: G1, secret: Fr) {
        // const M: G1 = mcl.hashAndMapToG1(msg)
        // const M: G1 = this.hashToPoint(msg)
        const signature: G1 = mcl.mul(M, secret)
        signature.normalize()
        return {
            signature,
            M,
        }
    }

    public toArgs(pubKey: G2, M: G1, signature: G1) {
        return {
            signature: this.serialiseG1Point(signature),
            pubKey: this.serialiseG2Point(pubKey),
            M: this.serialiseG1Point(M),
        }
    }
}

export function byteSwap(hex: string, n: number) {
    const bytes = getBytes('0x' + hex)
    if (bytes.byteLength !== n) throw new Error(`Invalid length: ${bytes.byteLength}`)
    return Array.from(bytes)
        .reverse()
        .map((v) => v.toString(16).padStart(2, '0'))
        .join('')
}

// mcl format:      x = a + bi
// kyber format:    x = b + ai
export function kyberMarshalG2(p: G2) {
    return [
        byteSwap(p.getX().get_b().serializeToHexStr(), 32),
        byteSwap(p.getX().get_a().serializeToHexStr(), 32),
        byteSwap(p.getY().get_b().serializeToHexStr(), 32),
        byteSwap(p.getY().get_a().serializeToHexStr(), 32),
    ].join('')
}

export function kyberMarshalG1(p: G1) {
    return [
        byteSwap(p.getX().serializeToHexStr(), 32),
        byteSwap(p.getY().serializeToHexStr(), 32),
    ].join('')
}

function mod(a: bigint, b: bigint) {
    return ((a % b) + b) % b
}

function toHex(n: bigint): `0x${string}` {
    return ('0x' + n.toString(16).padStart(64, '0')) as `0x${string}`
}

function createFp2(a: string, b: string) {
    const fp2_a: Fp = new mcl.Fp()
    const fp2_b: Fp = new mcl.Fp()
    fp2_a.setStr(a)
    fp2_b.setStr(b)
    const fp2: Fp2 = new mcl.Fp2()
    fp2.set_a(fp2_a)
    fp2.set_b(fp2_b)
    return fp2
}

function ceilDiv(a: bigint | number, b: bigint | number): bigint {
    const _a = BigInt(a)
    const _b = BigInt(b)
    return (_a + _b - 1n) / _b
}
