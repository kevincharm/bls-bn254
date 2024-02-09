import { ethers, solidityPackedKeccak256, zeroPadBytes } from 'ethers'
import { randomBytes, hexlify } from 'ethers'

export const FIELD_ORDER = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n

export const ZERO = 0n
export const ONE = 1n
export const TWO = 2n

export function bigmod(n: bigint, p: bigint) {
    return ((n % p) + p) % p
}

export function toBig(n: any): bigint {
    return BigInt(n)
}

export function randHex(n: number): string {
    return hexlify(randomBytes(n))
}

export function randBig(n: number): bigint {
    return toBig(randomBytes(n))
}

export function bigToHex(n: bigint): string {
    return zeroPadBytes('0x' + n.toString(16), 32)
}

export function randFs(): bigint {
    const r = randBig(32)
    return bigmod(r, FIELD_ORDER)
}

export function randFsHex(): string {
    const r = randBig(32)
    return bigToHex(bigmod(r, FIELD_ORDER))
}

export function randomHex(numBytes: number) {
    return BigInt(hexlify(randomBytes(numBytes)))
}

// export function randomNum(numBytes: number): number {
//     const bytes = randomBytes(numBytes)
//     return ethers.bigint.from(bytes).toNumber()
// }

// with zeros prepended to length bytes.
export function paddedHex(num: number, length: number): string {
    return zeroPadBytes('0x' + num.toString(16), length)
}

export function parseEvents(receipt: any): { [key: string]: any[] } {
    const obj: { [key: string]: any[] } = {}
    receipt.events.forEach((event: any) => {
        obj[event.event] = event.args
    })
    return obj
}

export function getParentLeaf(left: string, right: string) {
    return solidityPackedKeccak256(['bytes32', 'bytes32'], [left, right])
}

export function getZeroHash(zeroValue: any) {
    return solidityPackedKeccak256(['uint256'], [zeroValue])
}

export function defaultHashes(depth: number) {
    const zeroValue = 0
    const hashes = []
    hashes[0] = getZeroHash(zeroValue)
    for (let i = 1; i < depth; i++) {
        hashes[i] = getParentLeaf(hashes[i - 1], hashes[i - 1])
    }

    return hashes
}

export async function getMerkleRootFromLeaves(dataLeaves: string[], maxDepth: number) {
    let nodes: string[] = dataLeaves.slice()
    const defaultHashesForLeaves: string[] = defaultHashes(maxDepth)
    let odd = nodes.length & 1
    let n = (nodes.length + 1) >> 1
    let level = 0
    while (true) {
        let i = 0
        for (; i < n - odd; i++) {
            let j = i << 1
            nodes[i] = getParentLeaf(nodes[j], nodes[j + 1])
        }
        if (odd == 1) {
            nodes[i] = getParentLeaf(nodes[i << 1], defaultHashesForLeaves[level])
        }
        if (n == 1) {
            break
        }
        odd = n & 1
        n = (n + 1) >> 1
        level += 1
    }
    return nodes[0]
}
