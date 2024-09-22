import { hexlify } from 'ethers'

/**
 * Use noble-curves fromBytes instead!
 * **Kept here for testing purposes**
 * Convert Kyber's serialised G1 representation to the format accepted by the contract
 * @param g1 Serialised Kyber G1 point
 * @returns x and y coordinates in bigint
 */
export function unchecked_deserialiseKyberG1(g1: Uint8Array): [bigint, bigint] {
    const p = [g1.slice(0, 32), g1.slice(32, 64)].map((sigBuf) => BigInt(hexlify(sigBuf))) as [
        bigint,
        bigint,
    ]
    return p
}

/**
 * Use noble-curves fromBytes instead!
 * **Kept here for testing purposes**
 * Convert Kyber's serialised G2 representation to the format accepted by the contract
 * @param g2 Serialised Kyber G2 point
 * @returns x1, y1, x2, y2 coordinates in bigint
 */
export function unchecked_deserialiseKyberG2(g2: Uint8Array): [bigint, bigint, bigint, bigint] {
    const p = [g2.slice(32, 64), g2.slice(0, 32), g2.slice(96, 128), g2.slice(64, 96)].map((pBuf) =>
        BigInt(hexlify(pBuf)),
    ) as [bigint, bigint, bigint, bigint]
    return p
}
