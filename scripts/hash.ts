import { getBytes, isHexString, toBeHex, toUtf8Bytes } from 'ethers'
import { BlsBn254 } from '../lib/BlsBn254'

// hash-to-point
//
// regular string
//  yarn bls:hash "message to hash"
//
// hex bytes (make sure it's even-length)
//  yarn bls:hash 0xdeadbeef
//
// with optional DST
//  yarn bls:hash 0xdeadbeef "custom domain separator"

const DEFAULT_DOMAIN = 'BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_' // DST used in drand BN254 for hashing to G1

async function main() {
    const bls = await BlsBn254.create()
    const msg = process.argv[2]
    const dst = process.argv[3] || DEFAULT_DOMAIN
    const msgBytes = isHexString(msg) ? getBytes(msg) : toUtf8Bytes(msg)
    const dstBytes = isHexString(dst) ? getBytes(dst) : toUtf8Bytes(dst)
    const hash = bls.serialiseG1Point(bls.hashToPoint(dstBytes, msgBytes))

    console.log(
        `G1("${dst}")`,
        JSON.stringify(
            {
                x: toBeHex(hash[0], 32),
                y: toBeHex(hash[1], 32),
            },
            null,
            4,
        ),
    )
}

main()
    .then(() => {
        process.exit(0)
    })
    .catch((err) => {
        console.error(err)
        process.exit(1)
    })
