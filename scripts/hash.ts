import { getBytes, isHexString, toBeHex, toUtf8Bytes, zeroPadValue } from 'ethers'
import { BlsBn254 } from '../lib/BlsBn254'

// hash-to-point
//
// regular string
//  yarn bls:hash "message to hash"
//
// hex bytes (make sure it's even-length)
//  yarn bls:hash 0xdeadbeef

const DEFAULT_DOMAIN = toUtf8Bytes('BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_') // DST used in drand BN254 for hashing to G1

async function main() {
    const bls = await BlsBn254.create()
    const msg = process.argv[2]
    const msgBytes = isHexString(msg) ? getBytes(msg) : toUtf8Bytes(msg)
    const hash = bls.serialiseG1Point(bls.hashToPoint(DEFAULT_DOMAIN, msgBytes))

    console.log(
        'G1',
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
