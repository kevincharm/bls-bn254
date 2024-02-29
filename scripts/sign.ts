import { getBytes, isHexString, toUtf8Bytes } from 'ethers'
import { BlsBn254, kyberMarshalG1, kyberMarshalG2 } from '../lib/BlsBn254'

// Sign with BLS on BN254
//
// Usage
//  yarn bls:sign "0xprivatekey" "message to sign" [optional DST]

const DEFAULT_DOMAIN = 'BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_'

async function main() {
    const bls = await BlsBn254.create()
    const _secretKey = process.argv[2] as `0x${string}`
    const msg = process.argv[2]
    const dst = process.argv[3] || DEFAULT_DOMAIN
    const msgBytes = isHexString(msg) ? getBytes(msg) : toUtf8Bytes(msg)
    const dstBytes = isHexString(dst) ? getBytes(dst) : toUtf8Bytes(dst)
    const point = bls.hashToPoint(dstBytes, msgBytes)
    const { secretKey, pubKey } = bls.createKeyPair(_secretKey)
    const { signature } = bls.sign(point, secretKey)
    console.log(
        JSON.stringify(
            {
                pubKey: kyberMarshalG2(pubKey),
                signature: kyberMarshalG1(signature),
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
