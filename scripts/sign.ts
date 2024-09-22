import { getBytes, hexlify, isHexString, toUtf8Bytes } from 'ethers'
import { bn254 } from '@kevincharm/noble-bn254-drand'

// Sign with BLS on BN254
//
// Usage
//  yarn bls:sign "0xprivatekey" "message to sign" [optional DST]

const DEFAULT_DOMAIN = 'BLS_SIG_BN254G1_XMD:KECCAK-256_SVDW_RO_NUL_'

async function main() {
    const _secretKey = process.argv[2] as `0x${string}`
    const secretKey = BigInt(_secretKey)
    const msg = process.argv[2]
    const dst = process.argv[3] || DEFAULT_DOMAIN
    const msgBytes = isHexString(msg) ? getBytes(msg) : toUtf8Bytes(msg)
    const dstBytes = isHexString(dst) ? getBytes(dst) : toUtf8Bytes(dst)
    const pubKey = bn254.G2.ProjectivePoint.fromPrivateKey(secretKey).toHex()
    const signature = bn254.signShortSignature(msgBytes, secretKey, {
        DST: dstBytes,
    })
    console.log(
        JSON.stringify(
            {
                pubKey,
                signature: hexlify(signature),
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
