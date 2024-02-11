import { toUtf8Bytes } from 'ethers'
import { BlsBn254, kyberMarshalG1, kyberMarshalG2 } from '../lib/BlsBn254'

const domain = toUtf8Bytes('BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_')

async function main() {
    const bls = await BlsBn254.create()
    const _secretKey = process.argv[2] as `0x${string}`
    const _msg = process.argv[3]
    const { secretKey, pubKey } = bls.createKeyPair(_secretKey)
    const msg = bls.hashToPoint(domain, toUtf8Bytes(_msg))
    const { signature } = bls.sign(msg, secretKey)
    console.log(
        JSON.stringify(
            {
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
