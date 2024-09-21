import { hexlify } from 'ethers'
import { bn254 } from '../lib/bn254'

// yarn bls:newkey

async function main() {
    // const { pubKey, secretKey, _secretKey } = bls.createKeyPair()
    const secretKey = bn254.utils.randomPrivateKey()
    const pubKey = bn254.G2.ProjectivePoint.fromPrivateKey(secretKey).toHex()
    console.log(
        JSON.stringify(
            {
                secretKey: hexlify(secretKey),
                pubKey: pubKey,
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
