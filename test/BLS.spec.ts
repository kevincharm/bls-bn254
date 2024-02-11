import { ethers } from 'hardhat'
import { BLSTest, BLSTest__factory } from '../typechain-types'
import { SignerWithAddress } from '@nomicfoundation/hardhat-ethers/signers'
import { getBytes, hexlify, keccak256, toUtf8Bytes } from 'ethers'
import { expect } from 'chai'
import crypto from 'node:crypto'
import { BlsBn254, kyberMarshalG1, kyberMarshalG2 } from '../lib/BlsBn254'

describe('BLS', () => {
    let mcl: BlsBn254
    const domain = 'BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_'
    before(async () => {
        mcl = await BlsBn254.create()
    })

    let deployer: SignerWithAddress
    let blsTest: BLSTest
    beforeEach(async () => {
        ;[deployer] = await ethers.getSigners()
        blsTest = await new BLSTest__factory(deployer).deploy()
    })

    it('correctly implements expandMsgTo96', async () => {
        for (let i = 0; i < 10; i++) {
            const msg = crypto.randomBytes(32)

            const [impl, gas] = await blsTest.test__expandMsgTo96(toUtf8Bytes(domain), msg)
            // console.log(`expandMsgTo96(${hexlify(msg)}) = ${hexlify(impl)}`)
            // console.log(`gas: ${gas}`) // 5967

            // vs mcl
            const refMcl = hexlify(mcl.expandMsg(toUtf8Bytes(domain), msg, 96))
            expect(impl).to.eq(refMcl)
        }
    })

    it('correctly implements hashToField', async () => {
        const msg = crypto.randomBytes(32)

        const [impl, gas] = await blsTest.test__hashToField(toUtf8Bytes(domain), msg)
        // console.log(`hashToField(${hexlify(domain)}, ${hexlify(msg)}) = ${impl}`)
        // console.log(`gas: ${gas}`) // 6491

        // vs mcl
        expect(impl).to.deep.eq(mcl.hashToField(toUtf8Bytes(domain), msg, 2))
    })

    it('correctly implements mapToPointFT', async () => {
        const msg = crypto.randomBytes(32)

        const u = mcl.hashToField(toUtf8Bytes(domain), msg, 2)
        const [p0Impl, p0Gas] = await blsTest.test__mapToPointFT(u[0])
        const [p1Impl, p1Gas] = await blsTest.test__mapToPointFT(u[1])

        // console.log(`mapToPoint(${u[0]}) = ${p0Impl}`)
        // console.log(`p0Gas: ${p0Gas}`) // ~25k
        // console.log(`mapToPoint(${u[1]}) = ${p1Impl}`)
        // console.log(`p1Gas: ${p1Gas}`) // ~33k

        // vs mcl
        const p0Mcl = mcl.serialiseG1Point(
            mcl.mapToPoint(('0x' + u[0].toString(16)) as `0x${string}`),
        )
        const p1Mcl = mcl.serialiseG1Point(
            mcl.mapToPoint(('0x' + u[1].toString(16)) as `0x${string}`),
        )
        expect(p0Impl).to.deep.eq(p0Mcl)
        expect(p1Impl).to.deep.eq(p1Mcl)
    })

    it('correctly implements hashToPoint', async () => {
        for (let i = 0; i < 10; i++) {
            const msg = crypto.randomBytes(32)

            const [hashImpl, gas] = await blsTest.test__hashToPoint(toUtf8Bytes(domain), msg)
            // console.log(`hashToPoint(${hexlify(msg)}) = ${hashImpl}`)
            // console.log(`gas: ${gas}`) // ~~ min 50706, max 72506

            // mcl
            const hashRef = mcl.serialiseG1Point(mcl.hashToPoint(toUtf8Bytes(domain), msg))
            expect(hashImpl).to.deep.eq(hashRef)
        }
    })

    it('hashToPoint vs kyber', async () => {
        const msg = '0x358518b89b9d3a2a832fe0cdcb2f4f2d66391113001a77e03b80dd720b8d1aab'
        const [hashImpl] = await blsTest.test__hashToPoint(toUtf8Bytes(domain), msg)
        expect(hashImpl).to.deep.eq([
            0x12d20d3bd0cee942b9c39eef725b6b55a25b0ac2acf3fb0c0c1afa3fd0426e03n,
            0x0260318df23be5936deefeae50fbe4a03c29b3cf7fbae115caf2e6ac518fc9f9n,
        ])
    })

    it('verify single', async () => {
        const { secretKey, pubKey } = mcl.createKeyPair()
        // const msg = hexlify(randomBytes(12)) as `0x${string}`
        // 64-bit round number, encoded in big-endian
        const roundNumber = new Uint8Array(8)
        roundNumber[7] = 1 // round = 1
        const msg = keccak256(roundNumber) as `0x${string}`
        const [[msgX, msgY]] = await blsTest.test__hashToPoint(toUtf8Bytes(domain), msg)
        const M = mcl.g1FromEvm(msgX, msgY)
        expect(M.isValid()).to.eq(true)
        // console.log('M', kyberMarshalG1(M))
        const { signature } = mcl.sign(M, secretKey)

        // Kyber serialised format
        // console.log('pub', kyberMarshalG2(pubKey))
        // console.log('sig', kyberMarshalG1(signature))

        const args = mcl.toArgs(pubKey, M, signature)
        expect(await blsTest.isOnCurveG1(args.signature)).to.eq(true) // 400 gas
        expect(await blsTest.isOnCurveG1(args.M)).to.eq(true) // 400 gas
        expect(await blsTest.isOnCurveG2(args.pubKey)).to.eq(true) // 865k gas
        expect(
            await blsTest.verifySingle(args.signature, args.pubKey, args.M).then((ret) => ret[0]),
        ).to.eq(true)
        // console.log('gas:', await blsTest.verifySingleGasCost(args.signature, args.pubKey, args.M))
    })

    it('drand outputs', async () => {
        // Get the serialised pubkey from https://<drand_api_endpoint/<chainhash>/info
        const groupPubKey =
            '23c481bf1f32e4ce0c421d9408959b0ba59ad2671a55ae271ee685cee48a516f2ce733a719d57494963388057c26dcf10ac9fe62fab4571948c729f0dbb44017124ee2ce5bbb9f131b1730e639d65d76819bd920984b86efc2142c52747208911c4aab034dd68e6c83daf63673df99bd3a6b8cf95f2079ba3b25378a02d618b3'
        const pkBytes = getBytes(`0x${groupPubKey}`)
        const pk = [
            pkBytes.slice(32, 64),
            pkBytes.slice(0, 32),
            pkBytes.slice(96, 128),
            pkBytes.slice(64, 96),
        ].map((pkBuf) => BigInt(hexlify(pkBuf))) as [bigint, bigint, bigint, bigint]
        const testVectors = [
            {
                round: 2,
                randomness: 'b85b88d6153fda7450fd32bb1db638ee322c360a0e5018bfc5f90e0a2c7555e7',
                signature:
                    '04f6e9c2b5877d798e742363d075999a5493c3eb96f7c7923c6115bcc8b534a010c8d7068d7738c39d499ce7b084b65d65c8223106e33da12b1b862bccdb9222',
            },
            {
                round: 3,
                randomness: 'c9250479ece6a858d1178c253eb9e6e98f96f694f2d7914cf2cde532e0762af9',
                signature:
                    '1f1f4bdf2b1f6e7f4e513f8d647e3d3787b24d12895e97b441bc0501a97cddf300d53e7cdfea87edb753a7c7fce429d69f1b615f25e5731a42c5a4191afac780',
            },
            {
                round: 5,
                randomness: '5e71b795f3d92c5d3c0c20f772d2e0d23ce676eb747b31ec9492a38ef1facc0c',
                signature:
                    '1c2c0318648cf803a366a5f41792675360ac1aad51089b0ca3f65cb2a017a4d9067170d60a5b98cc27a08e9483ab4456a7dba1362727973f501cad41521f4bf8',
            },
            // After reshare
            {
                round: 14,
                randomness: '83196572217d79d3253b92821607f99f811d06ec20bcca5710b4ecd688fb77b7',
                signature:
                    '08f9db2047599ec0281e84e5e5069c97b10229034ed51dcfd0c097b1058cdc5e0049dabfefe0f9c4fac4c4fe0dbece30802a67eece438e7642ea53a1b77851a8',
            },
            {
                round: 16,
                randomness: '869ea34eb5e95c07d39b0a034ff01bf909ca8f6bf6e139a503864816d5d580db',
                signature:
                    '2696b73cbf934115b102649b99b4bd2b664eb8918b47116b94ec34367ecea2b52687b788db60286fadff49d681ce8d8cf000a39240b3cb18060dbcf6f41e0bf6',
            },
        ]
        for (const { round, signature, randomness } of testVectors) {
            const sigBytes = getBytes(`0x${signature}`)
            const sig = [sigBytes.slice(0, 32), sigBytes.slice(32, 64)].map((sigBuf) =>
                BigInt(hexlify(sigBuf)),
            ) as [bigint, bigint]

            // Round number must be interpreted as a uint64, then fed into keccak256
            const roundBytes = getBytes('0x' + round.toString(16).padStart(16, '0'))
            const h = keccak256(roundBytes)
            const [M] = await blsTest.test__hashToPoint(toUtf8Bytes(domain), h)
            const [valid] = await blsTest.verifySingle(sig, pk, [M[0], M[1]])
            expect(valid).to.eq(true)
        }
    })
})
