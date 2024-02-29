import { ethers } from 'hardhat'
import { BLSTest, BLSTest__factory } from '../typechain-types'
import { SignerWithAddress } from '@nomicfoundation/hardhat-ethers/signers'
import { getBytes, hexlify, keccak256, sha256, toUtf8Bytes, zeroPadValue } from 'ethers'
import { expect } from 'chai'
import crypto from 'node:crypto'
import { BlsBn254, kyberG1ToEvm, kyberG2ToEvm, toHex } from '../lib/BlsBn254'
import SVDW_TEST_VECTORS from './vectors/svdw'
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve'
import { keccak_256 } from '@noble/hashes/sha3'

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

    it('correctly implements SvdW', async () => {
        for (const { u, p } of SVDW_TEST_VECTORS.slice(500, 800)) {
            const [pImpl] = await blsTest.test__mapToPoint(u)
            expect(pImpl).to.deep.eq(p)

            const g1 = mcl.mapToPoint(toHex(BigInt(u)))
            expect(g1.getX().getStr(16)).to.eq(BigInt(p[0]).toString(16))
            expect(g1.getY().getStr(16)).to.eq(BigInt(p[1]).toString(16))
        }

        // fuzz gas
        let iterations = 100n
        let sumGasCost = 0n
        for (let i = 0n; i < iterations; i++) {
            const [, gasCost] = await blsTest.test__mapToPoint(pickRandomF())
            sumGasCost += gasCost
        }
        const meanGasCost = sumGasCost / iterations
        console.log(`[mapToPoint] mean gas cost: ${meanGasCost}`)
    })

    it('correctly implements expandMsgTo96', async () => {
        let sumGasCost = 0n
        const iterations = 100n
        for (let i = 0n; i < iterations; i++) {
            const msgByteLen = 16 + Math.floor(Math.random() * 192)
            const msg = crypto.randomBytes(msgByteLen)
            // const msg = getBytes('0xaf6c1f30b2f3f2fd448193f90d6fb55b544a')

            const [impl, gas] = await blsTest.test__expandMsgTo96(toUtf8Bytes(domain), msg)
            // console.log(`expandMsgTo96(${hexlify(msg)}) = ${hexlify(impl)}`)
            // console.log(`gas: ${gas}`) // 5967
            sumGasCost += gas

            // vs mcl
            const refMcl = hexlify(mcl.expandMsg(toUtf8Bytes(domain), msg, 96))
            expect(impl).to.eq(refMcl)
            // vs noble
            expect(impl).to.eq(
                hexlify(
                    expand_message_xmd(new Uint8Array(msg), toUtf8Bytes(domain), 96, keccak_256),
                ),
            )
        }
        console.log(`[expandMsgTo96] mean gas cost: ${sumGasCost / iterations}`)
    })

    it('correctly implements hashToField', async () => {
        let sumGasCost = 0n
        const iterations = 100n
        for (let i = 0n; i < iterations; i++) {
            const msgByteLen = 16 + Math.floor(Math.random() * 192)
            const msg = crypto.randomBytes(msgByteLen)

            const [impl, gas] = await blsTest.test__hashToField(toUtf8Bytes(domain), msg)
            // console.log(`gas: ${gas}`) // 6491
            sumGasCost += gas

            // Print for kyber tests
            // console.log(
            //     `{\n\tMsg: "${hexlify(msg).slice(2)}",\n\tRefX: "${zeroPadValue(
            //         toHex(impl[0]),
            //         32,
            //     ).slice(2)}",\n\tRefY: "${zeroPadValue(toHex(impl[1]), 32).slice(2)}",\n},`,
            // )

            // vs mcl
            expect(impl).to.deep.eq(mcl.hashToField(toUtf8Bytes(domain), msg, 2))
        }
        console.log(`[hashToField] mean gas cost: ${sumGasCost / iterations}`)
    })

    it('correctly implements hashToPoint', async () => {
        let sumGasCost = 0n
        const iterations = 100n
        for (let i = 0n; i < iterations; i++) {
            const msg = crypto.randomBytes(32)

            const [hashImpl, gas] = await blsTest.test__hashToPoint(toUtf8Bytes(domain), msg)
            // console.log(`hashToPoint(${hexlify(msg)}) = ${hashImpl}`)
            // console.log(`gas: ${gas}`) // ~~ min 50706, max 72506
            sumGasCost += gas

            // mcl
            const hashRef = mcl.serialiseG1Point(mcl.hashToPoint(toUtf8Bytes(domain), msg))
            expect(hashImpl).to.deep.eq(hashRef)
        }
        console.log(`[hashToPoint] mean gas cost: ${sumGasCost / iterations}`)
    })

    it('correct verifies a BLS sig from mcl', async () => {
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
        expect(await blsTest.test__isOnCurveG1(args.signature).then((ret) => ret[0])).to.eq(true) // 400 gas
        expect(await blsTest.test__isOnCurveG1(args.M).then((ret) => ret[0])).to.eq(true) // 400 gas
        expect(await blsTest.test__isOnCurveG2(args.pubKey).then((ret) => ret[0])).to.eq(true) // 865k gas
        const [isValid, callSuccess, verifySingleGasCost] = await blsTest.test__verifySingle(
            args.signature,
            args.pubKey,
            args.M,
        )
        expect(isValid && callSuccess).to.eq(true)
        console.log('[verify] gas:', verifySingleGasCost)

        const invalidSig = args.signature.map((v) => v + 1n) as [bigint, bigint]
        expect(
            await blsTest.test__verifySingle(invalidSig, args.pubKey, args.M).then((ret) => ret[0]),
        ).to.eq(false)
    })

    it('verifies only valid sigs', async () => {
        const round = 2
        const roundBytes = new Uint8Array(8)
        roundBytes[7] = round
        const validSig = kyberG1ToEvm(
            getBytes(
                '0x147d98a0bbadf6d1b2115441654c446039ed61ff2f71abefcdb8aefbfd81c37121bd020cd1814033782226408aa7b0ac86fd1682755c39a023282d0031635b7d',
            ),
        )
        const invalidSig = kyberG1ToEvm(
            getBytes(
                '0x007d98a0bbadf6d1b2115441654c446039ed61ff2f71abefcdb8aefbfd81c37121bd020cd1814033782226408aa7b0ac86fd1682755c39a023282d0031635b7d',
            ),
        )
        const xFieldOverflowSig = kyberG1ToEvm(
            getBytes(
                '0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd480000000000000000000000000000000000000000000000000000000000000000',
            ),
        )
        const yFieldOverflowSig = kyberG1ToEvm(
            getBytes(
                '0x000000000000000000000000000000000000000000000000000000000000000030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd48',
            ),
        )

        expect(await blsTest.test__isValidSignature(validSig).then((ret) => ret[0])).to.eq(true)
        expect(await blsTest.test__isValidSignature(invalidSig).then((ret) => ret[0])).to.eq(false)
        expect(await blsTest.test__isValidSignature(xFieldOverflowSig).then((ret) => ret[0])).to.eq(
            false,
        )
        expect(await blsTest.test__isValidSignature(yFieldOverflowSig).then((ret) => ret[0])).to.eq(
            false,
        )
    })

    it('verifies only valid pubkeys', async () => {
        const validPubKey = kyberG2ToEvm(
            getBytes(
                '0x22c42968fc34de59eed98be1ac7ecaca63ed067a2f09b28c1ff604f57f33bf1218b1c0651f1c340ce29c7f1b806e395d0433b9ab531a7cfd6b3b69026db8a9ff1e9786e80c8c5f3791803823ca18fb3beedb866ad7f57b67fc95abc832ab54d901c7b62e8f4d7f668912bd05e9f5f1e106a85a195557c1d009f52511ed00278c',
            ),
        )
        const invalidPubKey = kyberG2ToEvm(
            getBytes(
                '0x22c42968fc34de59eed98be1ac7ecaca63ed067a2f09b28c1ff604f57f33bf1218b1c0651f1c340ce29c7f1b806e395d0433b9ab531a7cfd6b3b69026db8a9ff1e9786e80c8c5f3791803823ca18fb3beedb866ad7f57b67fc95abc832ab54d901c7b62e8f4d7f668912bd05e9f5f1e106a85a195557c1d009f52511ed002700',
            ),
        )
        const xFieldOverflowSig = kyberG2ToEvm(
            getBytes(
                '0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
            ),
        )
        const yFieldOverflowSig = kyberG2ToEvm(
            getBytes(
                '0x000000000000000000000000000000000000000000000000000000000000000030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
            ),
        )
        const zFieldOverflowSig = kyberG2ToEvm(
            getBytes(
                '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd480000000000000000000000000000000000000000000000000000000000000000',
            ),
        )
        const wFieldOverflowSig = kyberG2ToEvm(
            getBytes(
                '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd48',
            ),
        )

        expect(await blsTest.test__isValidPublicKey(validPubKey).then((ret) => ret[0])).to.eq(true)
        expect(await blsTest.test__isValidPublicKey(invalidPubKey).then((ret) => ret[0])).to.eq(
            false,
        )
        expect(await blsTest.test__isValidPublicKey(xFieldOverflowSig).then((ret) => ret[0])).to.eq(
            false,
        )
        expect(await blsTest.test__isValidPublicKey(yFieldOverflowSig).then((ret) => ret[0])).to.eq(
            false,
        )
        expect(await blsTest.test__isValidPublicKey(zFieldOverflowSig).then((ret) => ret[0])).to.eq(
            false,
        )
        expect(await blsTest.test__isValidPublicKey(wFieldOverflowSig).then((ret) => ret[0])).to.eq(
            false,
        )
    })

    it('correctly implements hashToPoint vs kyber', async () => {
        const kyberOutputs = [
            {
                msg: 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks',
                g1: '0x09f71d403b4f8d7c7b9ba053d7759374885c1388201a4707841532ea11b0302024f8f78ac1a174f0b013aa29a4eef8e0e09ace5c859d75509cd9918a28f0eb21',
            },
            {
                msg: 'abc',
                g1: '0x263d6232dfe15bdc1b2d0a446e75f73a5e704e31a8d5a9f0ba9a1c685cde7ffd2a80c257aae3c99df125a2ffddb630a82d1284c8516fdd3c81758de714c05dc0',
            },
        ] as const
        for (const { msg, g1 } of kyberOutputs) {
            const [hashImpl] = await blsTest.test__hashToPoint(
                toUtf8Bytes(domain),
                toUtf8Bytes(msg),
            )
            expect(hashImpl).to.deep.eq(kyberG1ToEvm(getBytes(g1)))
        }
    })

    it('drand outputs', async () => {
        // Get the serialised pubkey from https://<drand_api_endpoint/<chainhash>/info
        const groupPubKey =
            '22c42968fc34de59eed98be1ac7ecaca63ed067a2f09b28c1ff604f57f33bf1218b1c0651f1c340ce29c7f1b806e395d0433b9ab531a7cfd6b3b69026db8a9ff1e9786e80c8c5f3791803823ca18fb3beedb866ad7f57b67fc95abc832ab54d901c7b62e8f4d7f668912bd05e9f5f1e106a85a195557c1d009f52511ed00278c'
        const pkBytes = getBytes(`0x${groupPubKey}`)
        const pk = kyberG2ToEvm(pkBytes)
        const testVectors = [
            {
                round: 2,
                randomness: 'f05d8117b23685543bbe4ff64e37c2ebc331278246f96ea2c3ddd44bbc3685d2',
                signature:
                    '281d32d8ffeb9842d750976b059c533d88236e243db9c8072ead1fc70a8b3b510d287a4664a5f9012d5936be1b4465e2d45fd1f4ed40203c47cdc8a927776e45',
            },
            {
                round: 3,
                randomness: '612e133fed9417332621ae77d2ed4ec8f6d37c58cfdab46bc46ec45792bfa363',
                signature:
                    '17b189f24f251e472fc995a3bda9f892422395f07ca3dfd2cec71a7b1b5f02a02fc3c10eed1dd9f77791430799c198444b880a7b8c29489225e0d2728c154b7b',
            },
            {
                round: 5,
                randomness: '11e270db99916cfa2d78674decfc67d3106a12a98872231660be6ba06fbaebbe',
                signature:
                    '111ec1ea8e210acb867434b3a59a1842f2fe7924a795d248d343807f677f5086166215f966e2bf70e79e308f3a66ab6ab462ec13977471508320b8d101695d0a',
            },
            // After reshare
            {
                round: 14,
                randomness: 'f47a9398f3a4c14face1e8e302320352aba6f3e1a50454f3360e3de742640800',
                signature:
                    '2c03eb7e9ce94f17aaa31b14105c6bdb8aa209b14ef2ded13582991c6b6e2f481af1534e9da8de69e1dd652c101ff19dc55aebd9e25749a9314eea7468f0b36d',
            },
            {
                round: 16,
                randomness: 'fec4debe4c429a22a19b2692f5f7be83b7f3e1fc66e4cda718971a25b96a318e',
                signature:
                    '26b977a91b9eb4af403ea9f7bd78ceb1fc372184b151910b73eb453df52397562350a3cd30ed8157fbe0a0fb37d55ad91b420a53b8fe66d3c371ae72bbf2e00f',
            },
            {
                round: 17,
                randomness: '0d6b449f1b680c5172af8902451c5f9e0561c40876677dd478731fd614df96ca',
                signature:
                    '2a0eea50b7cf25eddd5f5daa87f57e80d725de480bdac391027229351ac25cc526e3949ca6f62ddf6e9384795bf80a0f471e51299c2178c0b68bf07cb19f1c34',
            },
        ]
        for (const { round, signature, randomness } of testVectors) {
            const sigBytes = getBytes(`0x${signature}`)
            const sig = kyberG1ToEvm(sigBytes)

            const [isValidSig] = await blsTest.test__isValidSignature(sig)
            expect(isValidSig).to.eq(true)

            // Round number must be interpreted as a uint64, then fed into keccak256
            const roundBytes = getBytes('0x' + round.toString(16).padStart(16, '0'))
            const h = keccak256(roundBytes)
            const [M] = await blsTest.test__hashToPoint(toUtf8Bytes(domain), h)
            const [valid] = await blsTest.test__verifySingle(sig, pk, [M[0], M[1]])
            expect(valid).to.eq(true)

            // NB: drand hashes signatures with sha256 to produce `randomness`,
            // but we can technically use any hash onchain as the verifiability of
            // the randomness only depends on the validity of the signature.
            expect(sha256(sigBytes)).to.eq(hexlify(`0x${randomness}`))
        }
    })
})

/// Pick random element from BN254 F_p, accounting for modulo bias
function pickRandomF(): bigint {
    for (;;) {
        const rand32 = crypto.getRandomValues(new Uint8Array(32)) // 256-bit
        const f = BigInt(hexlify(rand32))
        if (f < 21888242871839275222246405745257275088696311157297823662689037894645226208583n) {
            return f
        }
    }
}
