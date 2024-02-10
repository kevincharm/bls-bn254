import { ethers } from 'hardhat'
import { BLSTest, BLSTest__factory } from '../typechain-types'
import { SignerWithAddress } from '@nomicfoundation/hardhat-ethers/signers'
import { hexlify, toUtf8Bytes } from 'ethers'
import { expect } from 'chai'
import crypto from 'node:crypto'
import { BlsBn254 } from '../lib/BlsBn254'

describe('BLS', () => {
    let mcl: BlsBn254
    const domain = 'BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_'
    before(async () => {
        mcl = await BlsBn254.create(domain)
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
})
