import { ethers } from 'hardhat'
import { BLSTest, BLSTest__factory } from '../typechain-types'
import { SignerWithAddress } from '@nomicfoundation/hardhat-ethers/signers'
import { hexlify, toUtf8Bytes } from 'ethers'
import { expect } from 'chai'
import crypto from 'node:crypto'
import * as noblehtc from '@noble/curves/abstract/hash-to-curve'
import { sha256 } from '@noble/hashes/sha256'
import { keccak_256 } from '@noble/hashes/sha3'
import { g1ToBig, hashToPoint, init, mapToPoint, setDomain } from './lib/mcl'
import { expandMsg, hashToField } from './lib/hash_to_field'
// const abi = ethers.AbiCoder.defaultAbiCoder()

describe('BLS', () => {
    before(async () => {
        await init()
    })

    let deployer: SignerWithAddress
    let blsTest: BLSTest
    beforeEach(async () => {
        ;[deployer] = await ethers.getSigners()
        blsTest = await new BLSTest__factory(deployer).deploy()
    })

    it('correctly implements expandMsgTo96', async () => {
        const domain = toUtf8Bytes('BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_').slice(0, 32) // TODO: don't slice
        for (let i = 0; i < 10; i++) {
            const msg = crypto.randomBytes(32)

            const impl = await blsTest.test__expandMsgTo96(domain, msg)
            // console.log(`expandMsgTo96(${hexlify(msg)}) = ${hexlify(impl)}`)

            // vs noble
            // TODO: This works with sha256, why not with keccak_256?
            // expect(impl).to.eq(hexlify(noblehtc.expand_message_xmd(msg, domain, 96, keccak_256)))
            // vs mcl
            const refMcl = hexlify(expandMsg(domain, msg, 96))
            expect(impl).to.eq(refMcl)
        }
    })

    it('correctly implements hashToField', async () => {
        const domain = toUtf8Bytes('BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_').slice(0, 32) // TODO: don't slice
        const msg = crypto.randomBytes(32)

        const impl = await blsTest.test__hashToField(domain, msg)
        console.log(`hashToField(${hexlify(domain)}, ${hexlify(msg)}) = ${impl}`)

        // vs mcl
        expect(impl).to.deep.eq(hashToField(domain, msg, 2))
    })

    it('correctly implements mapToPointFT', async () => {
        const domain = toUtf8Bytes('BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_').slice(0, 32) // TODO: don't slice
        const msg = crypto.randomBytes(32)

        const u = hashToField(domain, msg, 2)
        const p0Impl = await blsTest.test__mapToPointFT(u[0])
        const p1Impl = await blsTest.test__mapToPointFT(u[1])

        // console.log(`mapToPoint(${u[0]}) = ${p0Impl}`)
        // console.log(`mapToPoint(${u[1]}) = ${p1Impl}`)

        // vs mcl
        const p0Mcl = g1ToBig(mapToPoint('0x' + u[0].toString(16)))
        const p1Mcl = g1ToBig(mapToPoint('0x' + u[1].toString(16)))
        expect(p0Impl).to.deep.eq(p0Mcl)
        expect(p1Impl).to.deep.eq(p1Mcl)
    })

    it('correctly implements hashToPoint', async () => {
        const domain = toUtf8Bytes('BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_').slice(0, 32) // TODO: don't slice
        const msg = crypto.randomBytes(32)

        const hashImpl = await blsTest.test__hashToPoint(domain, msg)
        // console.log(`hashToPoint(${hexlify(msg)}) = ${hashImpl}`)

        // mcl
        setDomain(Buffer.from(domain).toString('utf-8'))
        const hashRef = g1ToBig(hashToPoint(hexlify(msg)))
        expect(hashImpl).to.deep.eq(hashRef)
    })
})
