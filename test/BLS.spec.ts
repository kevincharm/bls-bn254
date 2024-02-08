import { ethers } from 'hardhat'
import { BLSTest, BLSTest__factory } from '../typechain-types'
import { SignerWithAddress } from '@nomicfoundation/hardhat-ethers/signers'
import { hexlify, toUtf8Bytes } from 'ethers'
import { expect } from 'chai'
import crypto from 'node:crypto'
const abi = ethers.AbiCoder.defaultAbiCoder()

describe('BLS', () => {
    let deployer: SignerWithAddress
    let blsTest: BLSTest
    beforeEach(async () => {
        ;[deployer] = await ethers.getSigners()
        blsTest = await new BLSTest__factory(deployer).deploy()
    })

    it('correctly implements ref expandMsgTo96', async () => {
        const domain = toUtf8Bytes('BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_').slice(0, 32) // TODO: don't slice
        console.log('(utf8)domain:', hexlify(domain))
        const [opt, ref] = await blsTest.test__expandMsgTo96(domain, crypto.randomBytes(32))
        console.log('opt', opt)
        console.log('ref', ref)
        expect(opt === ref).to.eq(true)
    })
})
