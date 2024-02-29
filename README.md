# BLS on BN254

BLS operations on BN254 in Solidity, including constant-time hash-to-curve using a the general Shallue-van de Woestijne encoding described in [RFC9380 Section 6.6.1](https://datatracker.ietf.org/doc/html/rfc9380#section-6.6.1).

A lot of the code in this repository has been taken from these repositories:

-   https://github.com/thehubbleproject/hubble-contracts
-   https://github.com/ChihChengLiang/bls_solidity_python
-   https://github.com/kilic/evmbls
-   https://github.com/kevincharm/draft-irtf-cfrg-hash-to-curve

## JavaScript Library

This repo also comes with an accompanying JS lib for creating signatures.

```sh
    npm install --save @kevincharm/bls-bn254 ethers@^6 mcl-wasm@1.4.0
```

## Utilities

### Hash-to-point

Hash a regular string

```sh
    yarn bls:hash "message to hash"
```

Hash hex bytes

```sh
    yarn bls:hash 0xdeadbeef
```

## Readings

-   [BLS Signatures in Solidity by @liangcc](https://hackmd.io/@liangcc/bls-solidity)
-   [RFC9380](https://datatracker.ietf.org/doc/html/rfc9380)
