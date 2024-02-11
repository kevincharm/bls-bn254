# BLS on BN254

BLS operations on BN254 instead of BLS12-381 in Solidity, including constant-time hash-to-curve using a specialised SW mapping for BN curves from [this paper](https://doi.org/10.1007/978-3-642-33481-8_1).

Most of the code in this repository has been taken from these repositories:

-   https://github.com/thehubbleproject/hubble-contracts
-   https://github.com/ChihChengLiang/bls_solidity_python
-   https://github.com/kilic/evmbls

## JavaScript Library

This repo also comes with an accompanying JS lib for creating signatures.

```sh
    npm install --save @kevincharm/bls-bn254 ethers@^6 mcl-wasm@1.4.0
```

## Readings

-   [BLS Signatures in Solidity by @liangcc](https://hackmd.io/@liangcc/bls-solidity)
-   [Indifferentiable Hashing to Barreto--Naehrig Curves by Fouque & Tibouchi](https://doi.org/10.1007/978-3-642-33481-8_1)
