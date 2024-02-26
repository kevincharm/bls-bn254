// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {ModexpInverse, ModexpSqrt} from "./ModExp.sol";

/// @title  Boneh–Lynn–Shacham (BLS) signature scheme on Barreto-Naehrig 254 bit curve (BN-254)
/// @notice We use BLS signature aggregation to reduce the size of signature data to store on chain.
/// @dev We use G1 points for signatures and messages, and G2 points for public keys
/// @dev Adapted from https://github.com/thehubbleproject/hubble-contracts
library BLS {
    // Field order
    // prettier-ignore
    uint256 private constant N = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Negated generator of G2
    // prettier-ignore
    uint256 private constant N_G2_X1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    // prettier-ignore
    uint256 private constant N_G2_X0 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    // prettier-ignore
    uint256 private constant N_G2_Y1 = 17805874995975841540914202342111839520379459829704422454583296818431106115052;
    // prettier-ignore
    uint256 private constant N_G2_Y0 = 13392588948715843804641432497768002650278120570034223513918757245338268106653;

    // prettier-ignore
    uint256 private constant T24 = 0x1000000000000000000000000000000000000000000000000;
    // prettier-ignore
    uint256 private constant MASK24 = 0xffffffffffffffffffffffffffffffffffffffffffffffff;

    /// @notice Param A of BN254
    uint256 private constant A = 0;
    /// @notice Param B of BN254
    uint256 private constant B = 3;
    /// @notice Param Z for SVDW over E
    uint256 private constant Z = 1;
    /// @notice g(Z) where g(x) = x^3 + 3
    uint256 private constant C1 = 0x4;
    /// @notice -Z / 2 (mod N)
    uint256 private constant C2 =
        0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3;
    /// @notice C3 = sqrt(-g(Z) * (3 * Z^2 + 4 * A)) (mod N)
    ///     and sgn0(C3) == 0
    uint256 private constant C3 =
        0x16789af3a83522eb353c98fc6b36d713d5d8d1cc5dffffffa;
    /// @notice 4 * -g(Z) / (3 * Z^2 + 4 * A) (mod N)
    uint256 private constant C4 =
        0x10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9bd;
    /// @notice (N - 1) / 2
    uint256 private constant C5 =
        0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3;

    error BNAddFailed(uint256[4] input);
    error InvalidFieldElement(uint256 x);
    error MapToPointFailed(uint256 noSqrt);
    error InvalidDSTLength(bytes dst);
    error ModExpFailed(uint256 base, uint256 exponent, uint256 modulus);

    function verifySingle(
        uint256[2] memory signature,
        uint256[4] memory pubkey,
        uint256[2] memory message
    ) internal view returns (bool pairingSuccess, bool callSuccess) {
        uint256[12] memory input = [
            signature[0],
            signature[1],
            N_G2_X1,
            N_G2_X0,
            N_G2_Y1,
            N_G2_Y0,
            message[0],
            message[1],
            pubkey[1],
            pubkey[0],
            pubkey[3],
            pubkey[2]
        ];
        uint256[1] memory out;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            callSuccess := staticcall(
                sub(gas(), 2000),
                8,
                input,
                384,
                out,
                0x20
            )
        }
        return (out[0] != 0, callSuccess);
    }

    /// @notice Hash to BN254 G1
    /// @param domain Domain separation tag
    /// @param message Message to hash
    /// @return Point in G1
    function hashToPoint(
        bytes memory domain,
        bytes memory message
    ) internal view returns (uint256[2] memory) {
        uint256[2] memory u = hashToField(domain, message);
        uint256[2] memory p0 = mapToPoint(u[0]);
        uint256[2] memory p1 = mapToPoint(u[1]);
        uint256[4] memory bnAddInput;
        bnAddInput[0] = p0[0];
        bnAddInput[1] = p0[1];
        bnAddInput[2] = p1[0];
        bnAddInput[3] = p1[1];
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, bnAddInput, 128, p0, 64)
        }
        if (!success) revert BNAddFailed(bnAddInput);
        return p0;
    }

    /// @notice Check if `signature` is a valid signature
    /// @param signature Signature to check
    function isValidSignature(
        uint256[2] memory signature
    ) internal pure returns (bool) {
        if ((signature[0] >= N) || (signature[1] >= N)) {
            return false;
        } else {
            return isOnCurveG1(signature);
        }
    }

    /// @notice Check if `publicKey` is a valid public key
    /// @param publicKey PK to check
    function isValidPublicKey(
        uint256[4] memory publicKey
    ) internal pure returns (bool) {
        if (
            (publicKey[0] >= N) ||
            (publicKey[1] >= N) ||
            (publicKey[2] >= N || (publicKey[3] >= N))
        ) {
            return false;
        } else {
            return isOnCurveG2(publicKey);
        }
    }

    /// @notice Check if `point` is in G1
    /// @param point Point to check
    function isOnCurveG1(
        uint256[2] memory point
    ) internal pure returns (bool _isOnCurve) {
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let t0 := mload(point)
            let t1 := mload(add(point, 32))
            let t2 := mulmod(t0, t0, N)
            t2 := mulmod(t2, t0, N)
            t2 := addmod(t2, 3, N)
            t1 := mulmod(t1, t1, N)
            _isOnCurve := eq(t1, t2)
        }
    }

    /// @notice Check if `point` is in G2
    /// @param point Point to check
    function isOnCurveG2(
        uint256[4] memory point
    ) internal pure returns (bool _isOnCurve) {
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            // x0, x1
            let t0 := mload(point)
            let t1 := mload(add(point, 32))
            // x0 ^ 2
            let t2 := mulmod(t0, t0, N)
            // x1 ^ 2
            let t3 := mulmod(t1, t1, N)
            // 3 * x0 ^ 2
            let t4 := add(add(t2, t2), t2)
            // 3 * x1 ^ 2
            let t5 := addmod(add(t3, t3), t3, N)
            // x0 * (x0 ^ 2 - 3 * x1 ^ 2)
            t2 := mulmod(add(t2, sub(N, t5)), t0, N)
            // x1 * (3 * x0 ^ 2 - x1 ^ 2)
            t3 := mulmod(add(t4, sub(N, t3)), t1, N)

            // x ^ 3 + b
            t0 := addmod(
                t2,
                0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5,
                N
            )
            t1 := addmod(
                t3,
                0x009713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2,
                N
            )

            // y0, y1
            t2 := mload(add(point, 64))
            t3 := mload(add(point, 96))
            // y ^ 2
            t4 := mulmod(addmod(t2, t3, N), addmod(t2, sub(N, t3), N), N)
            t3 := mulmod(shl(1, t2), t3, N)

            // y ^ 2 == x ^ 3 + b
            _isOnCurve := and(eq(t0, t4), eq(t1, t3))
        }
    }

    /// @notice sqrt(xx) mod N
    /// @param xx Input
    function sqrt(uint256 xx) internal pure returns (uint256 x, bool hasRoot) {
        x = ModexpSqrt.run(xx);
        hasRoot = mulmod(x, x, N) == xx;
    }

    /// @notice a^{-1} mod N
    /// @param a Input
    function inverse(uint256 a) internal pure returns (uint256) {
        return ModexpInverse.run(a);
    }

    /// @notice Hash a message to the field
    /// @param domain Domain separation tag
    /// @param message Message to hash
    function hashToField(
        bytes memory domain,
        bytes memory message
    ) internal pure returns (uint256[2] memory) {
        bytes memory _msg = expandMsgTo96(domain, message);
        uint256 u0;
        uint256 u1;
        uint256 a0;
        uint256 a1;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let p := add(_msg, 24)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 48)
            u0 := and(mload(p), MASK24)
            a0 := addmod(mulmod(u1, T24, N), u0, N)
            p := add(_msg, 72)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 96)
            u0 := and(mload(p), MASK24)
            a1 := addmod(mulmod(u1, T24, N), u0, N)
        }
        return [a0, a1];
    }

    /// @notice Expand arbitrary message to 96 pseudorandom bytes, as described
    ///     in rfc9380 section 5.3.1, using H = keccak256.
    /// @param domain Domain separation tag
    /// @param message Message to expand
    function expandMsgTo96(
        bytes memory domain,
        bytes memory message
    ) internal pure returns (bytes memory) {
        uint256 t1 = domain.length;
        if (t1 > 255) revert InvalidDSTLength(domain);

        // zero<64>|msg<var>|lib_str<2>|I2OSP(0, 1)<1>|dst<var>|dst_len<1>
        uint256 t0 = message.length;
        bytes memory msg0 = new bytes(t1 + t0 + 64 + 4);
        bytes memory out = new bytes(96);

        // b0
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let p := add(msg0, 96)

            let z := 0
            for {

            } lt(z, t0) {
                z := add(z, 32)
            } {
                mstore(add(p, z), mload(add(message, add(z, 32))))
            }
            p := add(p, t0)

            mstore8(p, 0)
            p := add(p, 1)
            mstore8(p, 96)
            p := add(p, 1)
            mstore8(p, 0)
            p := add(p, 1)

            let words := div(t1, 32)
            let d := add(domain, 32)
            // per-word
            for {
                let i := 0
            } lt(i, words) {
                i := add(i, 1)
            } {
                mstore(p, mload(d))
                p := add(p, 32)
                d := add(d, 32)
            }
            // per-byte
            let rem := mod(t1, 32)
            for {
                let i := 0
            } lt(i, rem) {
                i := add(i, 1)
            } {
                mstore8(p, shr(248, mload(d)))
                p := add(p, 1)
                d := add(d, 1)
            }
            // store length
            mstore8(p, t1)

            let b0 := keccak256(add(msg0, 32), mload(msg0))

            t0 := add(t1, 34)

            mstore(msg0, t0)

            // b1
            mstore(add(msg0, 32), b0)
            mstore8(add(msg0, 64), 1)

            p := add(msg0, 65)
            words := div(t1, 32)
            d := add(domain, 32)
            // per-word
            for {
                let i := 0
            } lt(i, words) {
                i := add(i, 1)
            } {
                mstore(p, mload(d))
                p := add(p, 32)
                d := add(d, 32)
            }
            // per-byte
            rem := mod(t1, 32)
            for {
                let i := 0
            } lt(i, rem) {
                i := add(i, 1)
            } {
                mstore8(p, shr(248, mload(d)))
                p := add(p, 1)
                d := add(d, 1)
            }
            // store length
            mstore8(p, t1)

            let bi := keccak256(add(msg0, 32), mload(msg0))

            mstore(add(out, 32), bi)

            // b2
            let t := xor(b0, bi)
            mstore(add(msg0, 32), t)
            mstore8(add(msg0, 64), 2)

            p := add(msg0, 65)
            words := div(t1, 32)
            d := add(domain, 32)
            // per-word
            for {
                let i := 0
            } lt(i, words) {
                i := add(i, 1)
            } {
                mstore(p, mload(d))
                p := add(p, 32)
                d := add(d, 32)
            }
            // per-byte
            rem := mod(t1, 32)
            for {
                let i := 0
            } lt(i, rem) {
                i := add(i, 1)
            } {
                mstore8(p, shr(248, mload(d)))
                p := add(p, 1)
                d := add(d, 1)
            }
            // store length
            mstore8(p, t1)

            bi := keccak256(add(msg0, 32), mload(msg0))
            mstore(add(out, 64), bi)

            // b3
            t := xor(b0, bi)
            mstore(add(msg0, 32), t)
            mstore8(add(msg0, 64), 3)

            p := add(msg0, 65)
            words := div(t1, 32)
            d := add(domain, 32)
            // per-word
            for {
                let i := 0
            } lt(i, words) {
                i := add(i, 1)
            } {
                mstore(p, mload(d))
                p := add(p, 32)
                d := add(d, 32)
            }
            // per-byte
            rem := mod(t1, 32)
            for {
                let i := 0
            } lt(i, rem) {
                i := add(i, 1)
            } {
                mstore8(p, shr(248, mload(d)))
                p := add(p, 1)
                d := add(d, 1)
            }
            // store length
            mstore8(p, t1)

            bi := keccak256(add(msg0, 32), mload(msg0))
            mstore(add(out, 96), bi)
        }

        return out;
    }

    /// @notice Map field element to E using SvdW
    /// @param u Field element to map
    /// @return p Point on curve
    function mapToPoint(uint256 u) internal view returns (uint256[2] memory p) {
        if (u >= N) revert InvalidFieldElement(u);

        uint256 tv1 = mulmod(mulmod(u, u, N), C1, N);
        uint256 tv2 = addmod(1, tv1, N);
        tv1 = addmod(1, N - tv1, N);
        uint256 tv3 = inverse(mulmod(tv1, tv2, N));
        uint256 tv5 = mulmod(mulmod(mulmod(u, tv1, N), tv3, N), C3, N);
        uint256 x1 = addmod(C2, N - tv5, N);
        uint256 x2 = addmod(C2, tv5, N);
        uint256 tv7 = mulmod(tv2, tv2, N);
        uint256 tv8 = mulmod(tv7, tv3, N);
        uint256 x3 = addmod(Z, mulmod(C4, mulmod(tv8, tv8, N), N), N);

        bool hasRoot;
        uint256 gx;
        if (legendre(g(x1)) == 1) {
            p[0] = x1;
            gx = g(x1);
            (p[1], hasRoot) = sqrt(gx);
            if (!hasRoot) revert MapToPointFailed(gx);
        } else if (legendre(g(x2)) == 1) {
            p[0] = x2;
            gx = g(x2);
            (p[1], hasRoot) = sqrt(gx);
            if (!hasRoot) revert MapToPointFailed(gx);
        } else {
            p[0] = x3;
            gx = g(x3);
            (p[1], hasRoot) = sqrt(gx);
            if (!hasRoot) revert MapToPointFailed(gx);
        }
        if (sgn0(u) != sgn0(p[1])) {
            p[1] = N - p[1];
        }
    }

    /// @notice g(x) = y^2 = x^3 + 3
    function g(uint256 x) private pure returns (uint256) {
        return addmod(mulmod(mulmod(x, x, N), x, N), B, N);
    }

    /// @notice https://datatracker.ietf.org/doc/html/rfc9380#name-the-sgn0-function
    function sgn0(uint256 x) private pure returns (uint256) {
        return x % 2;
    }

    /// @notice Compute Legendre symbol of u
    /// @param u Field element
    /// @return 1 if u is a quadratic residue, -1 if not, or 0 if u = 0 (mod p)
    function legendre(uint256 u) private view returns (int8) {
        uint256 x = modexpLegendre(u);
        if (x == N - 1) {
            return -1;
        }
        if (x != 0 && x != 1) {
            revert MapToPointFailed(u);
        }
        return int8(int256(x));
    }

    /// @notice This is cheaper than an addchain for exponent (N-1)/2
    function modexpLegendre(uint256 u) private view returns (uint256 output) {
        bytes memory input = new bytes(192);
        bool success;
        assembly {
            let p := add(input, 32)
            mstore(p, 32) // len(u)
            p := add(p, 32)
            mstore(p, 32) // len(exp)
            p := add(p, 32)
            mstore(p, 32) // len(mod)
            p := add(p, 32)
            mstore(p, u) // u
            p := add(p, 32)
            mstore(p, C5) // (N-1)/2
            p := add(p, 32)
            mstore(p, N) // N

            success := staticcall(
                gas(),
                5,
                add(input, 32),
                192,
                0x00, // scratch space <- result
                32
            )
            output := mload(0x00) // output <- result
        }
        if (!success) {
            revert ModExpFailed(u, C5, N);
        }
    }
}
