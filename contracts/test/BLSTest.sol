// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "../BLS.sol";

contract BLSTest {
    function test__expandMsgTo96(
        bytes memory domain,
        bytes memory message
    ) external view returns (bytes memory expanded, uint256 gas) {
        gas = gasleft();
        expanded = BLS.expandMsgTo96(domain, message);
        gas = gas - gasleft();
    }

    function test__hashToField(
        bytes memory domain,
        bytes memory message
    ) external view returns (uint256[2] memory p, uint256 gas) {
        gas = gasleft();
        p = BLS.hashToField(domain, message);
        gas = gas - gasleft();
    }

    function test__mapToPoint(
        uint256 value
    ) external view returns (uint256[2] memory p, uint256 gas) {
        gas = gasleft();
        p = BLS.mapToPoint(value);
        gas = gas - gasleft();
    }

    function test__hashToPoint(
        bytes memory domain,
        bytes memory message
    ) external view returns (uint256[2] memory p, uint256 gas) {
        gas = gasleft();
        p = BLS.hashToPoint(domain, message);
        gas = gas - gasleft();
    }

    function test__verifySingle(
        uint256[2] memory signature,
        uint256[4] memory pubkey,
        uint256[2] memory message
    )
        external
        view
        returns (bool pairingSuccess, bool callSuccess, uint256 gas)
    {
        gas = gasleft();
        (pairingSuccess, callSuccess) = BLS.verifySingle(
            signature,
            pubkey,
            message
        );
        gas = gas - gasleft();
    }

    function test__isOnCurveG1(
        uint256[2] memory point
    ) external view returns (bool _isOnCurve, uint256 gas) {
        gas = gasleft();
        _isOnCurve = BLS.isOnCurveG1(point);
        gas = gas - gasleft();
    }

    function test__isOnCurveG2(
        uint256[4] memory point
    ) external view returns (bool _isOnCurve, uint256 gas) {
        gas = gasleft();
        _isOnCurve = BLS.isOnCurveG2(point);
        gas = gas - gasleft();
    }

    function test__isValidSignature(
        uint256[2] memory signature
    ) external view returns (bool isValid, uint256 gas) {
        gas = gasleft();
        isValid = BLS.isValidSignature(signature);
        gas = gas - gasleft();
    }

    function test__isValidPublicKey(
        uint256[4] memory publicKey
    ) external view returns (bool isValid, uint256 gas) {
        gas = gasleft();
        isValid = BLS.isValidPublicKey(publicKey);
        gas = gas - gasleft();
    }
}
