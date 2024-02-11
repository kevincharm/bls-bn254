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

    function test__mapToPointFT(
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

    function verifySingle(
        uint256[2] memory signature,
        uint256[4] memory pubkey,
        uint256[2] memory message
    ) external view returns (bool success, uint256 gas) {
        gas = gasleft();
        success = BLS.verifySingle(signature, pubkey, message);
        gas = gas - gasleft();
    }

    function isOnCurveG1(
        uint256[2] memory point
    ) external pure returns (bool _isOnCurve) {
        return BLS.isOnCurveG1(point);
    }

    function isOnCurveG2(
        uint256[4] memory point
    ) external pure returns (bool _isOnCurve) {
        return BLS.isOnCurveG2(point);
    }
}
