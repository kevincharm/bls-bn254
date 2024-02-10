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
}
