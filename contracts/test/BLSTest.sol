// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "../BLS.sol";

contract BLSTest {
    function test__expandMsgTo96(
        bytes memory domain,
        bytes memory message
    ) external pure returns (bytes memory) {
        return BLS.expandMsgTo96(domain, message);
    }

    function test__hashToField(
        bytes memory domain,
        bytes memory message
    ) external pure returns (uint256[2] memory) {
        return BLS.hashToField(domain, message);
    }

    function test__mapToPointFT(
        uint256 value
    ) external pure returns (uint256[2] memory) {
        return BLS.mapToPoint(value);
    }

    function test__hashToPoint(
        bytes memory domain,
        bytes memory message
    ) external view returns (uint256[2] memory) {
        return BLS.hashToPoint(domain, message);
    }
}
