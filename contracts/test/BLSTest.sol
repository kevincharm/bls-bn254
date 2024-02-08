// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "../BLS.sol";
import {BLSRef} from "./BLSRef.sol";

contract BLSTest {
    function test__expandMsgTo96(
        bytes memory domain,
        bytes memory message
    ) external pure returns (bytes memory, bytes memory) {
        return (
            BLS.expandMsgTo96(domain, message),
            BLSRef.expandMsgTo96(domain, message)
        );
    }
}
