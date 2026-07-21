// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original minimal mock of the Gelato VRF consumer base.
abstract contract GelatoVRFBase {
    function _requestRandomness(bytes memory data) internal virtual returns (uint256);
}

/// Original fixture: anyone can trigger paid randomness requests.
contract Lottery is GelatoVRFBase {
    uint256 public round;

    function _requestRandomness(bytes memory data)
        internal
        override
        returns (uint256)
    {
        return 0; // mock: real impl pays the Gelato VRF subscription
    }

    /// VULNERABLE: external with no access control; anyone drains the subscription.
    function spin() external {
        round = _requestRandomness(abi.encode(msg.sender));
    }
}
