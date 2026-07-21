// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original minimal mock of the Gelato VRF consumer base.
abstract contract GelatoVRFBase {
    function _requestRandomness(bytes memory data) internal virtual returns (uint256);
}

/// Original fixture: randomness requests restricted to the owner.
contract Lottery is GelatoVRFBase {
    address public owner;
    uint256 public round;

    constructor() {
        owner = msg.sender;
    }

    function _requestRandomness(bytes memory data)
        internal
        override
        returns (uint256)
    {
        return 0; // mock
    }

    /// SAFE: only the owner can request randomness.
    function spin() external {
        require(msg.sender == owner, "not owner");
        round = _requestRandomness(abi.encode(round));
    }
}
