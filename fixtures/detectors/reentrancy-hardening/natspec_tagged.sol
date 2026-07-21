// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: `@custom:security non-reentrant` marks state variables
/// that are safe to update after an external call (spec §11.3); tagged
/// variables are excluded from the writes-after classification.
contract TaggedVault {
    /// @custom:security non-reentrant
    mapping(address => uint256) public balances;

    mapping(address => uint256) public untagged;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        untagged[msg.sender] += msg.value;
    }

    /// SAFE BY ANNOTATION: balances carries the non-reentrant tag, so the
    /// write after the call is excluded.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }

    /// VULNERABLE control: same pattern without the tag — still flagged.
    function withdrawUntagged() external {
        uint256 amount = untagged[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        untagged[msg.sender] = 0;
    }
}

/// Block-doc variant of the tag on a no-Ether pattern.
contract TaggedAuction {
    /**
     * @custom:security non-reentrant
     */
    bool public settled;

    /// SAFE BY ANNOTATION: settled is tagged.
    function settle(address target) external {
        require(!settled, "already settled");
        (bool ok, ) = target.call("");
        require(ok, "notify failed");
        settled = true;
    }
}
