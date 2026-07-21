// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: dangerous reliance on block.timestamp.
contract Timed {
    uint256 public last;
    uint256 public deadline;

    /// VULNERABLE: exact-second window that validators can nudge into place.
    function claimWindow() external returns (bool) {
        if (block.timestamp % 60 == 0) {
            last = block.timestamp;
            return true;
        }
        return false;
    }

    /// VULNERABLE: strict equality against a timestamp.
    function isMilestone(uint256 milestone) external view returns (bool) {
        return block.timestamp == milestone;
    }

    /// VULNERABLE: ordering on a short window derived from the timestamp.
    function freshEnough(uint256 observedAt) external view returns (bool) {
        return block.timestamp - observedAt < 15;
    }

    /// VULNERABLE: plain deadline check — the timestamp comparison gates a
    /// value flow (catalog §7.39 flags timestamp comparisons broadly).
    function isOpen() external view returns (bool) {
        return block.timestamp <= deadline;
    }

    /// VULNERABLE: the timestamp comparison computed by an internal helper
    /// gates a state-changing require through a returned boolean.
    function claim() external {
        require(_active() && last != 0, "inactive");
        last = block.timestamp;
    }

    /// VULNERABLE: deadline comparison feeding the gating flag above.
    function _active() internal view returns (bool) {
        return block.timestamp <= deadline;
    }
}
