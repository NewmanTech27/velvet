// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: an override that calls its *own* base implementation
/// through an ancestor-qualified static call (`Base.f(...)`).  That call is
/// statically bound to the base body — it must NOT be resolved to the
/// most-derived override (that would be the caller itself, i.e. recursion),
/// otherwise the base body's writes/interactions are dropped from the
/// inlining summary.  Combined with an ERC-7201 diamond-storage accessor
/// (assembly `$.slot := ...`), the region write several hops deep must
/// still be matched against the region read on the path to the call.
interface ISnapshotEngine {
    function operateOnTransfer(
        address from,
        address to,
        uint256 fromBalanceBefore,
        uint256 toBalanceBefore,
        uint256 totalSupplyBefore
    ) external;
}

contract ERC20LikeBase {
    struct ERC20Storage {
        mapping(address => uint256) balances;
        uint256 totalSupply;
    }

    // Illustrative ERC-7201 slot constant.
    bytes32 private constant STORAGE_SLOT =
        0x52c63247a1c47a69f0cd6e78a5bd4f2e1e0d6b0d6b8d6f8a5d3c2b1a09080706;

    function _getERC20Storage() internal pure returns (ERC20Storage storage $) {
        assembly {
            $.slot := STORAGE_SLOT
        }
    }

    function totalSupply() public view returns (uint256) {
        ERC20Storage storage $ = _getERC20Storage();
        return $.totalSupply;
    }

    function _updateSupply(address from, address to, uint256 value) internal virtual {
        ERC20Storage storage $ = _getERC20Storage();
        $.totalSupply += value;
    }
}

contract RegionToken is ERC20LikeBase {
    ISnapshotEngine public snapshotEngine;

    function _updateSupply(address from, address to, uint256 value) internal virtual override {
        uint256 totalSupplyBefore = totalSupply();
        // Base-qualified static call: statically bound to ERC20LikeBase's
        // body (which holds the region write), NOT to this override.
        ERC20LikeBase._updateSupply(from, to, value);
        snapshotEngine.operateOnTransfer(from, to, 0, 0, totalSupplyBefore);
    }

    /// VULNERABLE (no-eth): the external call in `_burn`'s chain precedes
    /// the ERC20Storage region write in `_mint`'s chain, and the region was
    /// read (totalSupply) before the call.
    function burnAndMint(address from, address to, uint256 amount) public {
        _burn(from, amount);
        _mint(to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        _updateSupply(from, address(0), amount);
    }

    function _mint(address to, uint256 amount) internal {
        _updateSupply(address(0), to, amount);
    }
}

contract SafeRegionToken is ERC20LikeBase {
    ISnapshotEngine public snapshotEngine;

    function _updateSupply(address from, address to, uint256 value) internal virtual override {
        // SAFE: checks-effects-interactions — the region write lands before
        // the snapshot notification, and no sibling path writes after a call.
        uint256 totalSupplyBefore = totalSupply();
        ERC20LikeBase._updateSupply(from, to, value);
        snapshotEngine.operateOnTransfer(from, to, 0, 0, totalSupplyBefore);
    }

    function mint(address to, uint256 amount) public {
        _updateSupply(address(0), to, amount);
    }
}
