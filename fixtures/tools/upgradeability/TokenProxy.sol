// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/// @notice Minimal delegatecall proxy exercising the proxy-side checks:
/// - the `admin()`/`implementation()` getters shadow the implementation's
///   same-named getters (function-shadowing),
/// - collate_propagate_storage(bytes16) has selector 0x42966c68, equal
///   to the implementation's burn(uint256) (function-id-collision),
/// - `pendingAdmin` exists only on the proxy (extra-vars-proxy).
contract TokenProxy {
    address public implementation;
    address public admin;
    address public pendingAdmin;

    constructor(address logic) {
        implementation = logic;
        admin = msg.sender;
    }

    function upgradeTo(address newImplementation) external {
        require(msg.sender == admin, "not admin");
        implementation = newImplementation;
    }

    /// @dev Selector 0x42966c68 collides with burn(uint256).
    function collate_propagate_storage(bytes16) external {
        pendingAdmin = admin;
    }

    fallback() external payable {
        address logic = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), logic, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
