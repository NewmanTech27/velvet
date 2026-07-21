// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/// @notice A proxy whose storage prefix and function surface are
/// compatible with ProxyImpl: the shared variables appear in the same
/// order with the same types (internal, so no getter shadowing), no
/// shadowing functions, no selector collisions, no extra variables.
contract CleanProxy {
    address internal implementation;
    address internal admin;

    constructor(address logic) {
        implementation = logic;
        admin = msg.sender;
    }

    function upgradeTo(address newImplementation) external {
        require(msg.sender == admin, "not admin");
        implementation = newImplementation;
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

/// @notice Same variable names as ProxyImpl but declared in the opposite
/// order — order-vars-proxy fires because the shared variables' relative
/// order differs between proxy and implementation.
contract BadOrderProxy {
    address internal admin;
    address internal implementation;

    constructor(address logic) {
        implementation = logic;
        admin = msg.sender;
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
