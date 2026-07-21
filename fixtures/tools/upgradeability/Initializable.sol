// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/// @title Initializable
/// @notice Minimal once-only initialization guard used by the
/// upgradeability fixtures. The storage flag lives in the proxy's
/// context once deployed behind a delegatecall proxy, so an
/// `initializer`-guarded function can run exactly once.
/// (spec/printers-and-tools.md B.2.3 — original clean-room implementation)
abstract contract Initializable {
    bool private _initialized;

    modifier initializer() {
        require(!_initialized, "Initializable: already initialized");
        _;
        _initialized = true;
    }

    /// @notice Locks the implementation contract itself so its
    /// initializers can never be invoked outside a proxy.
    function _disableInitializers() internal {
        _initialized = true;
    }
}
