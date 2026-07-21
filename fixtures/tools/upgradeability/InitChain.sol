// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "./Initializable.sol";

abstract contract ChainBaseA is Initializable {
    uint256 public a;

    function initializeA() internal {
        a = 1;
    }
}

abstract contract ChainBaseB is Initializable {
    uint256 public b;

    function initializeB() internal {
        b = 2;
    }
}

/// @notice Every base initializer is reachable exactly once.
contract GoodChainImpl is ChainBaseA, ChainBaseB {
    function initialize() external initializer {
        initializeA();
        initializeB();
    }
}

/// @notice initializeB is never called from the derived initializer.
contract MissingCallsImpl is ChainBaseA, ChainBaseB {
    function initialize() external initializer {
        initializeA();
    }
}

/// @notice initializeA runs twice along the initialization path.
contract MultipleCallsImpl is ChainBaseA, ChainBaseB {
    function initialize() external initializer {
        initializeA();
        initializeA();
        initializeB();
    }
}

/// @notice The double call is hidden behind an internal helper.
contract MultipleCallsHelperImpl is ChainBaseA, ChainBaseB {
    function initialize() external initializer {
        initializeA();
        _initAgain();
        initializeB();
    }

    function _initAgain() internal {
        initializeA();
    }
}
