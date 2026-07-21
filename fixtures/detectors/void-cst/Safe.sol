// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Base with no explicit constructor.
contract PlainBase {
    uint256 internal value;
}

/// Base that DOES define a constructor.
contract RealBase {
    uint256 internal count;

    constructor() {
        count = 1;
    }
}

/// SAFE: no no-op base constructor call.
contract PlainChild is PlainBase {
    constructor() {
        value = 1;
    }
}

/// SAFE: the base constructor exists, so calling it is meaningful.
contract RealChild is RealBase {
    constructor() RealBase() {
        count = 2;
    }
}
