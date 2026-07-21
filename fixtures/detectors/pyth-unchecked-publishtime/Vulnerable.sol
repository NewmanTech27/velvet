// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original minimal mock of the Pyth price-feed interface.
interface IPyth {
    function getEmaPriceUnsafe(bytes32 id)
        external
        view
        returns (int64 price, uint64 conf, int32 expo, uint256 publishTime);

    function getPriceUnsafe(bytes32 id)
        external
        view
        returns (int64 price, uint64 conf, int32 expo, uint256 publishTime);
}

/// Original fixture: Pyth Unsafe prices used without a publishTime check.
contract Swap {
    /// VULNERABLE: publishTime is never checked on an Unsafe getter.
    function rate(IPyth pyth, bytes32 id) external view returns (int64 price) {
        (price, , , ) = pyth.getEmaPriceUnsafe(id);
    }

    /// VULNERABLE: publishTime extracted but never validated.
    function spot(IPyth pyth, bytes32 id) external view returns (int64 price) {
        uint256 publishTime;
        (price, , , publishTime) = pyth.getPriceUnsafe(id);
        // publishTime held but never compared to block.timestamp.
    }
}
