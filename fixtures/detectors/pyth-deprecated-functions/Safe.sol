// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original minimal mock of the Pyth price-feed interface.
interface IPyth {
    function getPriceNoOlderThan(bytes32 id, uint256 age)
        external
        view
        returns (int64 price, uint64 conf, int32 expo, uint256 publishTime);

    function getPriceUnsafe(bytes32 id)
        external
        view
        returns (int64 price, uint64 conf, int32 expo, uint256 publishTime);
}

/// Original fixture: current Pyth API with explicit staleness handling.
contract Feed {
    /// SAFE: the NoOlderThan variant enforces freshness.
    function quote(IPyth pyth, bytes32 id) external view returns (int64 price) {
        (price, , , ) = pyth.getPriceNoOlderThan(id, 60);
    }

    /// SAFE: the Unsafe variant with an explicit publishTime check.
    function quoteChecked(IPyth pyth, bytes32 id)
        external
        view
        returns (int64 price)
    {
        uint256 publishTime;
        (price, , , publishTime) = pyth.getPriceUnsafe(id);
        require(publishTime >= block.timestamp - 60, "stale");
    }
}
