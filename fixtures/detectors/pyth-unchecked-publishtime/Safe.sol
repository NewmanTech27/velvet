// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original minimal mock of the Pyth price-feed interface.
interface IPyth {
    function getPriceUnsafe(bytes32 id)
        external
        view
        returns (int64 price, uint64 conf, int32 expo, uint256 publishTime);

    function getPriceNoOlderThan(bytes32 id, uint256 age)
        external
        view
        returns (int64 price, uint64 conf, int32 expo, uint256 publishTime);
}

/// Original fixture: freshness enforced on every Pyth read.
contract Swap {
    uint256 public constant MAX_AGE = 60;

    /// SAFE: the Unsafe getter is guarded by an explicit publishTime check.
    function rate(IPyth pyth, bytes32 id) external view returns (int64 price) {
        uint256 publishTime;
        (price, , , publishTime) = pyth.getPriceUnsafe(id);
        require(publishTime >= block.timestamp - MAX_AGE, "stale price");
    }

    /// SAFE: the NoOlderThan variant enforces freshness at the API level.
    function ema(IPyth pyth, bytes32 id) external view returns (int64 price) {
        (price, , , ) = pyth.getPriceNoOlderThan(id, MAX_AGE);
    }
}
