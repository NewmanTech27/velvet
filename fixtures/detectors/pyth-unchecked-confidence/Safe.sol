// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original minimal mock of the Pyth price-feed interface.
interface IPyth {
    function getPriceUnsafe(bytes32 id)
        external
        view
        returns (int64 price, uint64 conf, int32 expo, uint256 publishTime);
}

/// Original fixture: Pyth price consumed only after bounding conf.
contract Lending {
    uint64 public constant MAX_CONF_BPS = 100; // 1%

    /// SAFE: the confidence interval is bounded against the price.
    function borrowValue(IPyth pyth, bytes32 id) external view returns (int64 price) {
        uint64 conf;
        (price, conf, , ) = pyth.getPriceUnsafe(id);
        require(price > 0, "bad price");
        require(conf * 10_000 <= uint64(price) * MAX_CONF_BPS, "conf too wide");
    }
}
