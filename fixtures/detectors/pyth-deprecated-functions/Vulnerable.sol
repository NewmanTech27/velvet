// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original minimal mock of the Pyth price-feed interface.
interface IPyth {
    function getPrice(bytes32 id)
        external
        view
        returns (int64 price, uint64 conf, int32 expo, uint256 publishTime);

    function getEmaPrice(bytes32 id)
        external
        view
        returns (int64 price, uint64 conf, int32 expo, uint256 publishTime);
}

/// Original fixture: deprecated Pyth getters.
contract Feed {
    /// VULNERABLE: getPrice is a deprecated entry point.
    function quote(IPyth pyth, bytes32 id) external view returns (int64 price) {
        (price, , , ) = pyth.getPrice(id);
    }

    /// VULNERABLE: getEmaPrice is a deprecated entry point.
    function ema(IPyth pyth, bytes32 id) external view returns (int64 price) {
        (price, , , ) = pyth.getEmaPrice(id);
    }
}
