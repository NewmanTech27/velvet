// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original minimal mock of the Pyth price-feed interface.
interface IPyth {
    function getPriceUnsafe(bytes32 id)
        external
        view
        returns (int64 price, uint64 conf, int32 expo, uint256 publishTime);

    function getEmaPriceNoOlderThan(bytes32 id, uint256 age)
        external
        view
        returns (int64 price, uint64 conf, int32 expo, uint256 publishTime);
}

/// Original fixture: Pyth price used without bounding the confidence interval.
contract Lending {
    /// VULNERABLE: conf is never even extracted.
    function borrowValue(IPyth pyth, bytes32 id) external view returns (int64 price) {
        (price, , , ) = pyth.getPriceUnsafe(id);
    }

    /// VULNERABLE: conf is extracted but never validated.
    function emaValue(IPyth pyth, bytes32 id) external view returns (int64 price) {
        uint64 conf;
        (price, conf, , ) = pyth.getEmaPriceNoOlderThan(id, 60);
        // conf is read into a local but never compared/validated.
    }
}
