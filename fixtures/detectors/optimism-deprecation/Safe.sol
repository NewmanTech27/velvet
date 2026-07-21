// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IGasPriceOracle {
    function scalar() external view returns (uint256);

    function decimals() external view returns (uint256);

    function baseFeeScalar() external view returns (uint32);
}

interface IScalarFeed {
    function scalar() external view returns (uint256);
}

/// Original fixture: supported predeploy functions, and a scalar() that
/// does not target the GasPriceOracle predeploy.
contract UpToDateFee {
    IGasPriceOracle constant GPO =
        IGasPriceOracle(0x420000000000000000000000000000000000000F);

    /// SAFE: decimals() was not removed by the Ecotone upgrade.
    function unit() external view returns (uint256) {
        return GPO.decimals();
    }

    /// SAFE: the supported replacement for the deprecated scalar().
    function currentScalar() external view returns (uint32) {
        return GPO.baseFeeScalar();
    }

    /// SAFE: scalar() on an application contract, not the predeploy.
    function appScalar(IScalarFeed feed) external view returns (uint256) {
        return feed.scalar();
    }
}
