// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IGasPriceOracle {
    function scalar() external view returns (uint256);

    function decimals() external view returns (uint256);
}

/// Original fixture: the deprecated GasPriceOracle.scalar() is called on
/// the well-known predeploy address; it always reverts post-Ecotone.
contract L2Fee {
    IGasPriceOracle constant GPO =
        IGasPriceOracle(0x420000000000000000000000000000000000000F);

    /// VULNERABLE: scalar() was removed by the Ecotone upgrade.
    function feeScalar() external view returns (uint256) {
        return GPO.scalar();
    }

    /// VULNERABLE: same deprecated call through an on-the-fly cast.
    function inlineScalar() external view returns (uint256) {
        return IGasPriceOracle(0x420000000000000000000000000000000000000F).scalar();
    }
}
