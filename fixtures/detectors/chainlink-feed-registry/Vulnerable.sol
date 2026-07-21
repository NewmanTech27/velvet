// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original minimal mock of the Chainlink Feed Registry interface.
interface IFeedRegistry {
    function latestRoundData(address base, address quote)
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

/// Original fixture: mainnet-only Feed Registry dependency.
contract Prices {
    // VULNERABLE: the canonical registry address exists only on mainnet.
    IFeedRegistry public constant REGISTRY =
        IFeedRegistry(0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf);

    address internal constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    address internal constant USD = 0x0000000000000000000000000000000000000348;

    /// VULNERABLE: two-address latestRoundData is the registry form.
    function ethUsd() external view returns (int256 price) {
        (, price, , , ) = REGISTRY.latestRoundData(ETH, USD);
    }
}
