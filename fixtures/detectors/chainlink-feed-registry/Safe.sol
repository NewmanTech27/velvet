// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original minimal mock of a chain-specific Chainlink aggregator.
interface IAggregator {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

/// Original fixture: a chain-specific aggregator address instead of the registry.
contract Prices {
    // SAFE: a per-chain aggregator proxy address works on every chain.
    IAggregator public immutable ethUsdFeed;

    constructor(IAggregator feed) {
        ethUsdFeed = feed;
    }

    /// SAFE: the no-arg latestRoundData is a plain aggregator read.
    function ethUsd() external view returns (int256 price) {
        (, price, , , ) = ethUsdFeed.latestRoundData();
    }
}
