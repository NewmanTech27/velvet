pragma solidity ^0.8.0;

// Vulnerable (review aid): low-level call usage.
contract LowLevelProxy {
    function forward(
        address target,
        bytes calldata data
    ) external returns (bytes memory) {
        (bool ok, bytes memory out) = target.call(data); // flagged for review
        require(ok);
        return out;
    }
}

interface ICounter {
    function increment() external;
}

// Safe: high-level interface call only.
contract HighLevelCaller {
    function forward(ICounter target) external {
        target.increment();
    }
}
