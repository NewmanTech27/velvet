// safe: length writes are constant or owner-protected.
pragma solidity 0.5.8;

contract Pool {
    uint256[] public entries;
    address public owner = msg.sender;

    function reset() external {
        entries.length = 0;
    }

    function resizeProtected(uint256 n) external {
        require(msg.sender == owner, "owner only");
        entries.length = n;
    }
}
