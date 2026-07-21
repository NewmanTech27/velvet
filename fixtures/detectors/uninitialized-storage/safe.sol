// safe: storage pointers are bound at declaration.
pragma solidity 0.5.8;

contract Wallet {
    address public owner = msg.sender;

    struct Entry {
        uint256 amount;
    }

    Entry[] public entries;

    function init() external {
        entries.push(Entry(1));
        Entry storage e = entries[0];
        e.amount = 0;
    }
}
