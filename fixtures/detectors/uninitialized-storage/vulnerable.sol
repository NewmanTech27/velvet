// vulnerable: a local storage pointer used before being assigned.
// NOTE: only pre-0.5 compilers accept this source; modern solc rejects
// "Entry storage e;" without an initializer, so the pattern is exercised by
// the test suite through a constructed model instead.
pragma solidity 0.4.24;

contract Wallet {
    address public owner = msg.sender;

    struct Entry {
        uint256 amount;
    }

    function corrupt() external {
        Entry e;
        e.amount = 0; // writes through the uninitialized storage pointer
    }
}
