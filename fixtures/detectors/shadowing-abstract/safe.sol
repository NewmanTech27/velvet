// safe: the derived contract uses distinct names.
pragma solidity 0.5.8;

contract Base {
    uint256 internal rate;

    function computeFee(uint256 amount) public view returns (uint256);

    function version() public pure returns (uint256);
}

contract Market is Base {
    uint256 public marketRate;

    function computeFee(uint256 amount) public view returns (uint256) {
        return amount * rate / 100;
    }

    function version() public pure returns (uint256) {
        return 1;
    }
}
