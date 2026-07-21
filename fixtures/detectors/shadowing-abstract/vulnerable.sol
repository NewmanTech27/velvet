// vulnerable: Market redeclares the abstract base's rate variable.
// (solc 0.5.x: an unimplemented function makes Base abstract; 0.6+ rejects
// state-variable shadowing entirely.)
pragma solidity 0.5.8;

contract Base {
    uint256 internal rate;

    function computeFee(uint256 amount) public view returns (uint256);

    function version() public pure returns (uint256);
}

contract Market is Base {
    // shadows Base.rate: Base.computeFee reads the base slot instead.
    uint256 public rate;

    function computeFee(uint256 amount) public view returns (uint256) {
        return amount / 100;
    }

    function version() public pure returns (uint256) {
        return 1;
    }
}
