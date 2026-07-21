// vulnerable: permit() followed by transferFrom with a caller-controlled from.
pragma solidity ^0.8.0;

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract Vault {
    // The from address is a user supplied parameter: anyone can drain a
    // holder that signed a permit for this contract.
    function depositWithPermit(
        IERC20Permit token,
        address holder,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        token.permit(holder, address(this), amount, deadline, v, r, s);
        token.transferFrom(holder, address(this), amount);
    }
}
