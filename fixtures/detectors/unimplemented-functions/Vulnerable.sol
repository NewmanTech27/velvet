// SPDX-License-Identifier: MIT
// vulnerable: Token is not marked abstract (pre-0.6 sources have no
// abstract keyword and implicitly-abstract contracts still compile) but
// leaves IERC20Minimal.transfer() unimplemented — it can never deploy.
pragma solidity ^0.5.17;

interface IERC20Minimal {
    function totalSupply() external view returns (uint256);

    function transfer(address to, uint256 amount) external returns (bool);
}

contract Token is IERC20Minimal {
    function totalSupply() external view returns (uint256) {
        return 0;
    }
    // transfer(address,uint256) is inherited but never implemented.
}
