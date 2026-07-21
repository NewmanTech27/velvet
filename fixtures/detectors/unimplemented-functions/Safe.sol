// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20Minimal {
    function totalSupply() external view returns (uint256);

    function transfer(address to, uint256 amount) external returns (bool);
}

/// SAFE: the omission is deliberate — the contract says `abstract`.
abstract contract PartialToken is IERC20Minimal {
    function totalSupply() external view returns (uint256) {
        return 0;
    }
}

/// SAFE: every inherited function is implemented.
contract FullToken is IERC20Minimal {
    function totalSupply() external view returns (uint256) {
        return 0;
    }

    function transfer(address, uint256) external returns (bool) {
        return true;
    }
}
