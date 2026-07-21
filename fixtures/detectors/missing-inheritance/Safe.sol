// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVault {
    function deposit(uint256 amount) external;

    function withdraw(uint256 amount) external;
}

interface IRegistry {
    function register(address who) external;

    function unregister(address who) external;
}

/// SAFE: the inheritance is declared, so conformance is compiler-enforced.
contract VaultImpl is IVault {
    mapping(address => uint256) public balances;

    function deposit(uint256 amount) external override {
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external override {
        balances[msg.sender] -= amount;
    }
}

/// SAFE: implements only part of IRegistry — not a full implementation.
contract PartialRegistry {
    function register(address who) external {}
}

interface IERC165Like {
    function supportsInterface(bytes4 id) external view returns (bool);
}

/// SAFE: a single-member surface (supportsInterface) is idiomatically
/// implemented standalone; it does not imply a missing type relationship.
contract StandaloneERC165 {
    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == 0x01ffc9a7;
    }
}

interface IBase {
    function ping() external;

    function pong() external;
}

abstract contract BaseImpl is IBase {
    function ping() external virtual {}

    function pong() external virtual {}
}

/// SAFE: only *provides* IBase's API through inheritance — it does not
/// define the members itself, and BaseImpl is already inherited.
contract InheritedImpl is BaseImpl {}
