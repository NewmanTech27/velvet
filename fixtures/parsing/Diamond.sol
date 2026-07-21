// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Original fixture: diamond inheritance for C3 linearization tests.
//
//          ICounter
//             |
//            Base
//           /    \
//        Left   Right
//           \    /
//          Diamond

interface ICounter {
    function version() external view returns (uint256);
}

contract Base is ICounter {
    uint256 internal counter;

    function version() public view virtual override returns (uint256) {
        return 1;
    }

    function bump() public virtual {
        counter += 1;
    }
}

contract Left is Base {
    function bump() public virtual override {
        counter += 2;
    }
}

contract Right is Base {
    function version() public view virtual override returns (uint256) {
        return 2;
    }
}

contract Diamond is Left, Right {
    function version() public view override(Base, Right) returns (uint256) {
        return Right.version();
    }

    function bump() public override(Base, Left) {
        counter += 3;
    }
}
