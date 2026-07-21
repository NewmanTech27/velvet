// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: public functions that ARE called internally / external ones.
contract Token {
    uint256 internal supply;

    /// SAFE: called internally by mintAndLog, so it must stay public.
    function mint(uint256 amount) public {
        supply += amount;
    }

    function mintAndLog(uint256 amount) external {
        mint(amount); // internal call site
    }

    /// SAFE: already external.
    function burn(uint256 amount) external {
        supply -= amount;
    }
}

interface IMinter {
    function mint(uint256 amount) external;
}

/// SAFE: implements the interface function; Solidity does not require the
/// `override` keyword for interface implementations, and the visibility is
/// constrained by the interface.
contract LeafToken is IMinter {
    uint256 internal supply;

    function mint(uint256 amount) public {
        supply += amount;
    }
}

/// SAFE: abstract contracts are inheritance APIs; their public functions may
/// be required `public` by derived contracts outside the analyzed set.
abstract contract AbstractToken {
    uint256 internal supply;

    function mint(uint256 amount) public virtual {
        supply += amount;
    }
}

/// SAFE: a contract that is inherited is an inheritance API as well.
contract BaseToken {
    uint256 internal supply;

    function mint(uint256 amount) public virtual {
        supply += amount;
    }
}

contract ChildToken is BaseToken {
    function burn(uint256 amount) external {
        supply -= amount;
    }
}
