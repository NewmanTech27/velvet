// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: documented naming exceptions and per-kind rules.
contract Conventions {
    uint256 private _privateCounter; // OK: leading underscore, private
    uint256 private __doubleCounter; // VIOLATION: two leading underscores
    uint256 public publicCounter; // OK

    /// OK: internal function with a leading underscore.
    function _bumpInternal(uint256 amount_) internal {
        _privateCounter += amount_;
    }

    /// VIOLATION: public function with a leading underscore.
    function _bumpPublic(uint256 amount_) public {
        _privateCounter += amount_;
    }

    /// OK: trailing underscore disambiguates from state variables.
    function setCounter(uint256 counter_) public {
        publicCounter = counter_;
    }

    /// VIOLATION: used parameter with a leading underscore.
    function pay(uint256 _amount) public {
        _privateCounter += _amount;
    }

    /// OK: unused parameter may keep its leading underscore.
    function payUnused(uint256 _amount) public {
        _privateCounter += 1;
    }

    /// OK: "$" has no case (ERC-7201 storage-pointer idiom).
    function storagePointer() public pure returns (uint256) {
        uint256 $ = 1;
        return $;
    }

    /// Same badly-named parameter declared by two functions in one file:
    /// two distinct declarations, two findings.
    function first(uint256 Bad_Param) public {
        publicCounter = Bad_Param;
    }

    function second(uint256 Bad_Param) public {
        publicCounter = Bad_Param;
    }
}
