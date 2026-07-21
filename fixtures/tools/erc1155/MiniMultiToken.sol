// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Minimal but signature-complete ERC-1155 (original fixture). Receiver-hook
/// calls are intentionally simplified — the conformance checker only verifies
/// the statically checkable requirements.
contract MiniMultiToken {
    mapping(uint256 => mapping(address => uint256)) internal _balances;
    mapping(address => mapping(address => bool)) internal _operators;

    event TransferSingle(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256 id,
        uint256 value
    );
    event TransferBatch(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256[] ids,
        uint256[] values
    );
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    event URI(string value, uint256 indexed id);

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return
            interfaceId == bytes4(0xd9b67a26) ||
            interfaceId == bytes4(0x01ffc9a7);
    }

    function uri(uint256) external pure returns (string memory) {
        return "https://example.invalid/{id}";
    }

    function balanceOf(address owner, uint256 id) external view returns (uint256) {
        return _balances[id][owner];
    }

    function balanceOfBatch(address[] memory owners, uint256[] memory ids)
        external
        view
        returns (uint256[] memory)
    {
        require(owners.length == ids.length, "length mismatch");
        uint256[] memory result = new uint256[](owners.length);
        for (uint256 i = 0; i < owners.length; i++) {
            result[i] = _balances[ids[i]][owners[i]];
        }
        return result;
    }

    function setApprovalForAll(address operator, bool approved) external {
        _operators[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address owner, address operator)
        external
        view
        returns (bool)
    {
        return _operators[owner][operator];
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 value,
        bytes memory
    ) external {
        require(to != address(0), "zero address");
        _balances[id][from] -= value;
        _balances[id][to] += value;
        emit TransferSingle(msg.sender, from, to, id, value);
    }

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory values,
        bytes memory
    ) external {
        require(to != address(0), "zero address");
        require(ids.length == values.length, "length mismatch");
        for (uint256 i = 0; i < ids.length; i++) {
            _balances[ids[i]][from] -= values[i];
            _balances[ids[i]][to] += values[i];
        }
        emit TransferBatch(msg.sender, from, to, ids, values);
    }
}
