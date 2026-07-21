// vulnerable: the comment below hides a right-to-left override character.
pragma solidity ^0.8.0;

contract Pay {
    function sweep(address to, uint256 amount) external {
        // ‮ ⁦ apparently harmless remark ⁩ ‬
        payable(to).transfer(amount);
    }
}
