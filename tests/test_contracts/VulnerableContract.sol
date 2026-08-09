// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/// @title VulnerableContract — Contains multiple security AND PQC vulnerabilities.
/// @dev    Intentionally vulnerable for testing the audit tool.
contract VulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    /// @dev Reentrancy: external call before state update + uses ecrecover.
    function withdrawWithSignature(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "Bad sig");

        uint256 amount = balances[signer];
        require(amount > 0, "No balance");

        // Vulnerable: external call BEFORE state update (reentrancy)
        (bool success, ) = signer.call{value: amount}("");
        require(success, "Transfer failed");

        // State update AFTER external call — reentrancy vulnerability
        balances[signer] = 0;
    }

    /// @dev Uses tx.origin for authorization (phishing vulnerability).
    function emergencyWithdraw() external {
        require(tx.origin == owner, "Not owner");
        uint256 amount = address(this).balance;
        (bool success, ) = owner.call{value: amount}("");
        require(success);
    }

    /// @dev Unprotected selfdestruct (critical).
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }

    /// @dev Uses block.timestamp for logic (manipulable by miners).
    function isTimeLocked() external view returns (bool) {
        return block.timestamp > 1700000000;
    }

    /// @dev Uses sha256 (Grover's quadratic speedup — MEDIUM PQC risk).
    function hashData(bytes memory data) external pure returns (bytes32) {
        return sha256(data);
    }

    receive() external payable {}
}
