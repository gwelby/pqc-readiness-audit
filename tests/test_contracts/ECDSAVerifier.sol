// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ECDSAVerifier — A contract that uses ecrecover (ECDSA), which is
///        quantum-vulnerable (Shor's algorithm breaks it in polynomial time).
contract ECDSAVerifier {
    mapping(address => bool) public isVerified;

    event Verified(address indexed signer, bytes32 messageHash);

    /// @notice Verifies a signature using ecrecover (ECDSA on secp256k1).
    /// @dev    This is CRITICAL PQC risk — Shor's algorithm breaks ECDSA.
    function verifySignature(
        bytes32 messageHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (address) {
        address signer = ecrecover(messageHash, v, r, s);
        require(signer != address(0), "Invalid signature");
        isVerified[signer] = true;
        emit Verified(signer, messageHash);
        return signer;
    }

    /// @notice Recovers multiple signers using ecrecover in a loop.
    function verifyMultiple(
        bytes32[] calldata messageHashes,
        uint8[] calldata vValues,
        bytes32[] calldata rValues,
        bytes32[] calldata sValues
    ) external returns (address[] memory signers) {
        require(
            messageHashes.length == vValues.length &&
            vValues.length == rValues.length &&
            rValues.length == sValues.length,
            "Array length mismatch"
        );
        signers = new address[](messageHashes.length);
        for (uint256 i = 0; i < messageHashes.length; i++) {
            signers[i] = ecrecover(messageHashes[i], vValues[i], rValues[i], sValues[i]);
            isVerified[signers[i]] = true;
        }
    }
}
