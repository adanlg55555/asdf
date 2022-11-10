---
eip: 
title: Unique NFT linking especific physical good
description: Minimal interface for linking ownership of EIP-721 NFT to a physical chip
author: adanlg55555 (@adanlg55555)
discussions-to: 
status: 
type: Standards Track
category: ERC
created: 2022-09-11
requires: 721
---

## Abstract

This implementation is a modification of [EIP-721](./eip-721.md). It proposes a minimal interface for a [EIP-721](./eip-721.md) NFT to be connected with its physical counterpart, allowing physical devices to be completely unique, trusteable without serial numbers or experts.

## Motivation

- Avoid counterfeiting and piracy making it impossible/ non profitable.

- Let the tangible products brands enter the ecosistem, by providing them a solution to make a percentage of the sale in the secundary market through NFTs.

- Bring real world assets to the digital world and making them trully unique.

- Verifying the authenticity of the physical item without 3rd party (e.g. StockX).

## Specification

The key words “MUST”, “MUST NOT”, “REQUIRED”, “SHALL”, “SHALL NOT”, “SHOULD”, “SHOULD NOT”, “RECOMMENDED”, “MAY”, and “OPTIONAL” in this document are to be interpreted as described in RFC 2119.

### Requirements

This approach requires that the physical item must have a chip attached to it that fulfills the following requirements:

- The chip can securely generate and store an ECDSA secp256k1 asymmetric key pair;
- The chip can sign messages using the private key of the previously-generated asymmetric key pair;
- The chip exposes the public key; and
- The private key cannot be extracted (preferably stored on a Secure Element)


### Approach

Let's make the approach with one real use case example, with a chip embedded to a luxury watch.
Each Smart Contract manage only one NFT linked to one physical chip.
When the smart contract is deployed, there are two things that have to be setted:
First, changing the owner of the smart contract to the chip's address that would never be possible to change again. Second, mint the unique token minteable to the address that buys the watch.
Since then, every time you want to sell the NFT you must need call the function "transferAuthorized" with the chip, and then the transferFrom with the owner of the token, like in a two factor athentication, to make one part essential for the other.
Also, you can provee the authenticity of the watch at any time, checking if the chip is the owner of the smart contact. 






### Specification

This is the technical explanation of the smart contract.

#### Before deployment

Open your IDE (Eg: Remix) 
Import

```solidity
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
´´´
Display all the code by using the falttener or other tool.

#### Interface

```solidity

interface IERCNumber {
    
    /// @notice Erase some functions that are not going to be available, neither its inside code
    /* function renounceOwnership() public virtual onlyOwner
    /* function _burn(uint256 tokenId) internal virtual {
    
    /// @notice remove all possible approval because the chip is going to be the unique capable of interact with some functions
    /* event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    /* event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    /* function approve(address to, uint256 tokenId) external;
    /* function setApprovalForAll(address operator, bool _approved) external;
    /* function getApproved(uint256 tokenId) external view returns (address operator);
    /*
    

    /// @notice remove the tokenId transfers and their overrides to simplify only to the transferFrom function
    /* function safeTransferFrom(
    /* function _safeTransfer(
    
    -----

    /// @notice Returns true if the chip for the specified token id is the signer of the signature of the payload.
    /// @dev Throws if tokenId does not exist in the collection.
    /// @param tokenId The token id.
    /// @param payload Arbitrary data that is signed by the chip to produce the signature param.
    /// @param signature Chip's signature of the passed-in payload.
    /// @return Whether the signature of the payload was signed by the chip linked to the token id.
    function isChipSignatureForToken(uint256 tokenId, bytes calldata payload, bytes calldata signature)
        external
        view
        returns (bool);

    /// @notice Transfers the token into the message sender's wallet.
    /// @param signatureFromChip An EIP-191 signature of (msgSender, blockhash), where blockhash is the block hash for blockNumberUsedInSig.
    /// @param blockNumberUsedInSig The block number linked to the blockhash signed in signatureFromChip. Should be a recent block number.
    /// @param useSafeTransferFrom Whether EIP-721's safeTransferFrom should be used in the implementation, instead of transferFrom.
    ///
    /// @dev The implementation should check that block number be reasonably recent to avoid replay attacks of stale signatures.
    /// The implementation should also verify that the address signed in the signature matches msgSender.
    /// If the address recovered from the signature matches a chip address that's bound to an existing token, the token should be transferred to msgSender.
    /// If there is no existing token linked to the chip, the function should error.
    function transferTokenWithChip(
        bytes calldata signatureFromChip,
        uint256 blockNumberUsedInSig,
        bool useSafeTransferFrom
    ) external;

    /// @notice Calls transferTokenWithChip as defined above, with useSafeTransferFrom set to false.
    function transferTokenWithChip(bytes calldata signatureFromChip, uint256 blockNumberUsedInSig) external;

    /// @notice Emitted when a token is minted
    event PBTMint(uint256 indexed tokenId, address indexed chipAddress);

    /// @notice Emitted when a token is mapped to a different chip.
    /// Chip replacements may be useful in certain scenarios (e.g. chip defect).
    event PBTChipRemapping(uint256 indexed tokenId, address indexed oldChipAddress, address indexed newChipAddress);
}

```

To aid recognition that an [EIP-721](./eip-721.md) token implements physical binding via this EIP: upon calling [EIP-165](./eip-165.md)’s `function supportsInterface(bytes4 interfaceID) external view returns (bool)` with `interfaceID=0x4901df9f`, a contract implementing this EIP must return true.

The mint interface is up to the implementation. The minted NFT's owner should be the owner of the physical chip (this authentication could be implemented using the signature scheme defined for `transferTokenWithChip`).

## Rationale

This solution's intent is to be the simplest possible path towards linking physical items to digital NFTs without a centralized authority.

The interface includes a `transferTokenWithChip` function that's opinionated with respect to the signature scheme, in order to enable a downstream aggregator-like product that supports transfers of any NFTs that implement this EIP in the future.

### Out of Scope

The following are some peripheral problems that are intentionally not within the scope of this EIP:

- trusting that a specific NFT collection's chip addresses actually map to physical chips embedded in items, instead of arbitrary EOAs
- ensuring that the chip does not deterioriate or get damaged
- ensuring that the chip stays attached to the physical item
- etc.

Work is being done on these challenges in parallel.

Mapping token ids to chip addresses is also out of scope. This can be done in multiple ways, e.g. by having the contract owner preset this mapping pre-mint, or by having a `(tokenId, chipAddress)` tuple passed into a mint function that's pre-signed by an address trusted by the contract, or by doing a lookup in a trusted registry, or by assigning token ids at mint time first come first served, etc.

Additionally, it's possible for the owner of the physical item to transfer the NFT to a wallet owned by somebody else (by sending a chip signature to that other person for use). We still consider the NFT physical backed, as ownership management is tied to the physical item. This can be interpreted as the item's owner temporarily lending the item to somebody else, since (1) the item's owner must be involved for this to happen as the one signing with the chip, and (2) the item's owner can reclaim ownership of the NFT at any time.

## Backwards Compatibility

This proposal is backward compatible with [EIP-721](./eip-721.md) on an API level. As mentioned above, for the token to be physical-backed, the contract must use a account-bound implementation of [EIP-721](./eip-721.md) (all [EIP-721](./eip-721.md) functions that transfer must throw) so that transfers go through the new function introduced here, which requires a chip signature.

## Reference Implementation

The following is a snippet on how to recover a chip address from a signature.

```solidity
import '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';

function getChipAddressFromChipSignature(
  bytes calldata signatureFromChip,
  uint256 blockNumberUsedInSig
) internal returns (TokenData memory) {
  if (block.number <= blockNumberUsedInSig) {
    revert InvalidBlockNumber();
  }
  unchecked {
    if (block.number - blockNumberUsedInSig > getMaxBlockhashValidWindow()) {
      revert BlockNumberTooOld();
    }
  }
  bytes32 blockHash = blockhash(blockNumberUsedInSig);
  bytes32 signedHash = keccak256(abi.encodePacked(_msgSender(), blockHash))
    .toEthSignedMessageHash();
  address chipAddr = signedHash.recover(signatureFromChip);
}

```

## Security Considerations

The [EIP-191](./eip-191.md) signature passed to `transferTokenWithChip` requires the function caller's address in its signed data so that the signature cannot be used in a replay attack. It also requires a recent blockhash so that a malicious chip owner cannot pre-generate signatures to use after a short time window (e.g. after the owner of the physical item changes).

Additionally, the level of trust that one has for whether the token is physically-backed is dependent on the security of the physical chip, which is out of scope for this EIP as mentioned above.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md). 
