Merkle Tree with RSA Signing and Verification
=============================================

This project is an implementation of a Merkle Tree with support for cryptographic 
signing and verification using RSA. It provides an interactive console-based 
interface for users to manage the tree, generate proofs of inclusion, and sign/verify 
the tree's root using RSA keys.

--------------------------------------------------------
Features:
1. Merkle Tree Operations:
   - Add leaves and compute the Merkle Tree root.
   - Generate and verify proofs of inclusion.

2. Cryptographic Operations:
   - Generate RSA private and public keys.
   - Sign the Merkle Tree root with an RSA private key.
   - Verify the signature of the root using an RSA public key.

3. Console-Based Interface:
   - Interact with the tree and cryptographic operations through 
     numbered commands.

--------------------------------------------------------
Setup:
Requirements:
- Python 3.6 or later
- cryptography library

Installation:
1. Clone the repository:
   git clone https://github.com/SimonFraiberg/MerkleTree.git

2. Install dependencies:
   pip install cryptography

--------------------------------------------------------
Usage:
Run the script:
   python merkle_tree.py

Commands:
1. Add a leaf:
   1 <data>
   Example: 
   1 example_data

2. Get the root:
   2

3. Generate proof of inclusion:
   3 <leaf_index>
   Example: 
   3 0

4. Verify proof of inclusion:
   4 <leaf_value> <proof_hashes>
   Example: 
   4 example_data 1<hash1> 0<hash2>

5. Generate RSA keys:
   5

6. Sign the root with RSA private key:
   6
   Paste the private key when prompted.

7. Verify the root's RSA signature:
   7
   Paste the public key and signature when prompted.

