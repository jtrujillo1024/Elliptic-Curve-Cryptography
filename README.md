# Elliptic-Curve-Cryptography

The elliptic curve cryptography repository will include python implementations of assymetric encryption, digital signatures, and various applicable algorithms such as the Extended Euclidean Algorithm.

Elliptic Curves are used for cryptographyically secure trapdoor functions protected by the computational limits of classical computers. Trapdoor functions are relatively fast to compute in one direction, but computationally infeasable in the opposite direction. For example, a private key is plugged into a cryptograpically secure elliptic curve (CS-EC) function to compute a corresponding public key. The public key may be available in plaintext without compromising the private key without a significant amount of computational resources and time. 

The Elliptic Curve in use includes cryptographically secure parameters set by the Standards for Efficient Cryptography, and is currently in use to generate public keys for Bitcoin and various other cryptocurrency public keys. Note that the public key is NOT the Bitcoin address, as the true address is the public key run through two different secure hashing algorithms multiple times including checksums and Base58 encoding.

#TODO include full EC-Digital Signature Algorithm
