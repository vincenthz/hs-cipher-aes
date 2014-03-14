Fast AES for haskell
====================

This is a simple and efficient AES implementation providing all most important
mode of operations.

Modes supported:

* ECB
* CBC
* CTR
* XTS
* GCM
* OCB

Implementation details:

* C implementation.
* Pure interface to haskell.
* support AESNI instructions if available (Intel and AMD).
* GCM mode only works on byte boundary.

TODO:

* remove create\_round\_key from sw implementation.
* add aesni acceleration for aes192.
* add pclmulqdq acceleration for GF.
* make galois multiplication endian safe.
* optimise further (lots of low hanging fruits).
* add a streaming GCM API
* GCM's GMAC support
