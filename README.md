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

Compilation Errors
------------------

Some older installed system do not support AESNI instructions, and cabal
doesn't have a good mechanism for doing discovery of those old systems
limitations.

One can use the following lists of command to solve the problems (doing forget to substitute what need be):

    cabal unpack cipher-aes
    cd cipher-aes-<VERSION>
    cabal configure --flag -support_aesni <OTHER OPTIONS>
    cabal install

Another alternative is upgrading your userspace environment to have a gcc version that is at least >= 4.4 (2009),
and a binutils >= 2.18 (2007).
