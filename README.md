# What is this?
libpqkex can be used as a post-quantum key agreement scheme and can replace X25519. (It's a X25519 SNTRUP761 hybrid).

It provides three functions:

`pqkex_keygen` to generate a key pair

`pqkex_encaps` to start a key exchange on one side

`pqkex_decaps` to finish a key exchange on the other side

# How do I use it?
Just put pqkex.c and pqkex.h into your own project and include the pqkex.h file.
Private keys have a size of PQKEX\_SKSIZE (1795 bytes), public keys have a size of PQKEX\_PKSIZE (1190 bytes), the ciphertext to be exchanged has a size of PQKEX\_CTSIZE (1071) and the whole exchange returns a shared secret of size PQKEX\_SSSIZE (64 bytes or 512 bits) that can be used as a key.

The Makefile also builds libpqkex.so, libpqkex.a and libpqkex.o so you can chose yours.

# Security
libpqkex works by doing a X25519 exchange and a SNTRUP761 exchange and then hashing the concatenated secrets with SHA512. This is very similar to what OpenSSH does and should be secure as long as at least one of the two primitives used isn't broken.

The code should be constant time although I haven't verified that yet.

# License
This code is public domain and is a compilation of a bunch of public domain code written by DJB and others. I only put it into one file and made it work.
