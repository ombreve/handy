# handy: A Low-tech Randomized Symmetric-key Cipher

This program encodes files with the Handy cipher.

Read the specification document by Bruce Kallick:
[Handycipher: a Low-tech, Randomized, Symmetric-key
Cryptosystem](./handy.pdf)

See the included man page for option details.

## Installation

Clone this repository, then:

    $ make PREFIX=/usr/local install

This will install both the compiled binary and a manual page under `PREFIX`.

## Example

    $ echo 'ABCDEFGHIJKLMNOPQRSTUVWXYabcdefghijklmnopqrstuvwxy^' >test.key
    $ echo TEST | handy --trace -k test.key -o test
    Key: ABCDEFGHIJKLMNOPQRSTUVWXYabcdefghijklmnopqrstuvwxy^
    Subkey: ABCDEFGHIJKLMNOPQRSTUVWXYZ.,?-^
    A B C D E | F G H I J
    K L M N O | P Q R S T
    U V W X Y | a b c d e
    f g h i j | k l m n o
    p q r s t | u v w x y

    T 20 10100 D3  YC    YC        kYC
    E  5 00101 R2  MK    MK        bMTxK
    S 19 10011 C4  iDs   iDjsf     iJDQjsuf
    T 20 10100 D3  qY    qYL       vGqSYL

    $ handy -d --trace test
    Key: ABCDEFGHIJKLMNOPQRSTUVWXYabcdefghijklmnopqrstuvwxy^
    Subkey: ABCDEFGHIJKLMNOPQRSTUVWXYZ.,?-^
    A B C D E | F G H I J
    K L M N O | P Q R S T
    U V W X Y | a b c d e
    f g h i j | k l m n o
    p q r s t | u v w x y

    kYCb                             YC    D3  10100 20 T
    MTxK                             MK    R2  00101  5 E
    iJDQjsufvG                       iDs   C4  10011 19 S
    qSYL                             qY    D3  10100 20 T

# Implementation notes

For convenience, spaces (C Library `isspace()`) are ignored from the input.

The random source is a version of [PCG](http://www.pcg-random.org).

To randomly loop through all the permutations of a set, we rank each
permutation using the algorithm presented in
[Ranking and unranking permutations in linear
time](https://webhome.cs.uvic.ca/~ruskey/Publications/RankPerm/RankPerm.html)
by Wendy Myrvold and Frank Ruskey.

To shuffle the elements of a set, we use D. Knuth's implementation of the
[Fisher-Yates algorithm](https://en.wikipedia.org/wiki/Fisher–Yates_shuffle).

If no key file is given, a unique key is derived from a passphrase:
the SHA256 hash of the passphrase is used as seed for the PCG source and
the 51 characters A-Ya-y^ are shuffled into a key.

