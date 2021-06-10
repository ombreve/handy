# handy: the low-tech randomized symmetric-key Handycipher

This program encodes files with the Handy cipher. See the specification
document by Bruce Kallick:
*Handycipher: a Low-tech, Randomized, Symmetric-key Cryptosystem*.

Note that, for convenience, spaces characters are ignored from the input.

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

