#!/bin/bash

set -eu

h1=(
    sha224
    sha256
    sha384
    sha512
    sm3
)

e1=(
    aes128
    aes192
    aes256
    aria128
    aria192
    aria256
    camellia128
    camellia192
    camellia256
    sm4
)

m1=(
    cbc
    cfb
    ofb1
    ofb8
    ofb64
    ofb128
)

cargo build --release > /dev/null 2>&1
CECE=./target/release/cece

for h in "${h1[@]}"
do
    for e in "${e1[@]}"
    do
        for m in "${m1[@]}"
        do
            $CECE -e -a "$h-$e-$m" -i testsfiles/sample.env -o temp
            $CECE -d -i temp -o temp2
            diff testsfiles/sample.env temp2 > /dev/null
        done
    done
done

$CECE -d -i testsfiles/sample.encrypt.env -o temp2
diff testsfiles/sample.env temp2 > /dev/null
