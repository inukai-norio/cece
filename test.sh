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
    cfb1
    cfb8
    cfb64
    cfb128
    ofb
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

$CECE -d -i testsfiles/all_algo.encrypt.env -o temp2
diff testsfiles/all_algo.env temp2 > /dev/null
