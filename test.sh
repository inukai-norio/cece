#!/bin/bash

set -eu

cargo run -- -e -i testsfiles/sample.env -o temp > /dev/null 2>&1
cargo run -- -d -i temp -o temp2 > /dev/null 2>&1
diff testsfiles/sample.env temp2 > /dev/null

cargo run -- -d -i testsfiles/sample.encrypt.env -o temp2 > /dev/null 2>&1
diff testsfiles/sample.env temp2 > /dev/null
