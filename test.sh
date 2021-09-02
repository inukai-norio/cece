#!/bin/bash

cargo run -- -e -i testsfiles/sample.env -o temp > /dev/null 2>&1
cargo run -- -d -i temp -o temp2 > /dev/null 2>&1
diff testsfiles/sample.env temp2 > /dev/null
exit $?
