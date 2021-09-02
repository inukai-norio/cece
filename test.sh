#!/bin/bash

cargo run -- -e -i testsfiles/sample.env -o temp
cargo run -- -d -i temp -o temp2
diff testsfiles/sample.env temp2
exit $?
