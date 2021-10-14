FROM rust:alpine3.13 AS builder
WORKDIR /usr/src/cece
RUN rustup toolchain install nightly
COPY . .
RUN cargo +nightly install --path .

FROM alpine:3.13
COPY --from=builder /usr/local/cargo/bin/cece /usr/local/bin/cece
CMD ["cece"]
