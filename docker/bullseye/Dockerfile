FROM rust:bullseye AS builder
WORKDIR /usr/src/cece
RUN rustup toolchain install nightly
RUN rustup +nightly target add x86_64-unknown-linux-musl
COPY . .
RUN cargo +nightly install --target=x86_64-unknown-linux-musl --path .

FROM debian:bullseye-slim
COPY --from=builder /usr/local/cargo/bin/cece /usr/local/bin/cece
COPY docker-shell/docker-cece-entrypoint /usr/local/bin/docker-cece-entrypoint
ENTRYPOINT ["docker-cece-entrypoint"]
CMD ["cece", "-h"]
