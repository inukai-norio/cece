FROM rust:1-bullseye-slim AS builder
WORKDIR /usr/src/cece
RUN rustup toolchain install nightly
COPY . .
RUN cargo +nightly install --path .

FROM debian:bullseye-slim
COPY --from=builder /usr/local/cargo/bin/cece /usr/local/bin/cece
COPY docker-shell/docker-cece-entrypoint /usr/local/bin/docker-cece-entrypoint
ENTRYPOINT ["docker-cece-entrypoint"]
CMD ["cece", "-h"]
