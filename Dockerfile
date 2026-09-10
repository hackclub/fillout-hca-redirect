FROM rust:1-slim-bookworm AS builder

# aws-lc-sys (via reqwest's rustls backend) needs a C toolchain and cmake
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 app

COPY --from=builder /build/target/release/fillout-hca-redirect /usr/local/bin/fillout-hca-redirect

USER app
EXPOSE 8080

CMD ["fillout-hca-redirect"]
