FROM node:20-alpine

WORKDIR /usr/src/app

# Install Rust and Cargo
RUN apk add --no-cache \
    curl \
    gcc \
    g++ \
    make \
    libressl-dev \
    libressl \
#    openssl \
#    openssl-dev \
    pkgconfig
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install the Rust toolchain
RUN rustup update stable
RUN rustup toolchain install nightly
RUN rustup default nightly
RUN rustup show

# Install the Rust source component
RUN rustup component add rust-src

# Install cargo-contract
RUN cargo install cargo-dylint dylint-link --force websocat
RUN cargo install --force cargo-contract --version 3.2.0

# Build and run blockchain node
# COPY package.json package-lock.json ./

COPY . .
RUN npm i
RUN npm run build

# Run unit tests
# RUN cd contracts/daosign_app && cargo test -- --nocapture && cargo clean
# RUN cd contracts/daosign_eip712 && cargo test -- --nocapture

# Run integration tests
# RUN npm run node:install
RUN npm run node:start

# Run e2e tests
# RUN npm run test

# Keep container running
CMD ["tail", "-f", "/dev/null"]

EXPOSE 9944
