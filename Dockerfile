FROM node:20

WORKDIR /usr/src/app

# Install Rust and Cargo dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    g++ \
    make \
    libssl-dev \
    pkg-config
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
# RUN npm run node:start

# Sleep for a while to keep the container running
# RUN sleep 60

# RUN npm run test

# Keep container running
CMD ["tail", "-f", "/dev/null"]

EXPOSE 9944
