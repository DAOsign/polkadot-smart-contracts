FROM node:20-alpine

WORKDIR /usr/src/app

# # Install Rust and cargo-contract dependencies
# RUN apt-get update && apt-get install -y curl build-essential gcc git clang libssl-dev pkg-config

# # Install Rust and set the PATH environment variable
# RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
# ENV PATH="/root/.cargo/bin:${PATH}"

# Install Rust and Cargo
RUN apk add --no-cache curl gcc g++ make
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install the Rust source component
RUN rustup component add rust-src

# Install cargo-contract
RUN cargo install --force --locked cargo-contract

COPY package.json package-lock.json ./

RUN npm i

COPY . .

RUN npm run build

RUN npm run run:node

# Keep container running
CMD ["tail", "-f", "/dev/null"]

EXPOSE 9944
