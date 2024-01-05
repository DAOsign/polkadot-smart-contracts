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

COPY package.json yarn.lock ./

RUN yarn install --non-interactive --frozen-lockfile

COPY . .

# RUN yarn build

# CMD ["yarn", "node"]

COPY $PWD/docker/entrypoint.sh /usr/local/bin

ENTRYPOINT ["/bin/sh", "/usr/local/bin/entrypoint.sh"]

EXPOSE 9944
