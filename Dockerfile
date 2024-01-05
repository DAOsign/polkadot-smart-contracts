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

RUN yarn global add @astar-network/swanky-cli

RUN yarn install --non-interactive --frozen-lockfile

COPY . .

RUN yarn build

CMD ["yarn", "run:node"]

# Keep container running
CMD ["tail", "-f", "/dev/null"]

EXPOSE 9944
