FROM node:20-alpine

WORKDIR /usr/src/app

# Install Rust and Cargo
RUN apk add --no-cache curl gcc g++ make
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install the Rust source component
RUN rustup component add rust-src

# Install cargo-contract
RUN cargo install --force --locked cargo-contract

# Build and run blockchain node
COPY package.json package-lock.json ./

RUN npm i

COPY . .

RUN npm run build

# RUN npm run node:install
RUN npm run node:start

# Keep container running
CMD ["tail", "-f", "/dev/null"]

EXPOSE 9944
