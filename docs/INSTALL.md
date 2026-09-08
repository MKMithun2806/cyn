# Installation

## Prerequisites

- **Rust** 1.75+ (via [rustup](https://rustup.rs/))
- **OpenVAS submodule** (included in this repo)
- System libraries (see below)

### Alpine Linux

```sh
sudo apk add \
  cmake clang-dev musl-dev libpcap-dev \
  libssh-dev libressl-dev perl sqlite-dev
```

### Debian / Ubuntu

```sh
sudo apt-get install -y \
  cmake clang libclang-dev llvm-dev \
  libpcap-dev libsnmp-dev libssl-dev \
  libssh2-1-dev zlib1g-dev
```

### Fedora / RHEL

```sh
sudo dnf install -y \
  cmake clang clang-devel llvm-devel \
  libpcap-devel net-snmp-devel openssl-devel \
  libssh2-devel zlib-devel
```

## Build from source

```sh
git clone --recursive https://github.com/MKMithun2806/cyn.git
cd cyn
cargo build --release
```

The binary is at `target/release/cyn`.

## Feed setup

Cyn requires the OpenVAS NVT feed. Update it:

```sh
cyn feed update
```

Or set a custom path:

```sh
export CYN_FEED_PATH=/path/to/feed
cyn feed status
```

## Verify installation

```sh
cyn --help
cyn feed status
```
