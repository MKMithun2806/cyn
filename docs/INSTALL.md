# Installation

## Prerequisites

- **Rust** 1.75+ (via [rustup](https://rustup.rs/))
- **OpenVAS submodule** (included in this repo)
- System libraries (see below)
- **nmap** (optional, for port discovery import)

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

## Pre-built binaries

Check the [Releases](https://github.com/MKMithun2806/cyn/releases) page
for pre-built binaries:

| Target | Archive |
|--------|---------|
| Linux amd64 (musl) | `cyn-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 (musl) | `cyn-<version>-aarch64-unknown-linux-musl.tar.gz` |
| Windows amd64 | `cyn-<version>-x86_64-pc-windows-msvc.zip` |
| macOS ARM | `cyn-<version>-aarch64-apple-darwin.tar.gz` |

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

## Nmap integration (optional)

For targeted scans, use nmap to discover ports first:

```sh
# Install nmap (if not already installed)
sudo apt-get install nmap    # Debian/Ubuntu
sudo apk add nmap            # Alpine
sudo dnf install nmap        # Fedora

# Discover ports
nmap -sV -oX scan.xml 192.168.1.1

# Feed into Cyn
cyn scan 192.168.1.1 --nmap scan.xml
```
