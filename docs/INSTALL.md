# Installation

## Prerequisites

- **Rust** 1.75+ (via [rustup](https://rustup.rs/))
- **OpenVAS scanner source** — vendored in this repo under `openvas/`
  (a normal tracked directory, no submodule init needed)
- **nmap** — required for automatic port discovery (Cyn shells out to it
  unless you pass `--nmap <file>`; install it or bring your own nmap XML)
- **rsync** — required for `cyn feed update`
- System libraries (see below)

### Alpine Linux

```sh
sudo apk add \
  cmake clang-dev musl-dev libpcap-dev \
  libssh-dev libressl-dev perl sqlite-dev \
  capnproto nmap rsync
```

### Debian / Ubuntu

```sh
sudo apt-get install -y \
  cmake clang libclang-dev llvm-dev \
  libpcap-dev libsnmp-dev libssl-dev \
  libssh2-1-dev zlib1g-dev \
  capnproto nmap rsync
```

### Fedora / RHEL

```sh
sudo dnf install -y \
  cmake clang clang-devel llvm-devel \
  libpcap-devel net-snmp-devel openssl-devel \
  libssh2-devel zlib-devel \
  capnproto nmap rsync
```

`capnproto` is needed at build time: `sequoia-ipc`'s build script shells
out to `capnp`.

## Pre-built binaries

Check the [Releases](https://github.com/MKMithun2806/cyn/releases) page
for pre-built binaries:

| Target | Archive |
|--------|---------|
| Linux amd64 (glibc) | `cyn-<version>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux amd64 (musl) | `cyn-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 (musl) | `cyn-<version>-aarch64-unknown-linux-musl.tar.gz` |

Each archive ships with a `.sha256` checksum file. Releases are published
automatically when the version in `Cargo.toml` changes.

## Build from source

```sh
git clone https://github.com/MKMithun2806/cyn.git
cd cyn
cargo build --release
```

The binary is at `target/release/cyn`.

CI builds static `krb5`/`libpcap` archives before running cargo
(`make -C openvas/rust/crates/nasl-c-lib`). On a clean checkout you may
need to do the same once if the build complains about
`build-cache/archives/include`.

## Feed setup

Cyn requires the OpenVAS NVT feed (~95,000 scripts). Update it:

```sh
cyn feed update
```

Or set a custom path:

```sh
export CYN_FEED_PATH=/path/to/feed
cyn feed status
```

The default feed location is `~/.local/share/cyn/plugins` (override with
`--feed` or `CYN_FEED_PATH`).

## Verify installation

```sh
cyn --help
cyn feed status
```

## Nmap integration (optional)

Automatic discovery runs `nmap` for you. To skip the built-in discovery
run — or to reuse a scan you already did — import nmap XML directly:

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

See [SCANNING.md](SCANNING.md) for the full scan pipeline and options.
