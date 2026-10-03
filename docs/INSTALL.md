# Installation

## Quick install (recommended)

```sh
curl -fsSL https://raw.githubusercontent.com/MKMithun2806/cyn/main/install.py | python3
```

The repo-root [install.py](../install.py) needs only Python 3.8+ (stdlib
only) and does the whole job:

1. **Detects your platform** — OS, CPU architecture, and C library
   (musl vs glibc, found via the dynamic loader, `platform.libc_ver()`,
   or `ldd`).
2. **Picks the right release target**:

   | Detected | Target installed |
   |----------|------------------|
   | Linux x86_64 + glibc | `x86_64-unknown-linux-gnu` |
   | Linux x86_64 + musl (Alpine, ...) | `x86_64-unknown-linux-musl` |
   | Linux arm64 | `aarch64-unknown-linux-musl` |
   | macOS, Windows, other | *not supported* |

3. **Downloads the latest release** (resolves the newest `v*` tag, then
   fetches `cyn-<version>-<target>.tar.gz`).
4. **Verifies the sha256 checksum** against the published `.sha256`
   asset (aborts on mismatch).
5. **Smoke-tests the binary** (`cyn --version`) before it is installed,
   so a binary that cannot run on your system never lands on PATH.
6. **Installs to `~/.local/bin`** and adds it to PATH by appending to
   your shell rc (`~/.bashrc` / `~/.zshrc` / `~/.profile`) only when it
   isn't already there.

**Unsupported platforms** get an explicit message instead of a silent
failure: the detected OS/arch is reported, the published targets are
listed, and the docs point you to a source build.

### Installer options

```sh
# Pin a specific release
curl -fsSL https://raw.githubusercontent.com/MKMithun2806/cyn/main/install.py \
  | python3 - --version 0.4.1

# Install somewhere else (e.g. system-wide)
curl -fsSL https://raw.githubusercontent.com/MKMithun2806/cyn/main/install.py \
  | python3 - --install-dir /usr/local/bin

# Leave shell rc files alone
curl -fsSL https://raw.githubusercontent.com/MKMithun2806/cyn/main/install.py \
  | python3 - --no-modify-path
```

| Flag / env | Description |
|------------|-------------|
| `--version <X.Y.Z>` | Release to install (default: latest) |
| `--install-dir <DIR>` | Install directory (default `~/.local/bin`) |
| `CYN_INSTALL_DIR` | Same, via environment variable |
| `--no-modify-path` | Never edit shell rc files |

You can also run it directly: `python3 install.py`.

## Build prerequisites

Only needed if you build from source — the quick installer above just
needs Python 3.8+.

- **Rust** 1.75+ (via [rustup](https://rustup.rs/))
- **OpenVAS scanner source** — vendored in this repo under `openvas/`
  (a normal tracked directory, no submodule init needed)
- **nmap** — required at runtime for automatic port discovery (Cyn shells
  out to it unless you pass `--nmap <file>`; install it or bring your own
  nmap XML)
- **rsync** — required at runtime for `cyn feed update`
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

The [quick installer](#quick-install-recommended) picks the right archive
for you automatically. To grab one manually, check the
[Releases](https://github.com/MKMithun2806/cyn/releases) page:

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
