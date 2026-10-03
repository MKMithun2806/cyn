#!/usr/bin/env python3
"""Cyn installer.

Detects the operating system, architecture and C library, downloads the
matching binary from the latest GitHub release, verifies its checksum,
installs it and puts it on PATH.

Quick install:

    curl -fsSL https://raw.githubusercontent.com/MKMithun2806/cyn/main/install.py | python3

Requires Python 3.8+ and no third-party packages.
"""

import argparse
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request

REPO = "MKMithun2806/cyn"
RELEASES_LATEST = "https://github.com/{}/releases/latest".format(REPO)
DOWNLOAD_BASE = "https://github.com/{}/releases/download".format(REPO)
API_LATEST = "https://api.github.com/repos/{}/releases/latest".format(REPO)
USER_AGENT = "cyn-installer"

# Targets published by .github/workflows/release.yml
SUPPORTED_TARGETS = (
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
)


class InstallerError(Exception):
    """Fatal installer problem with a user-facing message."""


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

def detect_os():
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith(("win", "cygwin", "msys")):
        return "windows"
    return sys.platform


def detect_arch():
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    return machine


def detect_libc():
    """Return 'musl', 'glibc' or None (non-Linux)."""
    if detect_os() != "linux":
        return None

    # A musl dynamic loader on disk is the strongest signal (Alpine etc.).
    for name in (
        "ld-musl-x86_64.so.1",
        "ld-musl-aarch64.so.1",
        "ld-musl-armhf.so.1",
        "ld-musl-i386.so.1",
    ):
        for directory in ("/lib", "/lib64", "/usr/lib"):
            if os.path.exists(os.path.join(directory, name)):
                return "musl"

    libc, _ = platform.libc_ver()
    if "musl" in libc:
        return "musl"
    if libc:
        return "glibc"

    # Last resort: ask ldd what it is linked against.
    try:
        proc = subprocess.run(
            ["ldd", "--version"], capture_output=True, text=True, timeout=5
        )
        blob = (proc.stdout + proc.stderr).lower()
        if "musl" in blob:
            return "musl"
        if "glibc" in blob or "gnu" in blob:
            return "glibc"
    except (OSError, subprocess.SubprocessError):
        pass

    return "glibc"


def select_target(os_name, arch, libc):
    """Map the detected platform to a release target triple, or None."""
    if os_name != "linux":
        return None
    if arch == "x86_64":
        if libc == "musl":
            return "x86_64-unknown-linux-musl"
        return "x86_64-unknown-linux-gnu"
    if arch == "aarch64":
        # The only published arm64 build is musl; verification after
        # install confirms whether it can actually run here.
        return "aarch64-unknown-linux-musl"
    return None


def unsupported_message(os_name, arch, libc):
    detected = "{} {}{}".format(
        os_name,
        arch,
        " ({})".format(libc) if libc else "",
    )
    lines = [
        "error: no prebuilt Cyn release for your platform ({})".format(detected),
        "",
        "Published release targets:",
    ]
    lines += ["  - {}".format(t) for t in SUPPORTED_TARGETS]
    lines += [
        "",
        "macOS and Windows builds are not currently published.",
        "Build from source instead:",
        "  https://github.com/{}/blob/main/docs/INSTALL.md".format(REPO),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Release resolution and download
# ---------------------------------------------------------------------------

def _http_get(url, timeout=30):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(request, timeout=timeout)


def resolve_version(explicit):
    if explicit:
        return explicit.lstrip("v")

    # Following the /releases/latest redirect reveals the tag without
    # touching the (rate-limited) GitHub API.
    try:
        with _http_get(RELEASES_LATEST) as response:
            final_url = response.geturl()
        match = re.search(r"/releases/tag/v?([^/?#]+)", final_url)
        if match:
            return match.group(1)
    except (urllib.error.URLError, OSError):
        pass

    # Fallback: GitHub API.
    try:
        import json

        with _http_get(API_LATEST) as response:
            data = json.loads(response.read().decode("utf-8"))
        tag = data.get("tag_name") or ""
        if tag:
            return tag.lstrip("v")
    except (urllib.error.URLError, OSError, ValueError):
        pass

    raise InstallerError(
        "could not determine the latest Cyn release.\n"
        "Check https://github.com/{}/releases or pass --version "
        "<version> explicitly.".format(REPO)
    )


def download(url, destination, what):
    try:
        with _http_get(url, timeout=120) as response, open(destination, "wb") as handle:
            shutil.copyfileobj(response, handle)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise InstallerError(
                "{} not found:\n  {}\n"
                "It may not have been published for this release yet.".format(what, url)
            )
        raise InstallerError("failed to download {}:\n  {}".format(what, error))
    except (urllib.error.URLError, OSError) as error:
        raise InstallerError("failed to download {}:\n  {}".format(what, error))


def verify_checksum(archive, checksum_file):
    expected = ""
    with open(checksum_file, "r", encoding="utf-8", errors="replace") as handle:
        first_line = handle.readline().strip()
    if first_line:
        expected = first_line.split()[0].lower()
    if not expected:
        print("warning: checksum file was empty, skipping verification")
        return

    digest = hashlib.sha256()
    with open(archive, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected:
        raise InstallerError(
            "checksum mismatch for {}\n  expected {}\n  got      {}".format(
                os.path.basename(archive), expected, actual
            )
        )
    print("  checksum verified (sha256)")


# ---------------------------------------------------------------------------
# Install and PATH handling
# ---------------------------------------------------------------------------

def default_install_dir():
    override = os.environ.get("CYN_INSTALL_DIR")
    if override:
        return os.path.abspath(os.path.expanduser(override))
    return os.path.join(os.path.expanduser("~"), ".local", "bin")


def extract_binary(archive, destination_dir):
    with tarfile.open(archive, "r:gz") as bundle:
        member = None
        for candidate in bundle.getmembers():
            if candidate.isfile() and os.path.basename(candidate.name) == "cyn":
                member = candidate
                break
        if member is None:
            raise InstallerError(
                "archive {} does not contain a cyn binary".format(
                    os.path.basename(archive)
                )
            )
        source = bundle.extractfile(member)
        if source is None:
            raise InstallerError("could not read cyn from the archive")
        binary_path = os.path.join(destination_dir, "cyn")
        with open(binary_path, "wb") as handle:
            shutil.copyfileobj(source, handle)
    os.chmod(binary_path, 0o755)
    return binary_path


def is_on_path(directory):
    return directory in os.environ.get("PATH", "").split(os.pathsep)


def shell_rc_path():
    shell = os.environ.get("SHELL", "").lower()
    if "zsh" in shell:
        return os.path.join(os.path.expanduser("~"), ".zshrc")
    if "bash" in shell:
        return os.path.join(os.path.expanduser("~"), ".bashrc")
    return os.path.join(os.path.expanduser("~"), ".profile")


def add_directory_to_path(directory):
    """Persist `export PATH=<directory>:$PATH` in the shell rc if needed.

    Returns (rc_path, already_configured).
    """
    rc_path = shell_rc_path()
    export_line = 'export PATH="{}:$PATH"'.format(directory)
    marker = "# added by the cyn installer"

    existing = ""
    if os.path.exists(rc_path):
        with open(rc_path, "r", encoding="utf-8", errors="replace") as handle:
            existing = handle.read()
    if directory in existing:
        return rc_path, True

    with open(rc_path, "a", encoding="utf-8") as handle:
        if existing and not existing.endswith("\n"):
            handle.write("\n")
        handle.write("\n{}\n{}\n".format(marker, export_line))
    return rc_path, False


def verify_binary(binary_path):
    """Run `cyn --version`; return (ok, output)."""
    try:
        proc = subprocess.run(
            [binary_path, "--version"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return False, str(error)
    output = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, output


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def install(args):
    os_name = detect_os()
    arch = detect_arch()
    libc = detect_libc()

    target = select_target(os_name, arch, libc)
    if target is None:
        print(unsupported_message(os_name, arch, libc))
        return 1

    print("detected: {} {}{} -> {}".format(
        os_name,
        arch,
        " ({})".format(libc) if libc else "",
        target,
    ))

    version = resolve_version(args.version)
    asset = "cyn-{}-{}.tar.gz".format(version, target)
    asset_url = "{}/{}/{}".format(DOWNLOAD_BASE, "v" + version, asset)
    print("latest release: v{}".format(version))

    with tempfile.TemporaryDirectory(prefix="cyn-install-") as workdir:
        archive = os.path.join(workdir, asset)
        print("downloading {}".format(asset_url))
        download(asset_url, archive, "release asset for {}".format(target))

        checksum_file = archive + ".sha256"
        try:
            download(asset_url + ".sha256", checksum_file, "checksum file")
            verify_checksum(archive, checksum_file)
        except InstallerError as error:
            # A missing checksum asset is a warning; a real mismatch aborts.
            if "not found" in str(error):
                print("  warning: no checksum file published, skipping verification")
            else:
                raise

        install_dir = os.path.abspath(
            os.path.expanduser(args.install_dir or default_install_dir())
        )
        try:
            os.makedirs(install_dir, exist_ok=True)
        except OSError as error:
            raise InstallerError(
                "cannot create install directory {}:\n  {}".format(install_dir, error)
            )

        binary_path = extract_binary(archive, workdir)

        # Verify before touching the final location so a binary that cannot
        # run here never lands on PATH.
        ok, output = verify_binary(binary_path)
        if not ok:
            print(
                "\nerror: the downloaded binary failed its smoke test on this "
                "system, so it was not installed:\n  {}".format(output or "no output")
            )
            print(unsupported_message(os_name, arch, libc))
            return 1

        final_path = os.path.join(install_dir, "cyn")
        try:
            shutil.move(binary_path, final_path)
        except OSError:
            # Cross-device or permission issue: fall back to copy + chmod.
            shutil.copyfile(binary_path, final_path)
            os.chmod(final_path, 0o755)
        installed_version = output

    print("\ninstalled {} -> {}".format(installed_version, final_path))

    if is_on_path(install_dir):
        print("  PATH: {} is already on PATH".format(install_dir))
    elif args.no_modify_path:
        print(
            "  PATH: add {} to your PATH manually:\n"
            '      export PATH="{}:$PATH"'.format(install_dir, install_dir)
        )
    else:
        rc_path, configured = add_directory_to_path(install_dir)
        if configured:
            print(
                "  PATH: {} is already configured in {} — restart your "
                "shell or run:\n      source {}".format(
                    install_dir, rc_path, rc_path
                )
            )
        else:
            print(
                "  PATH: added {} to {}\n"
                "      restart your shell or run:\n"
                "      source {}".format(install_dir, rc_path, rc_path)
            )

    print("\nNext steps:\n  cyn feed update\n  cyn scan <target>")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="install.py",
        description="Install the latest Cyn release for this platform.",
    )
    parser.add_argument(
        "--version",
        help="release version to install (default: latest, e.g. 0.4.1)",
    )
    parser.add_argument(
        "--install-dir",
        help="directory to install into (default: ~/.local/bin, "
        "env: CYN_INSTALL_DIR)",
    )
    parser.add_argument(
        "--no-modify-path",
        action="store_true",
        help="do not edit shell rc files to update PATH",
    )
    args = parser.parse_args(argv)

    try:
        return install(args)
    except InstallerError as error:
        print("error: {}".format(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nerror: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
