#!/usr/bin/env python3
"""
TheUpd8r

A deliberately unexciting system update utility.

Runs only as root.
Refuses to operate if anything looks unusual.
Verifies its own integrity before doing anything helpful.

Configuration, environment files, and keys are expected to be
sensibly owned, appropriately restricted, and not trying anything clever.

Proxy credentials are decrypted only at runtime and are written
nowhere permanent.

If verification fails, TheUpd8r will stop.
If updates fail, it will stop.
If everything succeeds, it will exit quietly.

Kernel updates are the one exception: the unattended (systemd) run
cannot apply them because the boot mount is read-only in that context.
When one is pending, the unattended run defers the upgrade and leaves
a login notice asking an administrator to run `sudo theUpd8r` from a
shell, where the update is applied normally.

No interaction is required.
No interaction is offered.
This is working as intended.
"""

import json
import os
import stat
import hashlib
import hmac
import fcntl
import subprocess
from pathlib import Path

from cryptography.fernet import Fernet

# --------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------

CONFIG_PATH = Path(
    os.environ.get("TheUpd8r_CONFIG", "/etc/theupd8r/TheUpd8r_config.json")
)
ALLOW_REPIN = os.environ.get("THEUPD8R_ALLOW_REPIN") == "1"
LOCK_PATH = "/run/theupd8r.lock"

# Package name prefixes treated as kernel updates (require a writable /boot).
KERNEL_PKG_PREFIXES = (
    "linux-image",
    "linux-headers",
    "linux-modules",
    "linux-generic",
    "linux-signed",
    "linux-virtual",
)

# Login notices shown while a kernel update is pending.
MOTD_NOTICE = Path("/etc/update-motd.d/99-theupd8r-kernel")
PROFILE_NOTICE = Path("/etc/profile.d/theupd8r-kernel-notice.sh")


# --------------------------------------------------------------------
# Security helpers
# --------------------------------------------------------------------

def require_root():
    if os.geteuid() != 0:
        raise SystemExit("[TheUpd8r] ERROR: Must be run as root.")


def set_umask():
    os.umask(0o077)


def acquire_lock():
    fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("[TheUpd8r] ERROR: Another instance is already running.")
    return fd


def check_secure_dir(path: Path, desc: str):
    if not path.exists():
        raise SystemExit(f"[TheUpd8r] ERROR: Missing {desc}: {path}")
    if path.is_symlink():
        raise SystemExit(f"[TheUpd8r] ERROR: {desc} is a symlink: {path}")

    st = path.stat()
    if st.st_uid != 0:
        raise SystemExit(f"[TheUpd8r] ERROR: {desc} not owned by root: {path}")

    mode = stat.S_IMODE(st.st_mode)
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SystemExit(
            f"[TheUpd8r] ERROR: {desc} is group/world writable: {oct(mode)}"
        )


def open_secure_ro(path: Path, desc: str, require_private: bool = True) -> int:
    # require_private=True  : secrets — no group/other access at all.
    # require_private=False : binaries — group/other may read/execute
    #                         (e.g. apt-get is 0755), but never write.
    try:
        fd = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except FileNotFoundError:
        raise SystemExit(f"[TheUpd8r] ERROR: Missing {desc}: {path}")
    except OSError as e:
        raise SystemExit(f"[TheUpd8r] ERROR: Cannot open {desc}: {path} ({e})")

    st = os.fstat(fd)

    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise SystemExit(f"[TheUpd8r] ERROR: {desc} is not a regular file: {path}")

    if st.st_uid != 0:
        os.close(fd)
        raise SystemExit(f"[TheUpd8r] ERROR: {desc} not owned by root: {path}")

    mode = stat.S_IMODE(st.st_mode)
    forbidden = (stat.S_IRWXG | stat.S_IRWXO) if require_private \
        else (stat.S_IWGRP | stat.S_IWOTH)
    if mode & forbidden:
        os.close(fd)
        raise SystemExit(
            f"[TheUpd8r] ERROR: {desc} has insecure permissions: {oct(mode)}"
        )

    return fd


def sha256_fd(fd: int) -> str:
    h = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------
# Config + binary verification
# --------------------------------------------------------------------

def load_config() -> dict:
    check_secure_dir(CONFIG_PATH.parent, "config directory")
    fd = open_secure_ro(CONFIG_PATH, "config")
    try:
        data = os.read(fd, os.fstat(fd).st_size)
        return json.loads(data.decode("utf-8"))
    finally:
        os.close(fd)


def atomic_write_config(cfg: dict):
    tmp = CONFIG_PATH.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_PATH)


def verify_binaries(cfg: dict):
    bins = cfg.get("binaries", {})

    for name, info in bins.items():
        path = Path(info["path"])
        expected = info["sha256"]

        fd = open_secure_ro(path, f"binary {name}", require_private=False)
        try:
            actual = sha256_fd(fd)
        finally:
            os.close(fd)

        if hmac.compare_digest(actual, expected):
            continue

        print(f"[TheUpd8r] WARNING: Binary hash mismatch: {name}")

        if name == "the_updater":
            raise SystemExit(
                "[TheUpd8r] ERROR: Self hash mismatch. Re-run setup."
            )

        if not ALLOW_REPIN:
            raise SystemExit(
                "[TheUpd8r] ERROR: Hash re-pinning not permitted."
            )

        res = subprocess.run(
            ["dpkg-query", "-S", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )

        if res.returncode != 0 or not res.stdout.strip():
            raise SystemExit(
                "[TheUpd8r] ERROR: Could not determine owning package."
            )

        pkg = res.stdout.split(":", 1)[0].strip()

        vres = subprocess.run(
            ["dpkg", "-V", pkg],
            capture_output=True,
            text=True,
            check=False,
        )

        if vres.stdout.strip():
            raise SystemExit(
                "[TheUpd8r] ERROR: Package integrity verification failed."
            )

        cfg["binaries"][name]["sha256"] = actual
        atomic_write_config(cfg)
        print(f"[TheUpd8r] Re-pinned hash for {name}.")


# --------------------------------------------------------------------
# Kernel update deferral
# --------------------------------------------------------------------

def pending_kernel_updates(apt: str, opts: list, env: dict) -> list:
    """Return kernel package names a dist-upgrade would install."""
    res = subprocess.run(
        [apt, *opts, "-s", "-y", "dist-upgrade"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
        close_fds=True,
        cwd="/",
    )
    pkgs = []
    for line in res.stdout.splitlines():
        if line.startswith("Inst "):
            name = line.split()[1]
            if name.startswith(KERNEL_PKG_PREFIXES):
                pkgs.append(name)
    return pkgs


def write_kernel_notice(pkgs: list):
    body = (
        "\n"
        "*** Kernel update required ***\n"
        f"Pending: {', '.join(sorted(pkgs))}\n"
        "TheUpd8r cannot apply kernel updates unattended\n"
        "(the boot mount is read-only in that context).\n"
        "Run:  sudo theUpd8r\n"
        "\n"
    )
    if MOTD_NOTICE.parent.is_dir():
        MOTD_NOTICE.write_text(
            "#!/bin/sh\ncat <<'EOF'" + body + "EOF\n", encoding="utf-8"
        )
        os.chmod(MOTD_NOTICE, 0o755)
    PROFILE_NOTICE.write_text(
        "cat <<'EOF'" + body + "EOF\n", encoding="utf-8"
    )
    os.chmod(PROFILE_NOTICE, 0o644)


def clear_kernel_notice():
    for p in (MOTD_NOTICE, PROFILE_NOTICE):
        try:
            p.unlink()
        except FileNotFoundError:
            pass


# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------

def main():
    require_root()
    set_umask()
    lock_fd = acquire_lock()

    pinned = os.environ.get("TheUpd8r_SHA256")
    if pinned:
        fd = open_secure_ro(Path(__file__).resolve(), "self")
        try:
            my_hash = sha256_fd(fd)
        finally:
            os.close(fd)

        if not hmac.compare_digest(my_hash, pinned):
            raise SystemExit("[TheUpd8r] ERROR: Self-hash mismatch.")

    cfg = load_config()
    verify_binaries(cfg)

    env_file = Path(cfg["env_file"])
    key_file = Path(cfg["key_file"])

    check_secure_dir(env_file.parent, "env directory")
    check_secure_dir(key_file.parent, "key directory")

    env_fd = open_secure_ro(env_file, "env_file")
    key_fd = open_secure_ro(key_file, "key_file")

    try:
        raw_env = os.read(env_fd, os.fstat(env_fd).st_size).decode()
        key = os.read(key_fd, os.fstat(key_fd).st_size)
    finally:
        os.close(env_fd)
        os.close(key_fd)

    fernet = Fernet(key)

    env_map = {}
    for line in raw_env.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env_map[k.strip()] = v.strip()

    def decrypt(name: str) -> str:
        token = env_map[cfg["variables"][name]]
        return fernet.decrypt(token.encode()).decode()

    scheme = decrypt("scheme")
    host = decrypt("host")
    port = decrypt("port")
    user = decrypt("user")
    password = decrypt("password")

    proxy_url = f"{scheme}://{user}:{password}@{host}:{port}"

    env = {
        "DEBIAN_FRONTEND": "noninteractive",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
    }

    apt = cfg["binaries"]["apt_get"]["path"]
    opts = [
        "-o", f"Acquire::http::Proxy={proxy_url}",
        "-o", f"Acquire::https::Proxy={proxy_url}",
    ]

    subprocess.run(
        [apt, *opts, "update"],
        env=env,
        check=True,
        close_fds=True,
        cwd="/",
    )

    kernel_pkgs = pending_kernel_updates(apt, opts, env)

    if kernel_pkgs and not os.isatty(0):
        # Unattended run: the boot mount is read-only here, so a kernel
        # upgrade would fail mid-transaction. Defer everything and ask a
        # human to run it from a login shell instead.
        write_kernel_notice(kernel_pkgs)
        print(
            "[TheUpd8r] Kernel update pending "
            f"({', '.join(sorted(kernel_pkgs))}). "
            "Deferred: run 'sudo theUpd8r' from a login shell to apply it."
        )
    else:
        subprocess.run(
            [apt, *opts, "-y", "dist-upgrade"],
            env=env,
            check=True,
            close_fds=True,
            cwd="/",
        )
        clear_kernel_notice()

    # Best-effort secret minimisation
    proxy_url = None
    scheme = host = port = user = password = None
    del env_map
    del raw_env
    del key

    print("[TheUpd8r] Completed successfully.")


if __name__ == "__main__":
    main()
