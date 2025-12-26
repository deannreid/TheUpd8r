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


def open_secure_ro(path: Path, desc: str) -> int:
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
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
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

        fd = open_secure_ro(path, f"binary {name}")
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

    proxy_url = f"{scheme}://{user}:{password}@{host}:{port}/"

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

    subprocess.run(
        [apt, *opts, "-y", "dist-upgrade"],
        env=env,
        check=True,
        close_fds=True,
        cwd="/",
    )

    # Best-effort secret minimisation
    proxy_url = None
    scheme = host = port = user = password = None
    del env_map
    del raw_env
    del key

    print("[TheUpd8r] Completed successfully.")


if __name__ == "__main__":
    main()
