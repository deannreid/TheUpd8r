#!/usr/bin/env python3
"""
setup_the_upd8r.py

Usage:
    sudo python3 setup_the_upd8r.py           # install / initial setup
    sudo python3 setup_the_upd8r.py --update  # update TheUpd8r + hashes, optional new proxy
    sudo python3 setup_the_upd8r.py --remove  # remove service, timer, config, files

What it does (quietly):
- Copies theUpd8r.py from this directory to /usr/local/sbin/theUpd8r.py
- Installs a `theUpd8r` command for manual runs (used to apply
  deferred kernel updates from a login shell)
- Prompts for proxy details (on install, or on update if requested)
- Encrypts proxy info and stores in:
    /etc/theupd8r/theupd8r.env
    /var/lib/theupd8r/theupd8r.key
- Stores mapping + metadata in:
    /etc/theupd8r/TheUpd8r_config.json
- Pins SHA256 hashes of:
    /usr/bin/apt-get
    /usr/local/sbin/TheUpd8r.py
  in both config and as environment variables in the systemd service.
- Creates theupd8r.service and theupd8r.timer (midnight run).
"""

import argparse
import getpass
import hashlib
import json
import os
import secrets
import shutil
import stat
import string
import subprocess
from pathlib import Path

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("[ERROR] cryptography module not found. Install with:")
    print("        sudo apt install -y python3-cryptography")
    raise SystemExit(1)

# --------------------------------------------------------------------
# Core paths / names
# --------------------------------------------------------------------

ETC_DIR = Path("/etc/theupd8r")
LIB_DIR = Path("/var/lib/theupd8r")

ENV_FILE = ETC_DIR / "theupd8r.env"
KEY_FILE = LIB_DIR / "theupd8r.key"
CONFIG_FILE = ETC_DIR / "TheUpd8r_config.json"

SYSTEMD_SERVICE = Path("/etc/systemd/system/theupd8r.service")
SYSTEMD_TIMER = Path("/etc/systemd/system/theupd8r.timer")

UPD8R_PATH = Path("/usr/local/sbin/theUpd8r.py")
WRAPPER_PATH = Path("/usr/local/sbin/theUpd8r")
APT_GET_PATH = Path("/usr/bin/apt-get")

# Login notices left behind by TheUpd8r when a kernel update is pending
MOTD_NOTICE = Path("/etc/update-motd.d/99-theupd8r-kernel")
PROFILE_NOTICE = Path("/etc/profile.d/theupd8r-kernel-notice.sh")

# Source theUpd8r.py (same dir as this script)
SETUP_DIR = Path(__file__).resolve().parent
SRC_UPD8R_PATH = SETUP_DIR / "theUpd8r.py"


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------

def require_root():
    if os.geteuid() != 0:
        raise SystemExit("[ERROR] This script must be run as root.")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def ensure_dirs():
    ETC_DIR.mkdir(parents=True, exist_ok=True)
    LIB_DIR.mkdir(parents=True, exist_ok=True)

    # Root-owned, private
    os.chmod(ETC_DIR, 0o700)
    os.chmod(LIB_DIR, 0o700)

    # Sanity check: not group/world writable
    if _mode(ETC_DIR) & (stat.S_IWGRP | stat.S_IWOTH):
        raise SystemExit(f"[ERROR] {ETC_DIR} is group/world writable.")
    if _mode(LIB_DIR) & (stat.S_IWGRP | stat.S_IWOTH):
        raise SystemExit(f"[ERROR] {LIB_DIR} is group/world writable.")


def random_var_name(length: int = 16) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def sha256_file(path: Path) -> str:
    if not path.exists():
        raise SystemExit(f"[ERROR] Cannot hash missing file: {path}")
    if path.is_symlink():
        raise SystemExit(f"[ERROR] Refusing to hash symlink: {path}")

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def prompt_proxy_details() -> dict:
    print("=== TheUpd8r Setup ===")
    print("Enter proxy settings for APT.\n")

    scheme = input("Proxy scheme (http/https/socks5) [http]: ").strip() or "http"
    proxy_address = input("Proxy address (host:port): ").strip()

    if ":" not in proxy_address:
        raise SystemExit("[ERROR] Proxy address must be host:port")

    host, port = proxy_address.split(":", 1)
    host = host.strip()
    port = port.strip()

    user = input("Proxy username: ").strip()
    password = getpass.getpass("Proxy password: ").strip()

    if not all([scheme, host, port, user, password]):
        raise SystemExit("[ERROR] All fields are required.")

    return {"scheme": scheme, "host": host, "port": port, "user": user, "password": password}


def generate_key() -> bytes:
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    os.chmod(KEY_FILE, 0o600)
    return key


def encrypt_and_write_env(secret_data: dict, key: bytes, var_map: dict):
    f = Fernet(key)
    lines = []
    for logical, value in secret_data.items():
        env_name = var_map[logical]
        token = f.encrypt(value.encode()).decode()
        lines.append(f"{env_name}={token}")
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(ENV_FILE, 0o600)


def install_upd8r() -> str:
    """Copy TheUpd8r.py into /usr/local/sbin and return its SHA256."""
    if not SRC_UPD8R_PATH.exists():
        raise SystemExit(f"[ERROR] Source TheUpd8r.py not found at: {SRC_UPD8R_PATH}")
    shutil.copy2(SRC_UPD8R_PATH, UPD8R_PATH)
    os.chmod(UPD8R_PATH, 0o700)
    install_wrapper()
    return sha256_file(UPD8R_PATH)


def install_wrapper():
    """Install the `theUpd8r` command used for manual (kernel) updates."""
    WRAPPER_PATH.write_text(
        "#!/bin/sh\n"
        f'exec /usr/bin/python3 {UPD8R_PATH} "$@"\n',
        encoding="utf-8",
    )
    # Root-only: regular users cannot execute (or even read) the command.
    os.chmod(WRAPPER_PATH, 0o700)
    print(f"[*] Installed command: {WRAPPER_PATH} (run manually with: sudo theUpd8r)")


def write_config(var_map: dict, upd8r_hash: str, apt_hash: str):
    cfg = {
        "env_file": str(ENV_FILE),
        "key_file": str(KEY_FILE),
        "variables": var_map,
        "binaries": {
            "apt_get": {"path": str(APT_GET_PATH), "sha256": apt_hash},
            "the_updater": {"path": str(UPD8R_PATH), "sha256": upd8r_hash},
        },
    }
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    os.chmod(CONFIG_FILE, 0o600)


def read_config() -> dict:
    if not CONFIG_FILE.exists():
        raise SystemExit(f"[ERROR] Config file not found: {CONFIG_FILE}")
    if CONFIG_FILE.is_symlink():
        raise SystemExit(f"[ERROR] Config file is a symlink: {CONFIG_FILE}")
    return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))


def create_systemd_files(upd8r_hash: str, apt_hash: str):
    # Note:
    # - TheUpd8r passes proxy settings via a root-only APT_CONFIG file under
    #   /run (never on the command line); no writes under /etc/apt.
    # - Keep hardening reasonable: apt/dpkg will still need to write to system locations.

    service_content = f"""[Unit]
Description=TheUpd8r - Verified APT updates (with proxy)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {UPD8R_PATH}

Environment=TheUpd8r_SHA256={upd8r_hash}
Environment=APTGET_SHA256={apt_hash}
Environment=TheUpd8r_CONFIG={CONFIG_FILE}

# Optional: allow controlled re-pin during maintenance windows only.
# Set to 1 explicitly when needed.
# Environment=THEUPD8R_ALLOW_REPIN=0

Nice=10

# Hardening (compatible defaults)
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# The updater needs to read its config + secrets, and apt/dpkg need to write system state.
ReadWritePaths=/etc /var /run

[Install]
WantedBy=multi-user.target
"""

    timer_content = """[Unit]
Description=Run TheUpd8r daily at midnight

[Timer]
OnCalendar=*-*-* 00:00:00
Persistent=true

[Install]
WantedBy=timers.target
"""

    SYSTEMD_SERVICE.write_text(service_content, encoding="utf-8")
    SYSTEMD_TIMER.write_text(timer_content, encoding="utf-8")

    # Hide service + timer from non-root users
    os.chmod(SYSTEMD_SERVICE, 0o600)
    os.chmod(SYSTEMD_TIMER, 0o600)

    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "theupd8r.timer"], check=True)
    subprocess.run(["systemctl", "start", "theupd8r.timer"], check=True)


def remove_everything():
    # Stop/disable systemd units
    for unit in ("theupd8r.timer", "theupd8r.service"):
        subprocess.run(
            ["systemctl", "disable", "--now", unit],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    # Remove files (ignore if missing)
    for p in (SYSTEMD_SERVICE, SYSTEMD_TIMER, CONFIG_FILE, ENV_FILE, KEY_FILE,
              UPD8R_PATH, WRAPPER_PATH, MOTD_NOTICE, PROFILE_NOTICE):
        try:
            if p.exists():
                p.unlink()
                print(f"Removed {p}")
        except Exception as e:
            print(f"[WARN] Failed to remove {p}: {e}")

    # Try to clean empty dirs
    for d in (ETC_DIR, LIB_DIR):
        try:
            d.rmdir()
        except OSError:
            pass

    subprocess.run(["systemctl", "daemon-reload"], check=False)
    print("[+] Removal complete.")


# --------------------------------------------------------------------
# Flows
# --------------------------------------------------------------------

def install_flow():
    ensure_dirs()

    print("[*] Installing TheUpd8r.py …")
    upd8r_hash = install_upd8r()
    apt_hash = sha256_file(APT_GET_PATH)

    proxy = prompt_proxy_details()
    var_map = {k: random_var_name() for k in proxy}

    key = generate_key()
    encrypt_and_write_env(proxy, key, var_map)
    write_config(var_map, upd8r_hash, apt_hash)
    create_systemd_files(upd8r_hash, apt_hash)

    print("\n=== Install complete ===")
    print("TheUpd8r will run daily at midnight (theupd8r.timer).")


def update_flow():
    if not CONFIG_FILE.exists():
        raise SystemExit("[ERROR] No existing config. Run without --update first.")

    ensure_dirs()

    print("[*] Updating TheUpd8r.py …")
    upd8r_hash = install_upd8r()
    apt_hash = sha256_file(APT_GET_PATH)

    cfg = read_config()
    var_map = cfg.get("variables", {})

    choice = input("Keep existing proxy credentials? [Y/n]: ").strip().lower()
    if choice in ("", "y", "yes"):
        print("[*] Keeping existing encrypted proxy credentials.")
    else:
        print("[*] Updating proxy credentials.")
        proxy = prompt_proxy_details()

        # Reuse existing var_map if present; otherwise, create new
        if not var_map:
            var_map = {k: random_var_name() for k in proxy}

        # Reuse existing key if present, else new
        if KEY_FILE.exists():
            key = KEY_FILE.read_bytes()
        else:
            key = generate_key()

        encrypt_and_write_env(proxy, key, var_map)

    # Update config with new hashes and current paths
    cfg["variables"] = var_map
    cfg["binaries"]["the_updater"]["sha256"] = upd8r_hash
    cfg["binaries"]["the_updater"]["path"] = str(UPD8R_PATH)
    cfg["binaries"]["apt_get"]["sha256"] = apt_hash
    cfg["binaries"]["apt_get"]["path"] = str(APT_GET_PATH)
    cfg["env_file"] = str(ENV_FILE)
    cfg["key_file"] = str(KEY_FILE)

    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    os.chmod(CONFIG_FILE, 0o600)

    create_systemd_files(upd8r_hash, apt_hash)

    print("\n[+] Update complete. Hashes and service updated.")
    print("If you need to re-pin binaries during maintenance, set THEUPD8R_ALLOW_REPIN=1 in the service.")


# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Setup/Update/Remove TheUpd8r")
    parser.add_argument("--remove", action="store_true",
                        help="Remove service, timer and all files")
    parser.add_argument("--update", action="store_true",
                        help="Update TheUpd8r + hashes (optional new proxy)")
    return parser.parse_args()


def main():
    require_root()
    args = parse_args()

    if args.remove:
        remove_everything()
    elif args.update:
        update_flow()
    else:
        install_flow()


if __name__ == "__main__":
    main()
