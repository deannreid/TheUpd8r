# 🛠️ TheUpd8r

[![Security Policy](https://img.shields.io/badge/security-policy-informational.svg)](SECURITY.md)
[![Responsible Disclosure](https://img.shields.io/badge/responsible-disclosure-green.svg)](SECURITY.md)


> A deliberately unexciting system update utility.

**TheUpd8r** is a hardened, root-only APT update runner designed for environments where:

* 🔐 integrity matters,
* 🧼 secrets must not linger,
* 🎊 and surprises are unwelcome.

It runs unattended, verifies its own integrity, decrypts proxy credentials only at runtime, applies system updates, and exits quietly.

No interaction is required.
No interaction is offered.
This is working as intended.

---

## 🤔 Why TheUpd8r Exists

Most update automation assumes:

* trusted environments,
* stable filesystems,
* cooperative users.

**TheUpd8r assumes none of that.**

It is designed to run in **hostile-by-default** conditions and will refuse to operate if:

* 🚫 files are writable when they shouldn’t be,
* 🔍 binaries do not match pinned hashes,
* 🔗 symlinks appear where they shouldn’t,
* ⚠️ execution conditions deviate from expectations.

---

## ✨ Features

* 🔒 **Root-only execution**
* 🧾 **Self-hash verification** (pinned via systemd environment)
* 🧷 **Pinned binary verification**

  * `apt-get` and TheUpd8r itself
  * Explicit, opt-in re-pinning only during maintenance
* 🧠 **TOCTOU-safe file handling**

  * `O_NOFOLLOW`, `fstat`, FD-based reads
* 📁 **Strict directory and permission validation**
* 🔐 **Encrypted proxy credentials**

  * Decrypted only in memory, only when needed
* 🧹 **No plaintext secrets on disk**
* ⚙️ **Invocation-based APT proxy configuration**

  * No temporary files under `/etc/apt`
* 🧪 **Minimal, sanitised execution environment**
* 🔁 **Concurrency protection**

  * Prevents overlapping runs
* ⏱️ **Systemd-native**

  * Timer-driven, sandboxed, predictable

---

## ▶️ What It Does (At Runtime)

1. 🧑‍💻 Ensures it is running as root
2. 🔐 Acquires an execution lock
3. 🔎 Verifies its own SHA256 hash
4. 📖 Loads and validates configuration securely
5. 🧷 Verifies pinned binaries
6. 🔓 Decrypts proxy credentials in memory
7. 📦 Runs:

   ```sh
   apt-get update
   apt-get -y dist-upgrade
   ```

   using invocation-based proxy settings
8. 🧼 Clears sensitive values
9. 🤫 Exits quietly

If anything looks wrong at any point, it stops.

---

## 📂 Repository Layout

```text
.
├── TheUpd8r.py          # Runtime updater (executed by systemd)
├── setup_the_upd8r.py   # Installer / updater / remover
└── README.md
```

---

## 🚀 Installation

```bash
sudo python3 setup_the_upd8r.py
```

You will be prompted once for proxy details. These are:

* 🔐 encrypted using Fernet,
* 💾 stored on disk encrypted,
* 🚫 never written in plaintext.

On completion:

* TheUpd8r is installed to `/usr/local/sbin/TheUpd8r.py`
* Configuration is stored under `/etc/theupd8r`
* Secrets are stored under `/var/lib/theupd8r`
* ⏰ A systemd **timer** is enabled to run daily at midnight

---

## 🔄 Updating TheUpd8r

```bash
sudo python3 setup_the_upd8r.py --update
```

You may choose to:

* ✅ keep existing encrypted proxy credentials, or
* 🔁 replace them.

Binary hashes and the systemd unit will be updated automatically.

---

## 🗑️ Removal

```bash
sudo python3 setup_the_upd8r.py --remove
```

This will:

* ⛔ stop and disable the timer and service,
* 🧹 remove installed files and configuration,
* 📴 leave no background activity behind.

---

## 🔧 Hash Re-Pinning (Explicit Only)

By default, **binary hash changes are fatal** 💥

If you are intentionally updating system components and need to re-pin hashes:

1. ✏️ Edit the systemd service:

   ```ini
   Environment=THEUPD8R_ALLOW_REPIN=1
   ```
2. ▶️ Run TheUpd8r once
3. 🧽 Remove the flag afterwards

Silent drift is not permitted.

---

## 🛡️ Threat Model (Summary)

TheUpd8r defends against:

* accidental misconfiguration
* symlink and TOCTOU attacks
* filesystem permission abuse
* unattended secret exposure
* unintended binary replacement

It does **not** attempt to protect against:

* a fully compromised root environment
* malicious kernel or init systems

At that point, you have larger problems 🔥

---

## 📋 Requirements

* 🐧 Debian-based system
* 🐍 Python 3
* 🔐 `python3-cryptography`
* ⚙️ systemd

---

## 🧠 Philosophy

TheUpd8r is:

* not clever
* not fast
* not flexible

It is:

* predictable
* verifiable
* difficult to trick

Which is rather the point ☕

---

## 📜 Licence

Choose whatever fits your organisation.
TheUpd8r will not have opinions about it.
