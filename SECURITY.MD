# 🔒 Security Policy

## Overview

**TheUpd8r** is a security-conscious system utility designed to operate in
hostile-by-default environments.

Its primary goals are:
- integrity over convenience
- predictability over flexibility
- refusal over recovery

This document describes the project’s **security model**, **supported scope**,
and **how to report issues responsibly**.

---

## 🎯 Security Design Principles

TheUpd8r is built around the following principles:

- **Fail closed**  
  If something is unexpected, execution stops.

- **Trust as little as possible**  
  Files, directories, binaries, and execution context are all validated.

- **Secrets are ephemeral**  
  Proxy credentials are:
  - encrypted at rest
  - decrypted only in memory
  - never written in plaintext to disk

- **Integrity is explicit**  
  Critical binaries are pinned via SHA-256 and verified before use.

- **No silent drift**  
  Hash re-pinning is disabled by default and must be explicitly enabled.

---

## 🛡️ Threat Model

### TheUpd8r is designed to defend against:

- Accidental misconfiguration
- Insecure filesystem permissions
- Symlink and TOCTOU attacks
- Unintended binary replacement
- Credential exposure via temporary files
- Concurrent execution hazards
- Unsafe execution environments

### TheUpd8r does **not** attempt to defend against:

- A fully compromised root environment
- A malicious kernel or init system
- Compromised systemd itself
- Hardware-level or firmware-level attacks

If an attacker already controls these components, the system is assumed lost.

---

## 🔐 Supported Security Guarantees

Within its threat model, TheUpd8r guarantees:

- Root-only execution
- Secure file access using `O_NOFOLLOW` and FD-based validation
- Constant-time hash comparisons
- Sanitised subprocess environments
- Explicit and auditable trust decisions

---

## ⚠️ Known Limitations

- Secrets must exist briefly in memory to be used  
  (this is unavoidable and considered acceptable)
- Python does not provide strong guarantees around memory zeroisation
- Security hardening relies partly on systemd sandboxing

These limitations are documented and intentional.

---

## 🔧 Secure Configuration Expectations

For correct and secure operation:

- `/etc/theupd8r` must be:
  - root-owned
  - not group/world writable
  - not a symlink

- `/var/lib/theupd8r` must meet the same criteria

- The systemd service **must not** be modified to weaken:
  - hash pinning
  - sandboxing
  - privilege restrictions

---

## 🚨 Reporting a Security Issue

If you believe you have found a security issue in TheUpd8r:

1. **Do not open a public issue**
2. Provide a clear description including:
   - affected component
   - version / commit hash
   - reproduction steps
   - impact assessment
3. Include whether the issue:
   - breaks stated guarantees
   - violates the documented threat model

Responsible disclosure is appreciated.

---

## 🔄 Security Updates

Security-relevant changes will be:
- documented in release notes
- treated as breaking changes where appropriate
- conservative by default

Backward compatibility is secondary to correctness.

---

## 🧠 Final Note

TheUpd8r is intentionally boring.

If it is doing something surprising, that is a bug.

If it refuses to run, that is usually by design.

☕
