# linux-priv-esc-audit

`linux-priv-esc-audit.sh` is a **dual-mode Linux privilege escalation & hardening audit script** written in Bash.

- 🛡️ **Root mode** → system-wide hardening / misconfiguration audit
- 🧪 **User mode** → post-exploitation enum for a given low-privileged account (e.g. `www-data`)

The goal is defensive: help admins and defenders see **what is exposed** if a user or service account gets compromised.

---

## Features

### Two modes in one script

- **Run as root**
  → global view of the system: hardening, exposure, misconfigs, risky perms.

- **Run as a normal user (www-data, app, etc.)**
  → “If this account is popped, what can I read/modify that could lead to privesc?”

The script autodetects the mode based on UID (`id -u`).

---

## What it checks (high level)

### Common (root & user)

- 🧩 **System & environment**
  - OS / kernel / distro info
  - Current user, groups, shell
- 🧮 **Version hints**
  - Kernel version (very old kernels flagged)
  - `sudo`, `OpenSSH`, `docker` versions (with heuristic CVE hints)
- 🔐 **MAC / LSM**
  - SELinux / AppArmor state
- 💽 **Filesystem & isolation**
  - Mount options on key filesystems (`nosuid`, `nodev`, `noexec`, etc.)
  - Basic NFS / CIFS exports overview
- 🧪 **Security tooling**
  - Hints about AV / EDR / security agents (processes, services, packages)
- 📦 **Packages & updates**
  - Quick inventory of “interesting” packages (web, DB, remote access, etc.)
  - Heuristic check for pending **security updates** (APT / DNF / YUM)
- ⚙️ **Sysctl hardening** (can be disabled with `--no-sysctl`)
  - A few classic hardening flags (IP forwarding, redirects, etc.)
- 🌐 **Listening services**
  - TCP/UDP listeners via `ss` or `netstat`
  - Compares against expected ports (`--ports`, `--ports-tcp`, `--ports-udp`)
- 🕒 **Recent changes & logs**
  - Recently modified files in key dirs (`/etc`, `/usr/local/bin`, `/var/www`, …)
  - Recent auth/system logs (journalctl or log files)
- 🧷 **CVE hints (heuristic)**
  - Adds “CVE hints” for some version combos (e.g. sudo Baron Samedit, OpenSSH recent CVEs), to review manually.

---

### ROOT mode (system-wide hardening view)

When run as **root**, the script focuses on global exposure:

- 🔑 **Sudo & sudoers**
  - Parses `/etc/sudoers` and `/etc/sudoers.d` for:
    - `NOPASSWD`, `!authenticate`, `ALL=(ALL) ALL`
  - Flags risky rules for review.

- 🧨 **SUID / SGID / GTFOBins**
  - Enumerates SUID root binaries & SGID binaries
  - Detects **world-writable** SUID/SGID (high risk)
  - Quick check against known GTFOBins patterns

- ⏰ **Cron & scheduled tasks**
  - `/etc/crontab`, `/etc/cron.*`, system cron jobs
  - World-writable cron scripts

- 🧵 **PATH & writable dirs**
  - PATH entries writable by root (dangerous if others can drop binaries there)
  - Some world-writable dirs on the filesystem

- 🔒 **Sensitive files & ACLs**
  - Permissions on:
    - `/etc/passwd`
    - `/etc/shadow`
    - `/etc/sudoers`
    - `/etc/ssh/sshd_config`
    - `/etc/crontab`
  - ACL / immutable attribute checks on these files

- 🧬 **Shell & core binaries**
  - Quick integrity-style check on `/bin/sh`, `/bin/bash`, `/usr/bin/sudo`, etc.

- 🛠️ **systemd services**
  - Looks at `.service` files and flags ExecStart paths that are writable (potential privesc via service hijack)

- 🔑 **SSH keys & options**
  - Checks SSH key permissions (root and optionally `$HOME`)
  - Parses authorized_keys options for risky configs

- 👣 **Persistence artifacts**
  - Basic scan of common persistence locations (rc files, cron, systemd units, etc.)

- 🌐 **Network exposure**
  - Firewall overview (UFW, iptables)
  - Listening sockets with PID/command head

---

### USER mode (post-exploitation view)

When run as a **non-root** user (e.g. `www-data`), the script changes angle:

- 🔑 **Sudo from this user**
  - Tries `sudo -n -l` (no password) to see immediate privesc vectors
  - Parses sudo rules visible to that user if possible

- 🧨 **SUID / SGID reachable**
  - SUID/SGID binaries visible to the user
  - World-writable SUID/SGID highlighted

- 🧵 **Writable PATH & dirs**
  - PATH entries writable by the user (PATH hijacking)
  - Some world-writable directories

- ⏰ **Cron exposure**
  - World-writable cron scripts
  - User crontab (if any)

- 🔐 **Readable sensitive configs**
  - Checks if the user can read:
    - `/etc/shadow`
    - `/etc/sudoers`
    - `/etc/ssh/sshd_config`
    - `/etc/crontab`
  - Flags unexpected read access (e.g. `/etc/shadow` readable = huge issue)

- 🔍 **Secrets & creds (heuristic)**
  - Greps for patterns like `password`, `secret`, `token`, `apikey` in small text files under:
    - `/etc`, `/opt`, `/var/www`, `/srv`, `/var/backups`, `/home`, `$HOME/.config`
  - Limited depth/size to avoid going crazy

- 🕓 **User histories**
  - Shell & tool history files for that user:
    - `~/.bash_history`, `~/.zsh_history`
    - `~/.mysql_history`, `~/.psql_history`, etc.

- 🧾 **User-owned files outside $HOME**
  - Lists files owned by the user outside their home directory (misconfigs, leaks, weird ownerships)

- 🐳 **Docker & sockets**
  - Checks if user is in `docker` group
  - Checks permissions on `/var/run/docker.sock`
  - Lists some sockets under `/var/run`

---

## Requirements

- Bash
- Classic Unix tools: `find`, `grep`, `sed`, `awk`, `ps`, `stat`, `ss` or `netstat`, `journalctl` (if systemd)
- Optional but useful:
  - `getcap`, `setfacl`, `getfacl`
  - `dpkg-query` / `apt-get` (Debian/Ubuntu)
  - `dnf` / `yum` (RHEL/Fedora-like)
  - `systemctl`
  - `timeout`

The script is designed for normal Linux servers (Debian, Ubuntu, RHEL-like, etc.).
On very minimal systems some checks will just be skipped with WARN messages.

---

## Installation

Clone the repo and make the script executable:

```bash
git clone https://github.com/tflr/linux-priv-esc-audit.git
cd linux-priv-esc-audit

chmod +x linux-priv-esc-audit.sh
````

You can then run it directly from the repo directory or put it somewhere in your `$PATH`.

---

## Usage

### Root mode (system-wide audit)

```bash
sudo ./linux-priv-esc-audit.sh
```

With output to a file:

```bash
sudo ./linux-priv-esc-audit.sh --output system-audit.txt
```

### User mode (post-exploitation style)

Example with `www-data`:

```bash
sudo -u www-data ./linux-priv-esc-audit.sh
```

With report:

```bash
sudo -u www-data ./linux-priv-esc-audit.sh --output www-data-audit.txt
```

---

## Command-line options

From `--help`:

```text
--no-color         Disable colored output
--quiet            Only show WARN/CRIT on stdout (full log still buffered)
--json             Emit a JSON summary at the end (to stdout)
--machine          Emit a TSV machine-readable summary (severity<TAB>message)
--max-depth N      Limit find/grep directory depth (default: 5)
--recent-days N    Show files changed in the last N days (default: 7)
--ports LIST       Expected listening ports (comma list, default: 22,80,443)
--ports-tcp LIST   Extra expected TCP ports (comma list)
--ports-udp LIST   Extra expected UDP ports (comma list)
--allow-groups G   Comma list of groups considered "safe" for writable paths
                   (default: root,wheel,adm)
--no-sysctl        Skip sysctl hardening checks
--output FILE      Write the full human-readable report to FILE
-h, --help         Show help
```

### JSON output

If you pass `--json`, the script will print a JSON summary at the very end, for example:

```bash
sudo ./linux-priv-esc-audit.sh --json > summary.json
```

* Human-readable output still appears on stdout before the JSON line.
* The JSON contains:

  * host, timestamp, user, `is_root`
  * counts: `crit_count`, `warn_count`
  * arrays: `crit`, `warn`, `ok`, `cve_hints`

If you want only the JSON, you can pipe or filter on the last line, or run with `--quiet` to reduce noise.

### Machine (TSV) mode

`--machine` prints each log entry as:

```text
severity<TAB>message
```

Where `severity` is `crit`, `warn`, `ok` or `info`.

Tip: combine with `--no-color` to avoid ANSI escape codes if you parse the output.

---

## Tuning & performance

A few knobs:

* `--max-depth N`
  Limit recursive `find`/`grep` depth (default: 5).

* `--recent-days N`
  Time window for “recent changes” and recent logs (default: 7 days for files, ~48h for logs).

* `--ports*`
  `--ports`, `--ports-tcp`, `--ports-udp` let you define expected listening ports to reduce noise.

* `--allow-groups`
  Specifies groups considered “normal” for writable paths; others may be flagged.

The script can be a bit heavy on very large systems (many files / mount points).
Use with common sense (e.g. during a maintenance window) if you know the server is huge.

---

## Limitations

* Heuristic only:

  * Does **not** replace a full pentest or audit.
  * Version checks and CVE hints are indicative; always verify with your distro’s advisories.
* Focuses on **classic** misconfigs and privesc paths.
* Some checks are best-effort and may be skipped if tools are missing.

---

## Legal & intended use

This script is intended for **defensive and auditing purposes only**.

* Use it on systems you own or are explicitly authorized to audit.
* It does **not** exploit anything by itself, it only **enumerates** and flags potential weak points.
* Always review findings manually before drawing conclusions.
