#!/usr/bin/env bash

set -o pipefail

# Paramètres de base pour checks sécu rapides
VERSION="0.3.0"
OUTPUT_FILE=""
NO_COLOR=0
QUIET=0
JSON_OUTPUT=0
MACHINE=0
MAX_DEPTH=5
EXPECTED_PORTS="22,80,443"
EXPECTED_TCP_PORTS=""
EXPECTED_UDP_PORTS=""
NO_SYSCTL=0
FIND_TIMEOUT="8s"
RECENT_DAYS=7
ALLOWED_GROUPS="root wheel adm"


if [ -t 1 ]; then
	RED="\033[31m"
	YELLOW="\033[33m"
	GREEN="\033[32m"
	BLUE="\033[34m"
	BOLD="\033[1m"
	RESET="\033[0m"
else
	RED=""
	YELLOW=""
	GREEN=""
	BLUE=""
	BOLD=""
	RESET=""
fi

log_buffer=""
CRIT_MSGS=()
WARN_MSGS=()
OK_MSGS=()
CVE_HINTS=()

# Mini logger avec option TSV pour parser facilement
log() {
	log_buffer+="$1"$'\n'
	if [ "$QUIET" -eq 0 ] || printf "%s" "$1" | grep -qE '\[WARN\]|\[CRIT\]'; then
		printf "%b\n" "$1"
	fi
	if [ "$MACHINE" -eq 1 ]; then
		local sev
		case "$1" in
			*\[CRIT\]*) sev="crit" ;;
			*\[WARN\]*) sev="warn" ;;
			*\[OK\]*)   sev="ok" ;;
			*)          sev="info" ;;
		esac
		printf "%s\t%s\n" "$sev" "$(printf "%b" "$1")"
	fi
}

log_to_file_if_needed() {
	if [ -n "$OUTPUT_FILE" ]; then
		printf "%s\n" "$log_buffer" > "$OUTPUT_FILE"
	fi
}

section() {
	local title="$1"
	log ""
	log "${BOLD}${BLUE}===== $title =====${RESET}"
}

ok() {
	log "${GREEN}[OK]${RESET} $1"
	OK_MSGS+=("$1")
}

warn() {
	log "${YELLOW}[WARN]${RESET} $1"
	WARN_MSGS+=("$1")
}

crit() {
	log "${RED}[CRIT]${RESET} $1"
	CRIT_MSGS+=("$1")
}


usage() {
	cat <<EOF
linux-priv-esc-audit.sh v$VERSION

Dual-mode Linux privilege escalation audit script.

- Run as root  : system-wide hardening / misconfiguration audit.
- Run as user  : post-exploitation style enum for that specific account
                 (e.g. www-data, app user) to see what it can abuse.

Usage:
  $0 [options]

Options:
  --no-color         Disable colored output
  --quiet            Only show WARN/CRIT on stdout (full log still buffered)
  --json             Emit a JSON summary at the end
  --machine          Emit a TSV machine-readable summary (severity<TAB>message)
  --max-depth N      Limit find/grep directory depth (default: $MAX_DEPTH)
  --recent-days N    Show files changed in the last N days (default: $RECENT_DAYS)
  --ports LIST       Expected listening ports (comma list, default: $EXPECTED_PORTS)
  --ports-tcp LIST   Extra expected TCP ports (comma list, optional)
  --ports-udp LIST   Extra expected UDP ports (comma list, optional)
  --allow-groups G   Comma list of groups considered safe for writable paths (default: $ALLOWED_GROUPS)
  --no-sysctl        Skip sysctl hardening checks
  --output FILE      Write the full report to FILE
  -h, --help         Show this help

Examples:
  sudo $0 --output system-audit.txt

  sudo -u www-data $0 --output www-data-audit.txt
EOF
}

# Parsing simple des flags pour garder le script lisible
while [ $# -gt 0 ]; do
	case "$1" in
		--no-color)
			NO_COLOR=1
			RED=""
			YELLOW=""
			GREEN=""
			BLUE=""
			BOLD=""
			RESET=""
			shift
			;;
		--quiet)
			QUIET=1
			shift
			;;
		--json)
			JSON_OUTPUT=1
			shift
			;;
		--machine)
			MACHINE=1
			shift
			;;
		--max-depth)
			MAX_DEPTH="$2"
			shift 2
			;;
		--ports)
			EXPECTED_PORTS="$2"
			shift 2
			;;
		--ports-tcp)
			EXPECTED_TCP_PORTS="$2"
			shift 2
			;;
		--ports-udp)
			EXPECTED_UDP_PORTS="$2"
			shift 2
			;;
		--allow-groups)
			ALLOWED_GROUPS="$2"
			shift 2
			;;
		--recent-days)
			RECENT_DAYS="$2"
			shift 2
			;;
		--no-sysctl)
			NO_SYSCTL=1
			shift
			;;
		--output)
			OUTPUT_FILE="$2"
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
	*)
		echo "Unknown option: $1" >&2
		usage
		exit 1
		;;
	esac
done

case "$MAX_DEPTH" in
	(*[!0-9]*|'')
		MAX_DEPTH=5
		;;
esac
case "$RECENT_DAYS" in
	(*[!0-9]*|'')
		RECENT_DAYS=7
		;;
esac
ALLOWED_GROUPS_LIST="${ALLOWED_GROUPS//,/ }"


# Helpers maison pour tester rapidement les binaires et perms
have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

run_cmd() {
	local desc="$1"
	shift
	log ""
	log "${BOLD}${desc}:${RESET}"
	"$@" 2>/dev/null || log "  (command failed or not available)"
}

find_quick() {
	local base="$1"
	shift
	if have_cmd timeout; then
		timeout "$FIND_TIMEOUT" find "$base" "$@" 2>/dev/null
	else
		find "$base" "$@" 2>/dev/null
	fi
}

port_in_expected() {
	local proto="$1"
	local port="$2"
	local list p
	if [ "$proto" = "tcp" ] && [ -n "$EXPECTED_TCP_PORTS" ]; then
		list="$EXPECTED_TCP_PORTS"
	elif [ "$proto" = "udp" ] && [ -n "$EXPECTED_UDP_PORTS" ]; then
		list="$EXPECTED_UDP_PORTS"
	else
		list="$EXPECTED_PORTS"
	fi
	for p in ${list//,/ }; do
		[ "$p" = "$port" ] && return 0
	done
	return 1
}

path_writable() {
	local p="$1"
	[ -w "$p" ]
}

perm_info() {
	stat -c "%a %U %G" "$1" 2>/dev/null
}

perm_detail() {
	local info
	info="$(perm_info "$1")" || return
	set -- $info
	printf "(mode=%s owner=%s group=%s)" "$1" "$2" "$3"
}

is_world_writable_mode() {
	case "$1" in
		*[2367]) return 0 ;;
	esac
	return 1
}

is_group_writable_mode() {
	local d
	d="${1%?}"
	d="${d#${d%?}}"
	case "$d" in
		[2367]) return 0 ;;
	esac
	return 1
}

is_allowed_group() {
	local g="$1"
	for ag in $ALLOWED_GROUPS_LIST; do
		[ "$ag" = "$g" ] && return 0
	done
	return 1
}

unpriv_writable() {
	local path="$1"
	[ -e "$path" ] || return 1
	local info mode owner group
	info="$(perm_info "$path")" || return 1
	mode="${info%% *}"
	owner="${info#* }"; owner="${owner%% *}"
	group="${info##* }"
	if is_world_writable_mode "$mode"; then
		return 0
	fi
	if is_group_writable_mode "$mode" && ! is_allowed_group "$group"; then
		return 0
	fi
	return 1
}

add_cve_hint() {
	local msg="$1"
	local seen
	for seen in "${CVE_HINTS[@]}"; do
		[ "$seen" = "$msg" ] && return 0
	done
	CVE_HINTS+=("$msg")
}

add_cve_hints() {
	case "$1" in
		(*sudo\ version*) add_cve_hint "Sudo version issues: review CVE-2021-3156 and vendor advisories." ;;
		(*docker.sock*) add_cve_hint "Docker socket access: review container escape vectors (e.g., CVE-2019-5736/runc)." ;;
		(*World-writable\ SUID*|*world-writable\ SUID*|*SUID/SGID*) add_cve_hint "Writable SUID/SGID binaries: check local privesc CVEs abusing writable binaries (multiple)." ;;
		(*Kernel\ major\ version*old*) add_cve_hint "Old kernel: review kernel LPEs (e.g., Dirty Pipe CVE-2022-0847, Dirty COW CVE-2016-5195)." ;;
		(*user\ namespaces*) add_cve_hint "User namespaces enabled: consider namespace LPEs (e.g., CVE-2022-0185)." ;;
		(*cap_net_raw*|*cap_net_admin*) add_cve_hint "Capabilities cap_net_raw/cap_net_admin: review CVEs allowing packet injection/spoofing (various)." ;;
		(*NOPASSWD*) add_cve_hint "Sudo NOPASSWD entries: review CVE-2021-3156 and command restrictions." ;;
	esac
}

json_escape() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/\"/\\\\"/g; s/	/\\t/g; s/\r/\\r/g; s/\n/\\n/g'
}

json_array_from() {
	local arr_name="$1"
	shift || true
	local arr
	eval "arr=(\"\${${arr_name}[@]}\")"
	local out=""
	local item
	for item in "${arr[@]}"; do
		local esc
		esc=$(json_escape "$item")
		if [ -n "$out" ]; then
			out+=","
		fi
		out+="\"$esc\""
	done
	printf '%s' "$out"
}

CRIT_COUNT=0
WARN_COUNT=0

add_crit() {
	CRIT_COUNT=$((CRIT_COUNT+1))
	crit "$1"
	add_cve_hints "$1"
}

add_warn() {
	WARN_COUNT=$((WARN_COUNT+1))
	warn "$1"
	add_cve_hints "$1"
}

CURRENT_USER="$(id -un 2>/dev/null || echo "unknown")"
CURRENT_UID="$(id -u 2>/dev/null || echo "99999")"
IS_ROOT=0
[ "$CURRENT_UID" -eq 0 ] && IS_ROOT=1
RUN_TS="$(date -Iseconds 2>/dev/null || date)"
HOSTNAME="$(hostname 2>/dev/null || echo "unknown")"


# Contexte machine avant d'aller plus loin
check_basic_system_info() {
	section "System & current user context"

	if have_cmd hostnamectl; then
		run_cmd "hostnamectl" hostnamectl
	else
		run_cmd "uname -a" uname -a
	fi

	if [ -f /etc/os-release ]; then
		log ""
		log "${BOLD}OS release (/etc/os-release):${RESET}"
		sed -n '1,8p' /etc/os-release 2>/dev/null
	fi

	log ""
	log "${BOLD}Current user & groups:${RESET}"
	id

	log ""
	log "${BOLD}Current shell:${RESET}"
	echo "$SHELL"
}

check_versions_with_heuristics() {
	section "Interesting versions (check manually against CVEs)"

	local kernel sudo_v docker_v

	if have_cmd uname; then
		kernel="$(uname -r)"
		KERNEL_VERSION="$kernel"
		log "${BOLD}Kernel:${RESET} $kernel"
		local k_major
		k_major="$(echo "$kernel" | cut -d'.' -f1)"
		if [ -n "$k_major" ]; then
			if [ "$k_major" -lt 4 ]; then
				add_crit "Kernel major version <$k_major> looks very old. Check for known priv-esc CVEs."
			elif [ "$k_major" -lt 5 ]; then
				add_warn "Kernel major version $k_major.x is relatively old. Verify vendor support and patches."
			else
				ok "Kernel major version $k_major.x looks recent enough, but still verify patches."
			fi
		fi
	fi

	if have_cmd sudo; then
		sudo_v="$(sudo -V 2>/dev/null | head -n1 | awk '{print $3}')"
		SUDO_VERSION="$sudo_v"
		log "${BOLD}sudo:${RESET} $sudo_v"
		local sudo_major_minor
		sudo_major_minor="$(echo "$sudo_v" | sed -n 's/.*\\([0-9]\\+\\.[0-9]\\+\\).*/\\1/p')"
		if [ -n "$sudo_major_minor" ]; then
			local sudo_major
			sudo_major="$(echo "$sudo_major_minor" | cut -d'.' -f1)"
			local sudo_minor
			sudo_minor="$(echo "$sudo_major_minor" | cut -d'.' -f2)"
			case "$sudo_major$sudo_minor" in
				(*[!0-9]*|'')
					add_warn "Could not parse sudo version \"$sudo_v\". Please check manually."
					;;
				(*)
					if [ "$sudo_major" -lt 1 ] || { [ "$sudo_major" -eq 1 ] && [ "$sudo_minor" -lt 8 ]; }; then
						add_crit "sudo version $sudo_v looks very old. Check for known sudo CVEs."
					elif [ "$sudo_major" -eq 1 ] && [ "$sudo_minor" -lt 9 ]; then
						add_warn "sudo version $sudo_v is older 1.9.x. Verify if it's still supported by your distro."
					else
						ok "sudo version $sudo_v looks reasonably recent (still verify distro security notices)."
					fi
					;;
			esac
		else
			add_warn "Could not extract sudo major.minor from \"$sudo_v\". Please check manually."
		fi
	fi

	if have_cmd docker; then
		docker_v="$(docker version --format '{{.Server.Version}}' 2>/dev/null)"
		if [ -n "$docker_v" ]; then
			DOCKER_VERSION="$docker_v"
			log "${BOLD}docker server:${RESET} $docker_v"
			add_warn "Docker version found: $docker_v. Check Docker CVEs manually if this is exposed to untrusted users."
		fi
	fi
}

check_mount_options() {
	section "Mount options & isolation"

	if [ ! -r /proc/mounts ]; then
		warn "/proc/mounts not readable."
		return
	fi

	while read -r src tgt fstype opts _; do
		case "$tgt" in
			/tmp|/var/tmp|/dev/shm)
				printf "%s\n" "$opts" | grep -q "noexec" || add_warn "$tgt missing noexec"
				printf "%s\n" "$opts" | grep -q "nodev" || add_warn "$tgt missing nodev"
				printf "%s\n" "$opts" | grep -q "nosuid" || add_warn "$tgt missing nosuid"
				;;
		esac
		case "$fstype" in
			nfs*|cifs|smb*|fuse*)
				add_warn "Network/FUSE mount $tgt type $fstype (review perms): $opts"
				;;
			esac
		done < /proc/mounts
}

check_nfs_cifs_exports() {
	section "NFS/CIFS exports and fstab"

	if [ -f /etc/exports ]; then
		if grep -E "no_root_squash" /etc/exports 2>/dev/null | head -n 10; then
			add_warn "/etc/exports contains no_root_squash (high risk)."
		fi
	fi

	if [ -f /etc/fstab ]; then
		while read -r src tgt type opts _; do
			[ -z "$src" ] && continue
			case "$type" in
				nfs*|cifs|smb*)
					printf "%s\n" "$opts" | grep -q "noexec" || add_warn "/etc/fstab entry $src missing noexec"
					printf "%s\n" "$opts" | grep -q "nodev" || add_warn "/etc/fstab entry $src missing nodev"
					printf "%s\n" "$opts" | grep -q "nosuid" || add_warn "/etc/fstab entry $src missing nosuid"
					;;
			esac
		done < /etc/fstab
	fi
}

check_packages_inventory() {
	section "Packages of interest (quick inventory)"

	local packages=(
		sudo
		openssh-server
		openssh-client
		docker-ce
		docker-ce-cli
		docker.io
		docker
		containerd
		nginx
		apache2
		httpd
		mysql-server
		mariadb-server
		postgresql
		samba
	)

	if have_cmd dpkg-query; then
		for pkg in "${packages[@]}"; do
			if ver=$(dpkg-query -W -f='${Version}\n' "$pkg" 2>/dev/null | head -n1); then
				log "${BOLD}${pkg}:${RESET} $ver"
				case "$pkg" in
					docker.io|docker-ce|docker-ce-cli)
						add_warn "Docker present ($pkg $ver). Ensure only trusted users are in docker group."
						DOCKER_VERSION="${DOCKER_VERSION:-$ver}"
						;;
					openssh-server)
						add_warn "OpenSSH server installed ($ver). Validate SSH exposure and hardening."
						OPENSSH_VERSION="$ver"
						;;
				esac
			fi
		done
	elif have_cmd rpm; then
		for pkg in "${packages[@]}"; do
			if ver=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$pkg" 2>/dev/null | head -n1); then
				log "${BOLD}${pkg}:${RESET} $ver"
				case "$pkg" in
					docker|docker-ce|docker-ce-cli|docker.io)
						add_warn "Docker present ($ver). Ensure docker group is restricted."
						DOCKER_VERSION="${DOCKER_VERSION:-$ver}"
						;;
					openssh-server)
						add_warn "OpenSSH server installed ($ver). Validate SSH exposure and hardening."
						OPENSSH_VERSION="$ver"
						;;
				esac
			fi
		done
	else
		warn "Package manager not detected (dpkg or rpm)."
	fi
}

check_listening_services() {
	section "Listening services exposure"

	local output proto lp addr port wild unexpected=0

	# Exceptions UDP/TCP pour éviter le bruit sur mdns/dhcp/ntp
	port_whitelist() {
		local p_proto="$1" p_port="$2" p_addr="$3"
		case "$p_proto" in
			udp)
				case "$p_port" in
					53) case "$p_addr" in 127.*|::1|*%lo*) return 0;; esac ;;
					67|68) return 0 ;; # DHCP
					5353) return 0 ;; # mDNS
					123) return 0 ;; # NTP
				esac
				;;
			tcp)
				case "$p_port" in
					53) case "$p_addr" in 127.*|::1|*%lo*) return 0;; esac ;;
					631) return 0 ;; # CUPS local
					25|110|143) case "$p_addr" in 127.*|::1|*%lo*) return 0;; esac ;;
				esac
				;;
		esac
		return 1
	}

	if have_cmd ss; then
		output="$(ss -tulpen 2>/dev/null)"
	elif have_cmd netstat; then
		output="$(netstat -tulpen 2>/dev/null)"
	else
		warn "Neither ss nor netstat available."
		return
	fi

	log "${BOLD}Expected ports:${RESET} tcp=[${EXPECTED_TCP_PORTS:-$EXPECTED_PORTS}] udp=[${EXPECTED_UDP_PORTS:-$EXPECTED_PORTS}]"
	printf "%s\n" "$output" | head -n 40

	while IFS= read -r line; do
		proto=$(printf "%s" "$line" | awk '{print $1}')
		lp=$(printf "%s" "$line" | awk '{print $5}')
		[ -z "$lp" ] && continue
		addr=$(printf "%s" "$lp" | sed 's/\[//g; s/\]//g; s/:\([0-9]\+\)$//')
		port=$(printf "%s" "$lp" | sed 's/.*:\([0-9][0-9]*\)$/\1/')
		wild=0
		case "$addr" in
			0.0.0.0|::|\*) wild=1 ;;
		esac

		if [ -n "$port" ] && port_in_expected "$proto" "$port"; then
			:
		elif [ -n "$port" ] && port_whitelist "$proto" "$port" "$addr"; then
			:
		elif [ -n "$port" ]; then
			unexpected=1
			add_warn "Unexpected listening port ${port} (${proto}) on ${addr}"
		fi

		if [ "$wild" -eq 1 ] && [ -n "$port" ] && ! port_in_expected "$proto" "$port" && port_whitelist "$proto" "$port" "$addr"; then
			:
		elif [ "$wild" -eq 1 ] && [ -n "$port" ] && ! port_in_expected "$proto" "$port"; then
			add_warn "Port ${port} is bound on all interfaces (${proto})"
		fi
	done <<< "$(printf "%s\n" "$output" | tail -n +2)"

	[ "$unexpected" -eq 0 ] && ok "No unexpected listening ports beyond expected tcp=[${EXPECTED_TCP_PORTS:-$EXPECTED_PORTS}] udp=[${EXPECTED_UDP_PORTS:-$EXPECTED_PORTS}]"
}

check_selinux_apparmor() {
	section "MAC / LSM status (SELinux/AppArmor)"

	if have_cmd getenforce; then
		local ge
		ge="$(getenforce 2>/dev/null)"
		if printf "%s" "$ge" | grep -qi enforcing; then
			ok "SELinux: $ge"
		else
			add_warn "SELinux not enforcing (getenforce=$ge)"
		fi
	elif have_cmd sestatus; then
		sestatus 2>/dev/null | head -n 5
	fi

	if have_cmd apparmor_status; then
		local aa
		aa="$(apparmor_status 2>/dev/null | head -n 5)"
		printf "%s\n" "$aa"
		printf "%s" "$aa" | grep -qi "complain" && add_warn "Some AppArmor profiles in complain mode."
	elif [ -d /sys/module/apparmor ]; then
		add_warn "AppArmor module loaded but apparmor_status unavailable."
	fi
}

check_ssh_key_permissions() {
	section "SSH keys & permissions"

	local homes=("$HOME")
	if [ "$IS_ROOT" -eq 1 ] && [ "$HOME" != "/root" ]; then
		homes+=("/root")
	fi

	for h in "${homes[@]}"; do
		[ -d "$h/.ssh" ] || continue
		log "${BOLD}$h/.ssh:${RESET}"
		ls -ld "$h/.ssh" 2>/dev/null
		for f in "$h"/.ssh/id_*; do
			[ -f "$f" ] || continue
			mode=$(stat -c "%a" "$f" 2>/dev/null || echo "?")
			log "  $(basename "$f") mode: $mode"
			case "$mode" in
				400|600|600? )
					:
					;;
				*)
					add_warn "SSH private key $f has loose permissions ($mode). Use 600."
					;;
			esac
		done
		for f in "$h"/.ssh/authorized_keys "$h"/.ssh/known_hosts; do
			[ -f "$f" ] || continue
			mode=$(stat -c "%a" "$f" 2>/dev/null || echo "?")
			case "$(basename "$f")" in
				authorized_keys)
					[ "$mode" != "600" ] && add_warn "$f should be 600 (is $mode)."
					;;
				known_hosts)
					[ "$mode" != "644" ] && [ "$mode" != "600" ] && add_warn "$f should be 644 or 600 (is $mode)."
					;;
			esac
		done
	done
}

check_capabilities_binaries() {
	section "File capabilities scan (quick)"

	if ! have_cmd getcap; then
		warn "getcap not available, skipping capabilities scan."
		return
	fi

	local caps
	caps="$(getcap -r / 2>/dev/null | head -n 50)"
	if [ -z "$caps" ]; then
		ok "No file capabilities found in quick scan."
	else
		log "${BOLD}Capabilities (top 50):${RESET}"
		printf "%s\n" "$caps"
		while IFS= read -r line; do
			case "$line" in
				*cap_net_raw*|*cap_net_admin*|*cap_dac_read_search*|*cap_dac_override*|*cap_sys_admin*|*cap_setuid*|*cap_setgid*|*cap_sys_module*|*cap_sys_ptrace*|*cap_sys_resource*|*cap_setpcap*)
					add_warn "High-priv capability detected: $line"
					;;
			esac
		done <<< "$caps"
	fi
}

check_sysctl_hardening() {
	[ "$NO_SYSCTL" -eq 1 ] && { warn "Sysctl hardening checks skipped (--no-sysctl)."; return; }

	section "Kernel/sysctl hardening (quick)"

	get_sysctl() {
		local key="$1"
		sysctl -n "$key" 2>/dev/null || cat "/proc/sys/${key//./\/}" 2>/dev/null
	}

	check_key() {
		local key="$1" expect="$2" cmp="$3" desc="$4"
		local val
		val="$(get_sysctl "$key")"
		if [ -z "$val" ]; then
			add_warn "Cannot read $key ($desc)."
			return
		fi
		case "$val" in
			(*[!0-9]*)
				add_warn "$key is non-numeric ($val), manual review ($desc)."
				return
				;;
		esac
		case "$cmp" in
			ge)
				if [ "$val" -ge "$expect" ]; then ok "$key=$val ($desc)"; else add_warn "$key=$val (expected >=$expect) - $desc"; fi
				;;
			eq)
				if [ "$val" -eq "$expect" ]; then ok "$key=$val ($desc)"; else add_warn "$key=$val (expected $expect) - $desc"; fi
				;;
		esac
	}

	check_key kernel.unprivileged_userns_clone 0 eq "User namespaces off is safer on shared hosts"
	check_key kernel.kptr_restrict 1 ge "Hide kernel pointers from unprivileged users"
	check_key kernel.randomize_va_space 2 eq "ASLR fully enabled"
	check_key fs.protected_symlinks 1 ge "Protect symlink following"
	check_key fs.protected_hardlinks 1 ge "Protect hardlink creation"
	check_key fs.protected_fifos 1 ge "Protect FIFO writes"
	check_key fs.protected_regular 2 ge "Protect writes to regular files in world-writable dirs"
}

check_av_edr_presence() {
	section "Security agents / EDR hints"

	local patterns="falcon|crowdstrike|sentinel|defender|sophos|bitdefender|carbonblack|tanium|kaspersky|msdefender|eset|clamd|fsav"
	if have_cmd ps; then
		ps -eo comm,pid,args 2>/dev/null | grep -Ei "$patterns" | head -n 20 && add_warn "Potential AV/EDR processes detected (review above)."
	fi

	if have_cmd systemctl; then
		systemctl list-units --type=service --state=running 2>/dev/null | grep -Ei "$patterns" | head -n 20 && add_warn "Potential AV/EDR services detected (review above)."
	fi

	if have_cmd dpkg-query; then
		dpkg-query -W -f='${Package}\n' 2>/dev/null | grep -Ei "$patterns" | head -n 20 && add_warn "Potential AV/EDR packages installed."
	elif have_cmd rpm; then
		rpm -qa 2>/dev/null | grep -Ei "$patterns" | head -n 20 && add_warn "Potential AV/EDR packages installed."
	fi
}

check_security_updates() {
	section "Security updates (offline heuristic)"

	if have_cmd apt-get; then
		local sim sec
		sim="$(apt-get -s upgrade 2>/dev/null | grep '^Inst ' || true)"
		if [ -z "$sim" ]; then
			warn "apt-get -s upgrade shows no upgradable packages (maybe run apt update)."
		else
			sec="$(printf "%s\n" "$sim" | grep -Ei 'security|ubuntu-security' || true)"
			if [ -n "$sec" ]; then
				add_warn "Security updates available via apt (review & patch)."
				printf "%s\n" "$sec" | head -n 20
			else
				add_warn "Upgradable packages detected (no explicit security tag). Review before patching."
				printf "%s\n" "$sim" | head -n 20
			fi
		fi
	elif have_cmd dnf; then
		add_warn "dnf present: consider 'dnf check-update --security' (not run here)."
	elif have_cmd yum; then
		add_warn "yum present: consider 'yum updateinfo list security' (not run here)."
	else
		warn "No known package manager detected for security updates."
	fi
}

check_logs_recent() {
	section "Recent auth/system logs (last 48h, truncated)"

	if have_cmd journalctl; then
		log "${BOLD}journalctl (ssh/sudo) warnings last 48h:${RESET}"
		journalctl -S -48h -u ssh -u sshd -u sudo -p warning..alert --no-pager 2>/dev/null | tail -n 40
	else
		if [ -f /var/log/auth.log ]; then
			log "${BOLD}/var/log/auth.log (tail):${RESET}"
			tail -n 40 /var/log/auth.log 2>/dev/null
		elif [ -f /var/log/secure ]; then
			log "${BOLD}/var/log/secure (tail):${RESET}"
			tail -n 40 /var/log/secure 2>/dev/null
		else
			warn "No auth log found."
		fi
	fi
}

check_persistence_artifacts() {
	section "Persistence & startup artifacts"

	if have_cmd systemctl; then
		log "${BOLD}Enabled systemd services (top 30):${RESET}"
		systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -n 30
		log ""
		log "${BOLD}User services (~/.config/systemd/user, if any):${RESET}"
		systemctl --user list-unit-files --type=service --state=enabled 2>/dev/null | head -n 20 || true
	fi

	if [ -d /etc/systemd/system ]; then
		log ""
		log "${BOLD}Services pointing to /tmp (quick grep):${RESET}"
		find_quick /etc/systemd/system -maxdepth "$MAX_DEPTH" -type f -name '*.service' -print | xargs -r grep -H "/tmp" 2>/dev/null | head -n 20
	fi

	if [ -d "$HOME" ]; then
		log ""
		log "${BOLD}Shell init files (world/group writable?):${RESET}"
		for f in "$HOME/.bashrc" "$HOME/.profile" "$HOME/.zshrc"; do
			[ -f "$f" ] || continue
			mode=$(stat -c "%a" "$f" 2>/dev/null || echo "?")
			case "$mode" in
				77?|66?|744|755)
					add_warn "$f is permissive ($mode). Consider 600/640."
					;;
			esac
		done
	fi
}

check_shell_binaries() {
	section "Shell / sudo binaries integrity (quick)"

	local files=(
		"/bin/sh"
		"/bin/bash"
		"/bin/dash"
		"/usr/bin/sudo"
	)

	for f in "${files[@]}"; do
		[ -e "$f" ] || continue
		owner=$(stat -c "%U:%G" "$f" 2>/dev/null || echo "?")
		mode=$(stat -c "%a" "$f" 2>/dev/null || echo "?")
		log "${BOLD}$f:${RESET} owner=$owner mode=$mode"
		[ "$owner" != "root:root" ] && add_warn "$f owner is $owner (expected root:root)."
		if unpriv_writable "$f"; then
			add_crit "$f is writable by non-root (should be immutable). $(perm_detail "$f")"
		fi
		[ "$f" != "/usr/bin/sudo" ] && [ -u "$f" ] && add_warn "$f has setuid bit set (unexpected)."
	done
}

check_acl_and_attrs() {
	section "ACLs / immutable attributes on sensitive files"

	local files=(
		"/etc/passwd"
		"/etc/shadow"
		"/etc/sudoers"
		"/etc/ssh/sshd_config"
		"/etc/crontab"
	)

	for f in "${files[@]}"; do
		[ -e "$f" ] || continue
		ls -ld "$f" 2>/dev/null
		if have_cmd getfacl; then
			getfacl --absolute-names "$f" 2>/dev/null | grep -vE '^#' | grep -q ':' && add_warn "$f has ACL entries (review)."
		fi
		if have_cmd lsattr; then
			lsattr "$f" 2>/dev/null | grep -q ' i ' && add_warn "$f has immutable bit set (check provenance)."
		fi
	done
}

check_recent_changes() {
	section "Recent changes (last $RECENT_DAYS day(s))"

	local dirs=(
		"/etc"
		"/usr/local/bin"
		"/usr/local/sbin"
		"/var/www"
		"/srv"
	)

	for d in "${dirs[@]}"; do
		[ -d "$d" ] || continue
		log "${BOLD}Modified in $d:${RESET}"
		find_quick "$d" -maxdepth "$MAX_DEPTH" -type f -mtime "-$RECENT_DAYS" | head -n 40
	done
}

check_authorized_keys_options() {
	section "SSH authorized_keys options"

	local homes=("$HOME")
	if [ "$IS_ROOT" -eq 1 ] && [ "$HOME" != "/root" ]; then
		homes+=("/root")
	fi

	for h in "${homes[@]}"; do
		f="$h/.ssh/authorized_keys"
		[ -f "$f" ] || continue
		while IFS= read -r line; do
			line=${line%%#*}
			[ -z "$line" ] && continue
			printf "%s" "$line" | grep -q "ssh-" || continue
			printf "%s" "$line" | grep -q "command=" || printf "%s" "$line" | grep -q "from=" || add_warn "$f entry without restrictions (consider command=/from= for shared accounts)."
		done < "$f"
	done
}

check_cve_correlations() {
	section "CVE correlation (heuristic, verify manually)"

	if [ -n "$SUDO_VERSION" ]; then
		case "$SUDO_VERSION" in
			1.6.*|1.7.*|1.8.*|1.9.[0-5]*)
				add_warn "Sudo version $SUDO_VERSION may be impacted by CVE-2021-3156 (Baron Samedit). Verify distro patches."
				add_cve_hint "CVE-2021-3156 (sudo) - check $SUDO_VERSION"
				;;
		esac
	fi

	if [ -n "$OPENSSH_VERSION" ]; then
		case "$OPENSSH_VERSION" in
			8.[0-9]*|9.[0-5]*)
				add_warn "OpenSSH server $OPENSSH_VERSION: review recent CVEs (ex: CVE-2024-6387 pour 9.2-9.7)."
				add_cve_hint "OpenSSH $OPENSSH_VERSION - review CVE-2024-6387 window"
				;;
		esac
	fi

	if [ -n "$DOCKER_VERSION" ]; then
		case "$DOCKER_VERSION" in
			19.*|20.*|23.*|24.*)
				add_warn "Docker $DOCKER_VERSION: review runc/containerd CVEs (ex: CVE-2019-5736, CVE-2024-21626)."
				add_cve_hint "Docker/runc CVEs (CVE-2019-5736, CVE-2024-21626) for $DOCKER_VERSION"
				;;
		esac
	fi

	if [ -n "$KERNEL_VERSION" ]; then
		km="${KERNEL_VERSION%%.*}"
		case "$km" in
			3|4)
				add_warn "Kernel $KERNEL_VERSION est ancien; revoir les LPE (Dirty COW CVE-2016-5195, SegmentSmack CVE-2018-5390, etc.)."
				add_cve_hint "Kernel LPEs (Dirty COW CVE-2016-5195, CVE-2018-5390) for kernel $KERNEL_VERSION"
				;;
		esac
	fi
}
check_systemd_exec_writable() {
	section "[ROOT] Systemd ExecStart writable paths"

	if [ "$IS_ROOT" -ne 1 ]; then
		warn "Not root, skipping writable ExecStart check."
		return
	fi

	local units
	units=$(find_quick /etc/systemd/system /lib/systemd/system -maxdepth "$MAX_DEPTH" -type f -name '*.service' 2>/dev/null | head -n 200)
	[ -z "$units" ] && { warn "No service units found (or unreadable)."; return; }

	check_exec_line() {
		local unit="$1" line="$2"
		[ -z "$line" ] && return
		local cmd
		cmd=${line#Exec}
		cmd=${cmd#*=}
		cmd=${cmd#-}
		cmd=${cmd%% *}
		cmd=${cmd%\"}
		cmd=${cmd#\"}
		[ -z "$cmd" ] && return
		if unpriv_writable "$cmd"; then
			add_crit "$unit $line target $cmd writable by non-root. $(perm_detail "$cmd")"
			return
		fi
		local dir
		dir=$(dirname "$cmd")
		if [ -d "$dir" ] && [ "$dir" != "." ] && unpriv_writable "$dir"; then
			add_warn "$unit $line directory writable by non-root: $dir $(perm_detail "$dir")"
		fi

		if printf "%s\n" "$line" | grep -q -- "-c"; then
			local payload script
			payload="$(printf "%s\n" "$line" | sed 's/^.*-c[[:space:]]*//')"
			payload="${payload#\"}"; payload="${payload#\'}"
			script="${payload%%[[:space:];]*}"
			script="${script%\"}"; script="${script%\'}"
			if [ -n "$script" ] && { [[ "$script" == /* ]] || [[ "$script" == ./* ]]; }; then
				if unpriv_writable "$script"; then
					add_warn "$unit shell payload $script writable by non-root. $(perm_detail "$script")"
				else
					local sdir
					sdir=$(dirname "$script")
					if [ -d "$sdir" ] && unpriv_writable "$sdir"; then
						add_warn "$unit shell payload directory writable by non-root: $sdir $(perm_detail "$sdir")"
					fi
				fi
			fi
		fi
	}

	while IFS= read -r unit; do
		[ -f "$unit" ] || continue
		while IFS= read -r line; do
			case "$line" in
				ExecStart=*|ExecStartPre=*|ExecStartPost=*|ExecReload=*)
					check_exec_line "$unit" "$line"
					;;
			esac
		done < "$unit"
	done <<< "$units"
}


check_root_sudo_and_sudoers() {
	section "[ROOT] Sudo & sudoers configuration"

	if have_cmd sudo; then
		run_cmd "sudo -V (version)" sudo -V | head -n3
	else
		warn "sudo not installed."
	fi

	log ""
	log "${BOLD}/etc/sudoers (interesting patterns):${RESET}"
	if [ -r /etc/sudoers ]; then
		grep -En 'NOPASSWD|!authenticate|ALL\s*=\s*\(ALL\)\s*ALL' /etc/sudoers 2>/dev/null || log "  (no obvious dangerous patterns found)"
	else
		warn "/etc/sudoers not readable (strange if root?)."
	fi

	if [ -d /etc/sudoers.d ]; then
		log ""
		log "${BOLD}/etc/sudoers.d snippets:${RESET}"
		grep -REn 'NOPASSWD|!authenticate|ALL\s*=\s*\(ALL\)\s*ALL' /etc/sudoers.d 2>/dev/null || log "  (no obvious dangerous entries in sudoers.d)"
	fi

	if grep -Eq 'NOPASSWD' /etc/sudoers 2>/dev/null || grep -Rqs 'NOPASSWD' /etc/sudoers.d 2>/dev/null; then
		add_warn "NOPASSWD entries present in sudoers. Review if they are really necessary."
	else
		ok "No NOPASSWD entries detected in sudoers."
	fi
}

check_root_suid_sgid() {
	section "[ROOT] SUID / SGID binaries (global)"

	if ! have_cmd find; then
		warn "find not available, cannot enumerate SUID/SGID binaries."
		return
	fi

	log "${BOLD}Some SUID root binaries (top 50):${RESET}"
	find_quick / -xdev -type f -perm -4000 | head -n 50

	log ""
	log "${BOLD}Some SGID binaries (top 30):${RESET}"
	find_quick / -xdev -type f -perm -2000 | head -n 30

	log ""
	log "${BOLD}World-writable SUID/SGID binaries (top 10):${RESET}"
	WW=$(find_quick / -xdev -type f \( -perm -4000 -o -perm -2000 \) -perm -0002 | head -n 10)
	if [ -n "$WW" ]; then
		add_crit "World-writable SUID/SGID binaries detected (high risk)."
		printf "%s\n" "$WW"
	else
		ok "No world-writable SUID/SGID binaries found in quick search."
	fi
}

# Checklist SUID/SGID qui sentent le privesc
check_suid_gtfo_bins() {
	section "[ROOT] SUID/SGID risky binaries (GTFO-style)"

	if ! have_cmd find; then
		warn "find not available, cannot enumerate SUID/SGID binaries."
		return
	fi

	local patterns="nmap|vim|vi|less|more|nano|awk|find|python[0-9.]*|perl|ruby|tar|cp|mv|rsync|socat|openssl|passwd|pkexec|env|mount|umount|newuidmap|newgidmap|bash|dash|sh|sed|ed|pico|zip|busybox"
	local hits
	hits=$(find_quick / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | grep -E "/($patterns)$" | head -n 50)
	if [ -n "$hits" ]; then
		add_warn "SUID/SGID binaries matching common privesc primitives detected (review GTFOBins techniques)."
		printf "%s\n" "$hits"
	else
		ok "No obviously risky SUID/SGID GTFO-style binaries found in quick scan."
	fi
}

check_root_cron_global() {
	section "[ROOT] Cron configuration"

	if [ -r /etc/crontab ]; then
		log "${BOLD}/etc/crontab:${RESET}"
		sed -n '1,80p' /etc/crontab
	else
		warn "/etc/crontab not readable (unexpected for root)."
	fi

	for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
		if [ -d "$d" ]; then
			log ""
			log "${BOLD}$d:${RESET}"
			ls -l "$d"
		fi
	done

	if have_cmd find; then
		log ""
		log "${BOLD}World-writable cron scripts (top 10):${RESET}"
		WW_CRON=$(find_quick /etc/cron* -type f -perm -0002 | head -n 10)
		if [ -n "$WW_CRON" ]; then
			add_warn "World-writable cron scripts found. Could be abused for privesc."
			printf "%s\n" "$WW_CRON"
		else
			ok "No obvious world-writable cron scripts in /etc/cron*."
		fi
	fi
}

check_root_path_and_writable_dirs() {
	section "[ROOT] PATH & writable directories"

	log "${BOLD}PATH:${RESET}"
	echo "$PATH"

	echo "$PATH" | tr ':' '\n' | grep -qx '.' && add_warn "PATH contains '.' (current directory) which is risky."
	printf "%s" "$PATH" | grep -q '::' && add_warn "PATH contains empty segments (::)."

	IFS=':' read -r -a path_elems <<< "$PATH"
	ANY_WW=0
	for dir in "${path_elems[@]}"; do
		[ -z "$dir" ] && continue
		if [ -d "$dir" ] && unpriv_writable "$dir"; then
			ANY_WW=1
			add_warn "PATH directory writable by non-root users: $dir $(perm_detail "$dir") (possible PATH hijack)."
		fi
	done
	[ "$ANY_WW" -eq 0 ] && ok "No PATH directory writable by non-root detected."
}

check_root_sensitive_files_perms() {
	section "[ROOT] Sensitive files permissions"

	local files=(
		"/etc/passwd"
		"/etc/shadow"
		"/etc/sudoers"
		"/etc/ssh/sshd_config"
		"/etc/crontab"
	)

	for f in "${files[@]}"; do
		if [ -e "$f" ]; then
			perm=$(stat -c "%a %U:%G" "$f" 2>/dev/null || echo "unknown")
			log "${BOLD}$f:${RESET} $perm"

			if [ "$f" = "/etc/shadow" ]; then
				mode=$(stat -c "%a" "$f" 2>/dev/null || echo "???")
				case "$mode" in
					60[0-4]|64[0-4])
						ok "/etc/shadow permissions look reasonable ($mode)."
						;;
					*)
						add_crit "/etc/shadow has unusual permissions ($mode). Very high risk if world/group readable."
						;;
				esac
			fi

			if [ "$f" = "/etc/sudoers" ]; then
				mode=$(stat -c "%a" "$f" 2>/dev/null || echo "???")
				case "$mode" in
					44[0-4])
						ok "/etc/sudoers permissions look reasonable ($mode)."
						;;
					*)
						add_warn "/etc/sudoers permissions are unusual ($mode). Usually 440 is recommended."
						;;
				esac
			fi
		else
			log "$f not present."
		fi
	done
}

check_root_processes_and_services() {
	section "[ROOT] Processes & services"

	if have_cmd ps; then
		log "${BOLD}Root-owned processes (head):${RESET}"
		ps -eo user,pid,cmd --sort=user 2>/dev/null | grep '^root ' | head -n 25
	else
		warn "ps not available."
	fi

	if have_cmd systemctl; then
		log ""
		log "${BOLD}Running systemd services (head):${RESET}"
		systemctl list-units --type=service --state=running 2>/dev/null | head -n 30
	fi
}

check_root_firewall_and_listening() {
	section "[ROOT] Firewall / listening sockets"

	if have_cmd ufw; then
		log "${BOLD}UFW status:${RESET}"
		ufw status verbose 2>/dev/null || log "  (cannot read UFW status)"
	fi

	if have_cmd iptables; then
		log ""
		log "${BOLD}iptables -L -n (head):${RESET}"
		iptables -L -n 2>/dev/null | head -n 20
	fi

	if have_cmd ss; then
		log ""
		log "${BOLD}Listening TCP sockets (ss -tlnp, head):${RESET}"
		ss -tlnp 2>/dev/null | head -n 20
	elif have_cmd netstat; then
		log ""
		log "${BOLD}Listening TCP sockets (netstat -tlnp, head):${RESET}"
		netstat -tlnp 2>/dev/null | head -n 20
	fi
}


user_check_sudo_rights() {
	section "[USER] Sudo rights for current user"

	if have_cmd sudo; then
		log "${BOLD}Trying non-interactive sudo -l (no password):${RESET}"
		if sudo -n -l 2>/dev/null; then
			add_crit "User can run sudo without password (or has sudo rights visible via sudo -l)."
		else
			ok "No sudo -n -l output (either no sudo rights or password required)."
		fi
	else
		warn "sudo not installed."
	fi
}

user_analyze_sudo_rules() {
	section "[USER] sudo -l detailed analysis"

	if ! have_cmd sudo; then
		warn "sudo not installed."
		return
	fi

	local out
	out="$(sudo -n -l 2>/dev/null || true)"
	if [ -z "$out" ]; then
		log "No sudo -l output (probably password required or no sudo rights)."
		return
	fi

	log "$out"

	printf "%s" "$out" | grep -qi "NOPASSWD" && add_warn "NOPASSWD sudo entries present for this user."

	local risky_cmds="tar|less|vi|vim|nano|awk|find|python|perl|rsync|socat|tee|bash|sh|cp|mv|cat"
	while IFS= read -r line; do
		printf "%s" "$line" | grep -Eq "$risky_cmds" || continue
		add_warn "sudo -l allows risky command: $line"
	done <<< "$out"
}

user_check_suid_sgid() {
	section "[USER] SUID / SGID binaries reachable"

	if ! have_cmd find; then
		warn "find not available, cannot enumerate SUID/SGID."
		return
	fi

	log "${BOLD}Some SUID root binaries (top 30):${RESET}"
	find_quick / -xdev -type f -perm -4000 | head -n 30

	log ""
	log "${BOLD}Some SGID binaries (top 20):${RESET}"
	find_quick / -xdev -type f -perm -2000 | head -n 20

	log ""
	log "${BOLD}World-writable SUID/SGID binaries (top 10):${RESET}"
	WW=$(find_quick / -xdev -type f \( -perm -4000 -o -perm -2000 \) -perm -0002 | head -n 10)
	if [ -n "$WW" ]; then
		add_crit "World-writable SUID/SGID binaries detected (high risk)."
		printf "%s\n" "$WW"
	else
		ok "No world-writable SUID/SGID binaries found in quick search."
	fi
}

user_check_world_writable_and_path() {
	section "[USER] PATH & world-writable directories"

	log "${BOLD}Current PATH:${RESET}"
	echo "$PATH"

	echo "$PATH" | tr ':' '\n' | grep -qx '.' && add_warn "PATH contains '.' (current directory) which is risky."
	printf "%s" "$PATH" | grep -q '::' && add_warn "PATH contains empty segments (::)."

	IFS=':' read -r -a path_elems <<< "$PATH"
	ANY_WW=0
	for dir in "${path_elems[@]}"; do
		[ -z "$dir" ] && continue
		if [ -d "$dir" ] && unpriv_writable "$dir"; then
			ANY_WW=1
			add_warn "PATH directory writable by current user: $dir $(perm_detail "$dir") (possible PATH hijacking)."
		fi
	done
	[ "$ANY_WW" -eq 0 ] && ok "No PATH directory writable by current user detected."

	if have_cmd find; then
		log ""
		log "${BOLD}Some world-writable directories (top 20):${RESET}"
		find_quick / -xdev -maxdepth "$MAX_DEPTH" -type d -perm -0002 | head -n 20
	fi
}

user_check_cron_writable() {
	section "[USER] Cron / timers writable by current user"

	if ! have_cmd find; then
		warn "find not available, cannot analyze cron directories."
		return
	fi

	log "${BOLD}World-writable files under /etc/cron* (top 10):${RESET}"
	WW_CRON=$(find_quick /etc/cron* -type f -perm -0002 | head -n 10)
	if [ -n "$WW_CRON" ]; then
		add_warn "World-writable cron scripts found (cron hijack possible)."
		printf "%s\n" "$WW_CRON"
	else
		ok "No obvious world-writable cron scripts in /etc/cron*."
	fi

	log ""
	log "${BOLD}Crontab for current user (if any):${RESET}"
	if have_cmd crontab; then
		crontab -l 2>/dev/null || log "  (no user crontab or not allowed)"
	else
		warn "crontab command not available."
	fi

	if have_cmd systemctl; then
		log ""
		log "${BOLD}User systemd timers (head):${RESET}"
		systemctl --user list-timers --all 2>/dev/null | head -n 15
	fi
}

user_check_configs_and_sensitive_readable() {
	section "[USER] Sensitive configs readable by this user"

	local files=(
		"/etc/passwd"
		"/etc/shadow"
		"/etc/sudoers"
		"/etc/ssh/sshd_config"
		"/etc/crontab"
	)

	for f in "${files[@]}"; do
		if [ -e "$f" ]; then
			if [ -r "$f" ]; then
				log "${BOLD}$f is readable by $CURRENT_USER${RESET}"
				ls -l "$f"
				if [ "$f" = "/etc/shadow" ]; then
					add_crit "/etc/shadow is readable by current user (huge risk)."
				elif [ "$f" = "/etc/sudoers" ]; then
					add_warn "/etc/sudoers is readable. This can leak policy details to a compromised user."
				fi
			fi
		fi
	done
}

user_search_for_secrets() {
	section "[USER] Searching for potential secrets in readable files"

	if ! have_cmd find || ! have_cmd grep; then
		warn "find or grep not available, skipping secrets search."
		return
	fi

	local search_dirs=(
		"/etc"
		"/opt"
		"/var/www"
		"/var/www/html"
		"/srv"
		"/var/backups"
		"/home"
		"$HOME/.config"
	)

	log "${BOLD}Looking for patterns like password/secret/token in small text files... (quick scan)${RESET}"
	log "Heuristic only, expect some false positives."

	for d in "${search_dirs[@]}"; do
		[ -d "$d" ] || continue
		log ""
		log "${BOLD}Directory: $d${RESET}"

		find_quick "$d" -maxdepth "$MAX_DEPTH" -type f -size -2M \
			-not -path "*/.git/*" \
			-not -path "*/node_modules/*" \
			-not -path "*/venv/*" \
			-not -path "*/.cache/*" \
			| head -n 800 \
			| xargs -r grep -niE 'password|passwd|pwd[^a-z]|secret|token|apikey|api_key|aws_access_key_id|aws_secret_access_key|github_pat|ghp_[a-z0-9]+|gitlab.*token|bearer[[:space:]]+|authorization:' 2>/dev/null \
			| head -n 80
	done
}

# check historiques pour traquer des credentials
check_user_histories() {
	section "[USER] Shell and tool history files"

	local history_files=(
		"$HOME/.bash_history"
		"$HOME/.zsh_history"
		"$HOME/.mysql_history"
		"$HOME/.psql_history"
		"$HOME/.sqlite_history"
		"$HOME/.python_history"
	)

	for f in "${history_files[@]}"; do
		[ -f "$f" ] || continue
		if unpriv_writable "$f"; then
			add_warn "$f is writable by non-root users $(perm_detail "$f")."
		fi
		log "${BOLD}Recent lines from $(basename "$f"):${RESET}"
		tail -n 10 "$f" 2>/dev/null
	done
}

user_check_user_owned_files_outside_home() {
	section "[USER] Files owned by current user outside its home"

	if ! have_cmd find; then
		warn "find not available, cannot enumerate files owned by current user."
		return
	fi

	HOME_DIR="${HOME:-/home/$CURRENT_USER}"

	log "${BOLD}Some files owned by $CURRENT_USER outside $HOME_DIR (top 30):${RESET}"
	find_quick / -xdev -maxdepth "$MAX_DEPTH" -user "$CURRENT_USER" -not -path "$HOME_DIR*" | head -n 30
}

user_check_docker_and_sockets() {
	section "[USER] Docker / sockets / special groups"

	log "${BOLD}Groups for current user:${RESET}"
	id

	if id | grep -qE '\bdocker\b'; then
		add_warn "User is in docker group (privesc via docker is often possible)."
	fi

	if [ -S /var/run/docker.sock ]; then
		if [ -w /var/run/docker.sock ]; then
			add_crit "User can write to /var/run/docker.sock (highly exploitable)."
		elif [ -r /var/run/docker.sock ]; then
			add_warn "User can read /var/run/docker.sock."
		fi
	fi

	if have_cmd docker; then
		log ""
		log "${BOLD}Docker containers (top 10):${RESET}"
		docker ps --format '{{.ID}} {{.Image}} {{.Status}} {{.Ports}} {{.Names}}' 2>/dev/null | head -n 10 || log "  (cannot list containers)"

		ids=$(docker ps -q 2>/dev/null | head -n 5)
		for cid in $ids; do
			docker inspect -f '{{.Id}} privileged={{.HostConfig.Privileged}} caps={{.HostConfig.CapAdd}} binds={{.HostConfig.Binds}}' "$cid" 2>/dev/null | sed 's/^/  /'
		done

		log ""
		log "${BOLD}Docker images (top 10):${RESET}"
		docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null | head -n 10 || true
	fi

	if id | grep -qE '\blxd\b'; then
		add_warn "User is in lxd group (LXD container privesc possible)."
	fi
	if have_cmd lxc; then
		log ""
		log "${BOLD}LXD info (short):${RESET}"
		lxc list 2>/dev/null | head -n 5 || true
	fi

	if [ -f "$HOME/.kube/config" ]; then
		add_warn "Kubeconfig found at $HOME/.kube/config (check cluster permissions)."
		ls -l "$HOME/.kube/config"
	fi

	if [ -S /run/containerd/containerd.sock ] && [ -w /run/containerd/containerd.sock ]; then
		add_warn "User can write to containerd socket."
	fi

	if [ -c /dev/kvm ]; then
		if [ -w /dev/kvm ]; then
			add_warn "/dev/kvm is writable (VM escape risk if attacker controls VM)."
		elif [ -r /dev/kvm ]; then
			add_warn "/dev/kvm is readable."
		fi
	fi

	if have_cmd find; then
		log ""
		log "${BOLD}Some sockets in /var/run (top 20):${RESET}"
		find_quick /var/run -maxdepth 2 -type s | head -n 20
	fi

	if [ -S /var/run/redis/redis-server.sock ]; then
		if unpriv_writable /var/run/redis/redis-server.sock; then
			add_warn "Redis socket /var/run/redis/redis-server.sock writable by non-root."
		elif [ -r /var/run/redis/redis-server.sock ]; then
			add_warn "Redis socket readable by current user (data leakage)."
		fi
	fi

	if [ -S /var/run/postgresql/.s.PGSQL.5432 ]; then
		if unpriv_writable /var/run/postgresql/.s.PGSQL.5432; then
			add_warn "PostgreSQL socket writable by non-root."
		elif [ -r /var/run/postgresql/.s.PGSQL.5432 ]; then
			add_warn "PostgreSQL socket readable by current user."
		fi
	fi
}


main() {
	if [ "$IS_ROOT" -eq 1 ]; then
		# Parcours root pour voir tout ce qui est exploitable
		section "Linux Privilege Escalation Audit - ROOT MODE"
		log "Running as root: system-wide hardening / misconfiguration audit."
		log "Goal: help administrators see what is exposed to low-priv users."
		log ""

		check_basic_system_info
		check_versions_with_heuristics
		check_selinux_apparmor
		check_mount_options
		check_nfs_cifs_exports
		check_av_edr_presence
		check_packages_inventory
		check_security_updates
		check_sysctl_hardening
		check_listening_services
		check_root_sudo_and_sudoers
		check_root_suid_sgid
		check_suid_gtfo_bins
		check_root_cron_global
		check_root_path_and_writable_dirs
		check_shell_binaries
		check_systemd_exec_writable
		check_root_sensitive_files_perms
		check_root_processes_and_services
		check_root_firewall_and_listening
		check_capabilities_binaries
		check_ssh_key_permissions
		check_authorized_keys_options
		check_persistence_artifacts
		user_check_docker_and_sockets
		user_search_for_secrets
		check_acl_and_attrs
		check_recent_changes
		check_logs_recent
		check_cve_correlations
	else
		# Parcours utilisateur pour simuler un attaquant déjà connecté
		section "Linux Privilege Escalation Audit - USER MODE"
		log "Running as non-root user: post-exploitation style audit for $CURRENT_USER."
		log "Goal: see what THIS account can read/write that may lead to privesc."
		log ""

		check_basic_system_info
		check_versions_with_heuristics
		check_selinux_apparmor
		check_mount_options
		check_nfs_cifs_exports
		check_av_edr_presence
		check_packages_inventory
		check_security_updates
		check_sysctl_hardening
		check_listening_services
		user_check_sudo_rights
		user_analyze_sudo_rules
		user_check_suid_sgid
		check_suid_gtfo_bins
		user_check_world_writable_and_path
		check_shell_binaries
		user_check_cron_writable
		user_check_configs_and_sensitive_readable
		user_search_for_secrets
		check_user_histories
		check_ssh_key_permissions
		check_authorized_keys_options
		check_capabilities_binaries
		check_persistence_artifacts
		check_acl_and_attrs
		check_recent_changes
		check_logs_recent
		check_cve_correlations
		user_check_user_owned_files_outside_home
		user_check_docker_and_sockets
	fi

	section "Summary"

	log "Potentially critical findings: $CRIT_COUNT"
	log "Potential warnings: $WARN_COUNT"

	if [ "$CRIT_COUNT" -eq 0 ] && [ "$WARN_COUNT" -eq 0 ]; then
		ok "No obvious weak points found. Manual review is still recommended."
	else
		warn "Review the findings above and validate which ones are actually exploitable."
	fi

	if [ "${#CRIT_MSGS[@]}" -gt 0 ]; then
		log ""
		log "${RED}${BOLD}Critical findings:${RESET}"
		local idx=1
		for item in "${CRIT_MSGS[@]}"; do
			log "${RED}  [$idx]${RESET} $item"
			idx=$((idx+1))
		done
	fi

	if [ "${#WARN_MSGS[@]}" -gt 0 ]; then
		log ""
		log "${YELLOW}${BOLD}Warnings:${RESET}"
		local idx=1
		for item in "${WARN_MSGS[@]}"; do
			log "${YELLOW}  [$idx]${RESET} $item"
			idx=$((idx+1))
		done
	fi

	if [ "${#CVE_HINTS[@]}" -gt 0 ]; then
		log ""
		log "${BOLD}CVE references to review (indicative):${RESET}"
		local idx=1
		for item in "${CVE_HINTS[@]}"; do
			log "  [$idx] $item"
			idx=$((idx+1))
		done
	fi

	if [ "$JSON_OUTPUT" -eq 1 ]; then
		local crit_json warn_json ok_json hint_json
		crit_json=$(json_array_from CRIT_MSGS)
		warn_json=$(json_array_from WARN_MSGS)
		ok_json=$(json_array_from OK_MSGS)
		hint_json=$(json_array_from CVE_HINTS)
		printf '{'"\n"
		printf '  "host": "%s",\n' "$(json_escape "$HOSTNAME")"
		printf '  "timestamp": "%s",\n' "$(json_escape "$RUN_TS")"
		printf '  "user": "%s",\n' "$(json_escape "$CURRENT_USER")"
		printf '  "is_root": %s,\n' "$IS_ROOT"
		printf '  "crit_count": %s,\n' "$CRIT_COUNT"
		printf '  "warn_count": %s,\n' "$WARN_COUNT"
		printf '  "crit": [%s],\n' "$crit_json"
		printf '  "warn": [%s],\n' "$warn_json"
		printf '  "ok": [%s],\n' "$ok_json"
		printf '  "cve_hints": [%s]\n' "$hint_json"
		printf '}'"\n"
	fi

	if [ -n "$OUTPUT_FILE" ]; then
		log ""
		log "Writing full report to: $OUTPUT_FILE"
		log_to_file_if_needed
	fi
}

main "$@"
