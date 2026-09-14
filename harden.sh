#!/usr/bin/env bash
# =============================================================================
#  harden.sh — Universal Server Security Hardening Script
#  OS Support : Ubuntu ≥ 20.04 | Debian ≥ 10 | FreeBSD ≥ 13
#  Usage      : sudo bash harden.sh
#  GitHub     : https://github.com/YOUR/server-harden
#  Version    : 1.0.0
# =============================================================================
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Constants & defaults  (override with env vars for non-interactive use)
# ─────────────────────────────────────────────────────────────────────────────
VERSION="1.0.0"
LOG="/var/log/server-harden.log"

D_SSH_PORT="${HARDEN_SSH_PORT:-22}"
D_USER="${HARDEN_USER:-admin}"
D_TZ="${HARDEN_TZ:-UTC}"
D_PORTS="${HARDEN_PORTS:-80,443}"
D_KNOCK="${HARDEN_KNOCK:-7000 8000 9000}"

# ─────────────────────────────────────────────────────────────────────────────
# Colors
# ─────────────────────────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m' NC='\033[0m'

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
log()  { printf '%s  %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
info() { echo -e "${G}[✓]${NC} $*"; log "INFO  $*"; }
warn() { echo -e "${Y}[!]${NC} $*"; log "WARN  $*"; }
err()  { echo -e "${R}[✗]${NC} $*" >&2; log "ERR   $*"; }
die()  { err "$*"; exit 1; }
hdr()  { printf '\n%b━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n  %s\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n\n' "$C" "$*" "$NC"; }

# ─────────────────────────────────────────────────────────────────────────────
# Root check
# ─────────────────────────────────────────────────────────────────────────────
check_root() {
    [[ "$(id -u)" -eq 0 ]] || die "Run as root:  sudo bash $0"
}

# ─────────────────────────────────────────────────────────────────────────────
# OS Detection
# ─────────────────────────────────────────────────────────────────────────────
detect_os() {
    OS_FAMILY="" OS_ID="" OS_VER="" IS_PVE=false

    if [[ "$(uname -s)" == "FreeBSD" ]]; then
        OS_FAMILY="freebsd"
        OS_ID="freebsd"
        OS_VER="$(uname -r | cut -d. -f1)"
    elif [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        OS_ID="${ID,,}"
        OS_VER="${VERSION_ID:-0}"
        case "$OS_ID" in
            ubuntu|debian|raspbian) OS_FAMILY="debian" ;;
            *) die "Unsupported distro: $OS_ID" ;;
        esac
        command -v pveversion &>/dev/null && IS_PVE=true
        [[ -d /etc/pve ]]                && IS_PVE=true
    else
        die "Cannot detect OS"
    fi

    info "Detected: $OS_ID $OS_VER | Proxmox VE: $IS_PVE"
}

# ─────────────────────────────────────────────────────────────────────────────
# Package manager abstraction
# ─────────────────────────────────────────────────────────────────────────────
pkg_update() {
    case "$OS_FAMILY" in
        debian)  DEBIAN_FRONTEND=noninteractive apt-get update -qq >> "$LOG" 2>&1 ;;
        freebsd) pkg update -q  >> "$LOG" 2>&1 ;;
    esac
}

pkg_install() {
    case "$OS_FAMILY" in
        debian)  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >> "$LOG" 2>&1 ;;
        freebsd) pkg install -y "$@" >> "$LOG" 2>&1 ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# sshd_config helper  —  portable sed (GNU + BSD)
# ─────────────────────────────────────────────────────────────────────────────
sshd_set() {
    local key="$1" val="$2" cfg="${3:-/etc/ssh/sshd_config}"
    if grep -qE "^#?[[:space:]]*${key}[[:space:]]" "$cfg"; then
        perl -i -pe "s|^#?[[:space:]]*${key}[[:space:]].*|${key} ${val}|" "$cfg"
    else
        printf '%s %s\n' "$key" "$val" >> "$cfg"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Whiptail wrappers
# ─────────────────────────────────────────────────────────────────────────────
BT="Server Hardening v${VERSION}"
TF=$(mktemp)
trap 'rm -f "$TF"' EXIT

wh_in()  { whiptail --backtitle "$BT" --title "$1" --inputbox    "$2" 10 68 "$3" 2>"$TF"; cat "$TF"; }
wh_pw()  { whiptail --backtitle "$BT" --title "$1" --passwordbox "$2" 10 68       2>"$TF"; cat "$TF"; }
wh_yn()  { whiptail --backtitle "$BT" --title "$1" --yesno       "$2" 12 68; }   # 0=yes 1=no
wh_msg() { whiptail --backtitle "$BT" --title "$1" --msgbox      "$2" 20 72; }
wh_chk() {   # wh_chk "title" "text" tag "desc" ON|OFF ...
    local t="$1" txt="$2"; shift 2
    whiptail --backtitle "$BT" --title "$t" --checklist "$txt" 22 72 12 "$@" 2>"$TF"
    tr -d '"' < "$TF"
}

# ─────────────────────────────────────────────────────────────────────────────
# Gather settings interactively
# ─────────────────────────────────────────────────────────────────────────────
gather() {
    hdr "Interactive Setup"

    # ── Hostname ──────────────────────────────────────────────────────────────
    CFG_HOST=$(wh_in "Hostname" "Server hostname:" "$(hostname -s 2>/dev/null || echo server)")
    [[ -z "$CFG_HOST" ]] && CFG_HOST="$(hostname)"

    # ── Timezone ──────────────────────────────────────────────────────────────
    CFG_TZ=$(wh_in "Timezone" "Timezone (e.g. UTC  Europe/Moscow  Asia/Novosibirsk):" "$D_TZ")
    [[ -z "$CFG_TZ" ]] && CFG_TZ="$D_TZ"

    # ── Admin user ────────────────────────────────────────────────────────────
    CFG_MK_USER=false; CFG_USER=""; CFG_USER_PW=""
    if wh_yn "Admin User" "Create a non-root admin user (with sudo/wheel)?"; then
        CFG_MK_USER=true
        CFG_USER=$(wh_in "Admin User" "Username:" "$D_USER")
        [[ -z "$CFG_USER" ]] && CFG_USER="$D_USER"
        CFG_USER_PW=$(wh_pw "Admin User" "Password for ${CFG_USER}:")
    fi

    # ── SSH ───────────────────────────────────────────────────────────────────
    CFG_SSH_PORT=$(wh_in "SSH" "SSH listen port (default 22 or custom e.g. 2222):" "$D_SSH_PORT")
    [[ -z "$CFG_SSH_PORT" ]] && CFG_SSH_PORT="$D_SSH_PORT"

    local ssh_opts
    ssh_opts=$(wh_chk "SSH Hardening" "Toggle with SPACE, confirm with ENTER:" \
        disable_root  "Disable root login"                     ON  \
        key_only      "Key-only auth (disable password)"       OFF \
        no_x11        "Disable X11 forwarding"                 ON  \
        limit_auth    "MaxAuthTries 3 / LoginGraceTime 30s"    ON  \
        idle_out      "Auto-disconnect idle sessions (10 min)" ON  \
    ) || ssh_opts=""

    CFG_SSH_NO_ROOT=false; [[ "$ssh_opts" == *disable_root* ]] && CFG_SSH_NO_ROOT=true
    CFG_SSH_KEY_ONLY=false;[[ "$ssh_opts" == *key_only*     ]] && CFG_SSH_KEY_ONLY=true
    CFG_SSH_NO_X11=false;  [[ "$ssh_opts" == *no_x11*       ]] && CFG_SSH_NO_X11=true
    CFG_SSH_LIMIT=false;   [[ "$ssh_opts" == *limit_auth*   ]] && CFG_SSH_LIMIT=true
    CFG_SSH_IDLE=false;    [[ "$ssh_opts" == *idle_out*      ]] && CFG_SSH_IDLE=true

    # ── SSH public key ────────────────────────────────────────────────────────
    CFG_PUBKEY=""; CFG_ADD_KEY=false
    if $CFG_SSH_KEY_ONLY || wh_yn "SSH Public Key" "Add an SSH public key for authentication?"; then
        CFG_PUBKEY=$(wh_in "SSH Public Key" "Paste public key (ssh-ed25519 / ssh-rsa ...):" "")
        [[ -n "$CFG_PUBKEY" ]] && CFG_ADD_KEY=true
    fi

    # ── 2FA ───────────────────────────────────────────────────────────────────
    CFG_2FA=false
    if wh_yn "Two-Factor Auth" \
        "Enable 2FA (Google Authenticator / TOTP)?\n\nAfter setup each user must run:\n  google-authenticator -t -d -f -r 3 -R 30 -W"; then
        CFG_2FA=true
    fi

    # ── Firewall ──────────────────────────────────────────────────────────────
    CFG_FW=false; CFG_PORTS=""
    if wh_yn "Firewall" "Configure firewall (default-deny, allow specific ports)?"; then
        CFG_FW=true
        CFG_PORTS=$(wh_in "Firewall" \
            "Allowed TCP ports, comma-separated (SSH added automatically):" "$D_PORTS")
        [[ -z "$CFG_PORTS" ]] && CFG_PORTS="$D_PORTS"
    fi

    # ── Port knocking ─────────────────────────────────────────────────────────
    CFG_KNOCK=false; CFG_KNOCK_SEQ=""
    if $CFG_FW && [[ "$OS_FAMILY" == "debian" ]]; then
        if wh_yn "Port Knocking" \
            "Enable port knocking for SSH?\n(SSH stays closed until correct knock sequence\n — opens only for your IP)"; then
            CFG_KNOCK=true
            CFG_KNOCK_SEQ=$(wh_in "Port Knocking" \
                "Knock sequence — 3 ports, space-separated:" "$D_KNOCK")
            [[ -z "$CFG_KNOCK_SEQ" ]] && CFG_KNOCK_SEQ="$D_KNOCK"
        fi
    fi

    # ── fail2ban ──────────────────────────────────────────────────────────────
    CFG_F2B=false
    if [[ "$OS_FAMILY" == "debian" ]]; then
        wh_yn "fail2ban" "Install fail2ban (auto-ban SSH brute-force)?" \
            && CFG_F2B=true || true
    fi

    # ── Sysctl ────────────────────────────────────────────────────────────────
    CFG_SYSCTL=false
    wh_yn "Kernel Hardening" \
        "Apply sysctl security settings?\n(rp_filter, SYN cookies, ASLR, disable redirects...)" \
        && CFG_SYSCTL=true || true

    # ── Auto-updates ──────────────────────────────────────────────────────────
    CFG_AUTOUPD=false
    if [[ "$OS_FAMILY" == "debian" ]]; then
        wh_yn "Auto-updates" "Enable automatic security updates (unattended-upgrades)?" \
            && CFG_AUTOUPD=true || true
    fi

    # ── PVE ───────────────────────────────────────────────────────────────────
    CFG_PVE=false
    if $IS_PVE; then
        wh_yn "Proxmox VE" \
            "Apply PVE-specific settings?\n\n• Install qemu-guest-agent\n• Disable SSH by default\n• Install ssh-toggle helper script" \
            && CFG_PVE=true || true
    fi

    # ── Summary / Confirm ─────────────────────────────────────────────────────
    local s
    s="Hostname    : $CFG_HOST\n"
    s+="Timezone    : $CFG_TZ\n"
    s+="Admin user  : $CFG_MK_USER"
    $CFG_MK_USER && s+=" → $CFG_USER"
    s+="\nSSH port    : $CFG_SSH_PORT\n"
    s+="No root SSH : $CFG_SSH_NO_ROOT\n"
    s+="Key-only    : $CFG_SSH_KEY_ONLY\n"
    s+="2FA         : $CFG_2FA\n"
    s+="Firewall    : $CFG_FW"
    $CFG_FW && s+=" → $CFG_PORTS"
    s+="\nPort knock  : $CFG_KNOCK"
    $CFG_KNOCK && s+=" → $CFG_KNOCK_SEQ"
    s+="\nfail2ban    : $CFG_F2B\n"
    s+="Sysctl      : $CFG_SYSCTL\n"
    s+="Auto-updates: $CFG_AUTOUPD\n"
    $IS_PVE && s+="PVE mode    : $CFG_PVE\n"

    # shellcheck disable=SC2059
    wh_yn "✓ Confirm Settings" "$(printf "$s")\n\nApply now?" \
        || die "Aborted by user"
}

# ─────────────────────────────────────────────────────────────────────────────
# Hostname & Timezone
# ─────────────────────────────────────────────────────────────────────────────
apply_host_tz() {
    hdr "Hostname & Timezone"

    if [[ -n "$CFG_HOST" ]]; then
        if command -v hostnamectl &>/dev/null; then
            hostnamectl set-hostname "$CFG_HOST"
        else
            echo "$CFG_HOST" > /etc/hostname
            hostname "$CFG_HOST"
        fi
        if grep -q "^127\.0\.1\.1" /etc/hosts; then
            perl -i -pe "s/^127\.0\.1\.1.*/127.0.1.1\t$CFG_HOST/" /etc/hosts
        else
            printf '127.0.1.1\t%s\n' "$CFG_HOST" >> /etc/hosts
        fi
        info "Hostname → $CFG_HOST"
    fi

    case "$OS_FAMILY" in
        debian)
            if command -v timedatectl &>/dev/null; then
                timedatectl set-timezone "$CFG_TZ"
            else
                ln -sf "/usr/share/zoneinfo/$CFG_TZ" /etc/localtime
                echo "$CFG_TZ" > /etc/timezone
            fi
            ;;
        freebsd)
            cp "/usr/share/zoneinfo/$CFG_TZ" /etc/localtime
            echo "$CFG_TZ" > /etc/timezone
            ;;
    esac
    info "Timezone → $CFG_TZ"
}

# ─────────────────────────────────────────────────────────────────────────────
# Admin User
# ─────────────────────────────────────────────────────────────────────────────
apply_user() {
    $CFG_MK_USER || return 0
    hdr "Admin User"

    if id "$CFG_USER" &>/dev/null; then
        warn "User $CFG_USER already exists — skipping creation"
    else
        case "$OS_FAMILY" in
            debian)
                useradd -m -s /bin/bash "$CFG_USER"
                echo "$CFG_USER:$CFG_USER_PW" | chpasswd
                usermod -aG sudo "$CFG_USER"
                ;;
            freebsd)
                pw useradd "$CFG_USER" -m -s /bin/sh -G wheel
                printf '%s\n' "$CFG_USER_PW" | pw usermod "$CFG_USER" -h 0
                ;;
        esac
        info "User $CFG_USER created"
    fi

    if $CFG_ADD_KEY; then
        local home; home=$(eval echo "~$CFG_USER")
        mkdir -p "${home}/.ssh"
        echo "$CFG_PUBKEY" >> "${home}/.ssh/authorized_keys"
        chmod 700 "${home}/.ssh"
        chmod 600 "${home}/.ssh/authorized_keys"
        chown -R "$CFG_USER:$CFG_USER" "${home}/.ssh"
        info "SSH public key added for $CFG_USER"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SSH Hardening
# ─────────────────────────────────────────────────────────────────────────────
apply_ssh() {
    hdr "SSH Hardening"
    local cfg="/etc/ssh/sshd_config"
    cp "$cfg" "${cfg}.bak.$(date +%s)"

    sshd_set Port                         "$CFG_SSH_PORT"
    sshd_set Protocol                     "2"
    sshd_set PermitEmptyPasswords         "no"
    sshd_set PrintLastLog                 "yes"
    sshd_set UsePAM                       "yes"
    sshd_set KbdInteractiveAuthentication "yes"
    sshd_set Banner                       "/etc/issue.net"
    sshd_set MaxSessions                  "5"
    sshd_set AllowAgentForwarding         "no"
    sshd_set AllowTcpForwarding           "no"
    sshd_set Compression                  "no"

    $CFG_SSH_NO_ROOT \
        && sshd_set PermitRootLogin "no" \
        || sshd_set PermitRootLogin "prohibit-password"

    $CFG_SSH_NO_X11 \
        && sshd_set X11Forwarding "no" \
        || sshd_set X11Forwarding "yes"

    if $CFG_SSH_LIMIT; then
        sshd_set MaxAuthTries   "3"
        sshd_set LoginGraceTime "30"
    fi

    if $CFG_SSH_IDLE; then
        sshd_set ClientAliveInterval "300"
        sshd_set ClientAliveCountMax "2"
    fi

    if $CFG_SSH_KEY_ONLY; then
        sshd_set PasswordAuthentication "no"
        sshd_set AuthenticationMethods  "publickey"
    else
        sshd_set PasswordAuthentication "yes"
        sshd_set AuthenticationMethods  "keyboard-interactive"
    fi

    # Add key to root if no admin user was created
    if $CFG_ADD_KEY && ! $CFG_MK_USER; then
        mkdir -p /root/.ssh
        echo "$CFG_PUBKEY" >> /root/.ssh/authorized_keys
        chmod 700 /root/.ssh
        chmod 600 /root/.ssh/authorized_keys
        info "SSH key added for root"
    fi

    sshd -t >> "$LOG" 2>&1 || die "sshd config validation failed — see $LOG"

    case "$OS_FAMILY" in
        debian)  systemctl restart sshd ;;
        freebsd) service sshd restart >> "$LOG" 2>&1 ;;
    esac

    info "SSH hardened — port $CFG_SSH_PORT | root: $CFG_SSH_NO_ROOT | key-only: $CFG_SSH_KEY_ONLY"
}

# ─────────────────────────────────────────────────────────────────────────────
# 2FA — Google Authenticator / TOTP
# ─────────────────────────────────────────────────────────────────────────────
apply_2fa() {
    $CFG_2FA || return 0
    hdr "Two-Factor Authentication (TOTP)"

    case "$OS_FAMILY" in
        debian)  pkg_install libpam-google-authenticator ;;
        freebsd) pkg_install pam_google_authenticator ;;
    esac

    # Ensure pam_google_authenticator is NOT in common-auth (duplicates TOTP prompt)
    if [[ -f /etc/pam.d/common-auth ]]; then
        perl -ni -e 'print unless /pam_google_authenticator/' /etc/pam.d/common-auth
        info "Cleaned up pam_google_authenticator from common-auth"
    fi

    # Add to sshd PAM only
    local pam_sshd="/etc/pam.d/sshd"
    if ! grep -q "pam_google_authenticator" "$pam_sshd"; then
        echo "auth required pam_google_authenticator.so" >> "$pam_sshd"
    fi

    # sshd_config: override AuthenticationMethods to require TOTP
    sshd_set KbdInteractiveAuthentication "yes"
    sshd_set UsePAM                       "yes"

    if $CFG_SSH_KEY_ONLY; then
        sshd_set AuthenticationMethods "publickey,keyboard-interactive"
    else
        # Password disabled → TOTP only
        sshd_set PasswordAuthentication "no"
        sshd_set AuthenticationMethods  "keyboard-interactive"
    fi

    sshd -t >> "$LOG" 2>&1 || die "sshd config error after 2FA setup"

    case "$OS_FAMILY" in
        debian)  systemctl restart sshd ;;
        freebsd) service sshd restart >> "$LOG" 2>&1 ;;
    esac

    info "2FA PAM configured"
    echo ""
    echo -e "  ${Y}Each user that needs 2FA must run:${NC}"
    echo -e "  ${C}  google-authenticator -t -d -f -r 3 -R 30 -W${NC}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Firewall — Linux (iptables + knockd)
# ─────────────────────────────────────────────────────────────────────────────
apply_fw_linux() {
    hdr "Firewall — iptables"
    pkg_install iptables iptables-persistent netfilter-persistent

    IFS=',' read -ra ALLOW_PORTS <<< "$CFG_PORTS"

    # Flush everything
    iptables -F; iptables -X; iptables -Z

    # Default policy: block in, allow out
    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  ACCEPT

    # Loopback
    iptables -A INPUT -i lo -j ACCEPT

    # Established / related connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ICMP ping — rate-limited
    iptables -A INPUT -p icmp --icmp-type echo-request \
        -m limit --limit 5/min --limit-burst 10 -j ACCEPT

    # Anti-scan basics
    iptables -A INPUT -p tcp ! --syn -m state --state NEW    -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL ALL             -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL NONE            -j DROP

    # Allowed ports (80, 443, etc.)
    for p in "${ALLOW_PORTS[@]}"; do
        p="${p// /}"
        [[ -z "$p" ]] && continue
        iptables -A INPUT -p tcp --dport "$p" -j ACCEPT
        info "Allowed TCP port $p"
    done

    # SSH — with or without port knocking
    if $CFG_KNOCK; then
        read -ra KP <<< "$CFG_KNOCK_SEQ"
        local k1="${KP[0]:-7000}" k2="${KP[1]:-8000}" k3="${KP[2]:-9000}"

        pkg_install knockd

        # Keep current SSH session alive during setup
        local cur_ip=""
        cur_ip=$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')
        if [[ -n "$cur_ip" ]]; then
            iptables -A INPUT -s "$cur_ip" -p tcp --dport "$CFG_SSH_PORT" -j ACCEPT
            warn "Current session IP $cur_ip whitelisted (remove after testing: iptables -D INPUT -s $cur_ip -p tcp --dport $CFG_SSH_PORT -j ACCEPT)"
        fi

        # Block SSH for everyone else (knockd will open per-IP)
        iptables -A INPUT -p tcp --dport "$CFG_SSH_PORT" -j DROP

        # Determine primary interface for knockd
        local iface
        iface=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1 || echo "eth0")

        cat > /etc/knockd.conf << EOF
[options]
    UseSyslog
    Interface = ${iface}

[openSSH]
    sequence    = ${k1},${k2},${k3}
    seq_timeout = 5
    command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport ${CFG_SSH_PORT} -j ACCEPT
    tcpflags    = syn

[closeSSH]
    sequence    = ${k3},${k2},${k1}
    seq_timeout = 5
    command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport ${CFG_SSH_PORT} -j ACCEPT
    tcpflags    = syn
EOF

        # Enable knockd service
        if [[ -f /etc/default/knockd ]]; then
            perl -i -pe 's/START_KNOCKD=0/START_KNOCKD=1/' /etc/default/knockd
        fi

        systemctl enable knockd >> "$LOG" 2>&1
        systemctl restart knockd >> "$LOG" 2>&1

        info "Port knocking: $k1 → $k2 → $k3"
        warn "Connect:  knock HOST $k1 $k2 $k3 && ssh -p $CFG_SSH_PORT user@HOST"
        warn "Close:    knock HOST $k3 $k2 $k1"

        # Write a client-side helper snippet
        local helper="/root/ssh-knock-example.sh"
        cat > "$helper" << EOF
#!/bin/bash
# Client-side example (install knock: apt install knockd)
HOST="\${1:-YOUR_SERVER_IP}"
knock "\$HOST" $k1 $k2 $k3
sleep 1
ssh -p $CFG_SSH_PORT user@"\$HOST"
EOF
        chmod +x "$helper"
        info "Client snippet saved: $helper"
    else
        iptables -A INPUT -p tcp --dport "$CFG_SSH_PORT" -j ACCEPT
        info "SSH port $CFG_SSH_PORT open"
    fi

    # Save rules (persist across reboots)
    netfilter-persistent save >> "$LOG" 2>&1
    info "iptables rules saved (persistent)"

    # IPv6 — basic hardening
    if command -v ip6tables &>/dev/null; then
        ip6tables -P INPUT   DROP
        ip6tables -P FORWARD DROP
        ip6tables -P OUTPUT  ACCEPT
        ip6tables -A INPUT -i lo -j ACCEPT
        ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        ip6tables -A INPUT -p ipv6-icmp -j ACCEPT   # required for NDP
        netfilter-persistent save >> "$LOG" 2>&1
        info "IPv6 hardened"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Firewall — FreeBSD (pf)
# ─────────────────────────────────────────────────────────────────────────────
apply_fw_freebsd() {
    hdr "Firewall — pf"

    local iface
    iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' || echo "em0")

    # "80,443" → "{ 80 443 }"
    local pf_ports
    pf_ports="{ $(echo "$CFG_PORTS" | tr ',' ' ') }"

    local pf_conf="/etc/pf.conf"
    cp "$pf_conf" "${pf_conf}.bak.$(date +%s)" 2>/dev/null || true

    cat > "$pf_conf" << EOF
# Generated by server-harden.sh $(date)
ext_if = "$iface"

# Auto-ban table
table <bruteforce> persist

# Options
set block-policy drop
set skip on lo0
scrub in all

# Default deny
block in  all
pass  out all keep state

# ICMP
pass in inet  proto icmp  icmp-type  echoreq keep state
pass in inet6 proto icmp6            all     keep state

# Block known bad actors
block in quick from <bruteforce>

# SSH — rate-limit (auto-adds offenders to bruteforce table)
pass in on \$ext_if proto tcp to port $CFG_SSH_PORT \\
    flags S/SA keep state \\
    (max-src-conn 5, max-src-conn-rate 3/30, overload <bruteforce> flush global)

# Allowed ports
pass in on \$ext_if proto tcp to port $pf_ports keep state
EOF

    # Enable pf on boot
    sysrc pf_enable=YES    >> "$LOG" 2>&1
    sysrc pflog_enable=YES >> "$LOG" 2>&1

    # Load rules
    if pfctl -nf "$pf_conf" >> "$LOG" 2>&1; then
        pfctl -f "$pf_conf"  >> "$LOG" 2>&1 || true
        pfctl -e             >> "$LOG" 2>&1 || true
        info "pf enabled and configured"
    else
        warn "pf config has errors — check $LOG and $pf_conf"
    fi

    # Hourly cron: expire bruteforce table entries (>1h old)
    echo "0 * * * * root /sbin/pfctl -t bruteforce -T expire 3600" \
        > /etc/cron.d/pf-expire
    info "Bruteforce table expires hourly via cron"
}

apply_firewall() {
    $CFG_FW || return 0
    case "$OS_FAMILY" in
        debian)  apply_fw_linux   ;;
        freebsd) apply_fw_freebsd ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# fail2ban
# ─────────────────────────────────────────────────────────────────────────────
apply_fail2ban() {
    $CFG_F2B || return 0
    hdr "fail2ban"
    pkg_install fail2ban

    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = $CFG_SSH_PORT
maxretry = 3
bantime  = 86400
EOF

    # Extra jail for wrong TOTP code if 2FA is enabled
    if $CFG_2FA; then
        cat >> /etc/fail2ban/jail.local << 'EOF'

[google-authenticator]
enabled  = true
filter   = google-authenticator
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 86400
EOF
        cat > /etc/fail2ban/filter.d/google-authenticator.conf << 'EOF'
[Definition]
failregex = pam_google_authenticator.*user=.+ host=<HOST>
ignoreregex =
EOF
    fi

    systemctl enable fail2ban >> "$LOG" 2>&1
    systemctl restart fail2ban >> "$LOG" 2>&1
    info "fail2ban: SSH ban after 3 attempts → 24h"
}

# ─────────────────────────────────────────────────────────────────────────────
# Kernel hardening (sysctl)
# ─────────────────────────────────────────────────────────────────────────────
apply_sysctl() {
    $CFG_SYSCTL || return 0
    hdr "Kernel Hardening (sysctl)"

    case "$OS_FAMILY" in
        debian)
            cat > /etc/sysctl.d/99-harden.conf << 'EOF'
# ── Network ──────────────────────────────────────────────────────────────────
# Spoofing protection
net.ipv4.conf.all.rp_filter                 = 1
net.ipv4.conf.default.rp_filter             = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects          = 0
net.ipv4.conf.default.accept_redirects      = 0
net.ipv4.conf.all.send_redirects            = 0
net.ipv6.conf.all.accept_redirects          = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route       = 0
net.ipv4.conf.default.accept_source_route   = 0

# SYN flood protection
net.ipv4.tcp_syncookies                     = 1
net.ipv4.tcp_max_syn_backlog                = 4096

# Log packets with impossible addresses
net.ipv4.conf.all.log_martians              = 1

# Ignore broadcast pings + bogus errors
net.ipv4.icmp_echo_ignore_broadcasts        = 1
net.ipv4.icmp_ignore_bogus_error_responses  = 1

# RFC1337 TIME_WAIT fix
net.ipv4.tcp_rfc1337                        = 1

# Disable IPv6 Router Advertisements
net.ipv6.conf.all.accept_ra                 = 0
net.ipv6.conf.default.accept_ra             = 0

# ── Kernel ────────────────────────────────────────────────────────────────────
# Full ASLR
kernel.randomize_va_space                   = 2

# Disable SysRq
kernel.sysrq                                = 0

# Restrict dmesg to root
kernel.dmesg_restrict                       = 1

# Restrict ptrace
kernel.yama.ptrace_scope                    = 1

# Disable core dumps for SUID binaries
fs.suid_dumpable                            = 0

# ── Limits ───────────────────────────────────────────────────────────────────
net.core.somaxconn                          = 65535
EOF
            sysctl -p /etc/sysctl.d/99-harden.conf >> "$LOG" 2>&1
            info "sysctl settings applied"
            ;;

        freebsd)
            cat >> /etc/sysctl.conf << 'EOF'

# server-harden.sh
net.inet.ip.redirect=0
net.inet.icmp.drop_redirect=1
net.inet.tcp.drop_synfin=1
net.inet.ip.sourceroute=0
net.inet.ip.accept_sourceroute=0
kern.randompid=1
security.bsd.see_other_uids=0
security.bsd.see_other_gids=0
security.bsd.unprivileged_read_msgbuf=0
EOF
            sysctl -f /etc/sysctl.conf >> "$LOG" 2>&1 || true
            info "sysctl settings applied (FreeBSD)"
            ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# Automatic security updates (Debian/Ubuntu)
# ─────────────────────────────────────────────────────────────────────────────
apply_autoupdates() {
    $CFG_AUTOUPD || return 0
    hdr "Automatic Security Updates"
    pkg_install unattended-upgrades apt-listchanges

    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    systemctl enable unattended-upgrades >> "$LOG" 2>&1
    systemctl restart unattended-upgrades >> "$LOG" 2>&1
    info "Automatic security updates enabled"
}

# ─────────────────────────────────────────────────────────────────────────────
# Proxmox VE
# ─────────────────────────────────────────────────────────────────────────────
apply_pve() {
    $CFG_PVE || return 0
    hdr "Proxmox VE Hardening"

    pkg_install qemu-guest-agent
    systemctl enable qemu-guest-agent >> "$LOG" 2>&1
    systemctl start  qemu-guest-agent >> "$LOG" 2>&1
    info "qemu-guest-agent installed and started"

    # Disable SSH by default on PVE nodes
    local ssh_svc
    ssh_svc=$(systemctl list-unit-files 2>/dev/null \
        | awk '/^ssh(d)?\.service/{print $1; exit}' || echo "sshd.service")

    systemctl disable "$ssh_svc" >> "$LOG" 2>&1 || true
    systemctl stop    "$ssh_svc" >> "$LOG" 2>&1 || true
    info "SSH disabled by default"

    # ssh-toggle — quick helper to turn SSH on/off
    cat > /usr/local/bin/ssh-toggle << 'SCRIPT'
#!/bin/bash
# ssh-toggle — quickly enable/disable SSH on PVE nodes
# Usage: ssh-toggle [on|off|persist|status]
SSH_SVC=$(systemctl list-unit-files 2>/dev/null \
    | awk '/^ssh(d)?\.service/{print $1; exit}')

case "${1:-status}" in
    on)
        systemctl start "$SSH_SVC"
        echo "SSH started (temporary, not persisted)"
        ;;
    off)
        systemctl stop "$SSH_SVC"
        echo "SSH stopped"
        ;;
    persist)
        systemctl enable "$SSH_SVC"
        systemctl start  "$SSH_SVC"
        echo "SSH enabled permanently"
        ;;
    status|*)
        if systemctl is-active --quiet "$SSH_SVC"; then
            echo "SSH is running"
        else
            echo "SSH is stopped"
        fi
        ;;
esac
SCRIPT
    chmod +x /usr/local/bin/ssh-toggle
    info "ssh-toggle installed:  ssh-toggle [on|off|persist|status]"
}

# ─────────────────────────────────────────────────────────────────────────────
# Miscellaneous hardening
# ─────────────────────────────────────────────────────────────────────────────
apply_misc() {
    hdr "Miscellaneous Hardening"

    # Login banner
    cat > /etc/issue.net << 'EOF'
***************************************************************************
              AUTHORIZED ACCESS ONLY — ALL SESSIONS ARE MONITORED
***************************************************************************
EOF
    info "Login banner set"

    # Idle session timeout — 10 minutes for all users
    printf 'TMOUT=600; readonly TMOUT; export TMOUT\n' \
        > /etc/profile.d/99-timeout.sh
    chmod 644 /etc/profile.d/99-timeout.sh
    info "Idle session timeout: 10 minutes"

    if [[ "$OS_FAMILY" == "debian" ]]; then
        # Disable core dumps
        cat >> /etc/security/limits.conf << 'EOF'

# server-harden.sh: disable core dumps
*    soft core 0
*    hard core 0
root soft core 0
root hard core 0
EOF

        # Disable USB storage kernel module
        echo "install usb-storage /bin/true" \
            > /etc/modprobe.d/disable-usb-storage.conf
        info "USB storage module disabled"

        # Secure shared memory
        if ! grep -qE "tmpfs.*/dev/shm" /etc/fstab 2>/dev/null; then
            echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec 0 0" \
                >> /etc/fstab
            mount -o remount /dev/shm 2>/dev/null || true
            info "Shared memory secured (nosuid,nodev,noexec)"
        fi
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Final report
# ─────────────────────────────────────────────────────────────────────────────
final_report() {
    echo ""
    echo -e "${G}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${G}║   ✓  Hardening complete!                     ║${NC}"
    echo -e "${G}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${C}Log:${NC}       $LOG"
    echo -e "  ${C}SSH port:${NC}  $CFG_SSH_PORT"
    if $CFG_KNOCK; then
        echo ""
        echo -e "  ${C}Port knocking sequence:${NC}"
        echo -e "    knock HOST $CFG_KNOCK_SEQ"
        echo -e "    ssh -p $CFG_SSH_PORT user@HOST"
        echo -e "  ${C}Client example:${NC} /root/ssh-knock-example.sh"
    fi
    if $CFG_2FA; then
        echo ""
        echo -e "  ${Y}⚠ 2FA:${NC}     Each user must run: google-authenticator -t -d -f -r 3 -R 30 -W"
    fi
    if $CFG_PVE; then
        echo ""
        echo -e "  ${Y}⚠ SSH off:${NC}  Enable with:  ssh-toggle on"
        echo -e "             Permanently: ssh-toggle persist"
    fi
    echo ""
    echo -e "  ${R}⚠  Do NOT close this session!${NC}"
    echo -e "  ${R}   Open a new window and verify login before proceeding.${NC}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
main() {
    : > "$LOG"    # init / clear log
    check_root
    detect_os

    printf '\n%b' "$C"
    echo "  ┌──────────────────────────────────────────────┐"
    printf '  │  Server Hardening Script  v%-18s│\n' "${VERSION}"
    printf '  │  OS: %-12s  PVE: %-17s│\n' "${OS_ID:-?} ${OS_VER:-}" "${IS_PVE}"
    echo "  └──────────────────────────────────────────────┘"
    printf '%b\n\n' "$NC"

    pkg_update
    pkg_install whiptail

    gather

    apply_host_tz
    apply_user
    apply_ssh
    apply_2fa
    apply_firewall
    apply_fail2ban
    apply_sysctl
    apply_autoupdates
    apply_pve
    apply_misc

    final_report
}

main "$@"
