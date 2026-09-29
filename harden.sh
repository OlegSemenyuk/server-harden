#!/usr/bin/env bash
# =============================================================================
#  harden.sh — Universal Server Security Hardening Script
#  OS Support : Ubuntu ≥ 20.04 | Debian ≥ 10 | FreeBSD ≥ 13
#  Usage      : sudo bash harden.sh
#  GitHub     : https://github.com/YOUR/server-harden
#  Version    : 1.0.0
# =============================================================================
set -euo pipefail

# ── Constants & defaults (override via env vars for non-interactive use) ──────
HARDEN_VER="1.0.0"
LOG="/var/log/server-harden.log"

D_SSH_PORT="${HARDEN_SSH_PORT:-22}"
D_USER="${HARDEN_USER:-admin}"
D_TZ="${HARDEN_TZ:-UTC}"
D_PORTS="${HARDEN_PORTS:-80,443}"
D_KNOCK="${HARDEN_KNOCK:-7000 8000 9000}"

# ── Colors ────────────────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m' NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { printf '%s  %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
info() { echo -e "${G}[✓]${NC} $*"; log "INFO  $*"; }
warn() { echo -e "${Y}[!]${NC} $*"; log "WARN  $*"; }
err()  { echo -e "${R}[✗]${NC} $*" >&2; log "ERR   $*"; }
die()  { err "$*"; exit 1; }
hdr()  { printf '\n%b━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n  %s\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n\n' "$C" "$*" "$NC"; }
trim() { printf '%s' "$1" | tr -d '\n\r' | xargs; }

# ── Root check ────────────────────────────────────────────────────────────────
check_root() {
    [[ "$(id -u)" -eq 0 ]] || die "Run as root:  sudo bash $0"
}

# ── OS Detection ──────────────────────────────────────────────────────────────
detect_os() {
    OS_FAMILY="" OS_ID="" OS_VER="" IS_PVE=false IS_VM=false VIRT_TYPE="none"

    if [[ "$(uname -s)" == "FreeBSD" ]]; then
        OS_FAMILY="freebsd"; OS_ID="freebsd"
        OS_VER="$(uname -r | cut -d. -f1)"
        VIRT_TYPE=$(sysctl -n kern.vm_guest 2>/dev/null || echo "none")
        [[ "$VIRT_TYPE" != "none" ]] && IS_VM=true
    elif [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        OS_ID="${ID,,}"; OS_VER="${VERSION_ID:-0}"
        case "$OS_ID" in
            ubuntu|debian|raspbian) OS_FAMILY="debian" ;;
            *) die "Unsupported distro: $OS_ID" ;;
        esac
        # PVE HOST (сам гипервизор)
        command -v pveversion &>/dev/null && IS_PVE=true
        [[ -d /etc/pve ]]                && IS_PVE=true
        # VM guest detection
        if command -v systemd-detect-virt &>/dev/null; then
            VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
            [[ "$VIRT_TYPE" != "none" ]] && IS_VM=true
        fi
    else
        die "Cannot detect OS"
    fi

    local vm_info=""
    $IS_VM  && vm_info=" | VM: $VIRT_TYPE"
    $IS_PVE && vm_info+=" | PVE host"
    info "Detected: $OS_ID $OS_VER${vm_info}"
}

# ── Package manager ───────────────────────────────────────────────────────────
pkg_update() {
    case "$OS_FAMILY" in
        debian)  DEBIAN_FRONTEND=noninteractive apt-get update -qq >> "$LOG" 2>&1 ;;
        freebsd) pkg update -q >> "$LOG" 2>&1 ;;
    esac
}
pkg_install() {
    case "$OS_FAMILY" in
        debian)  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >> "$LOG" 2>&1 ;;
        freebsd) pkg install -y "$@" >> "$LOG" 2>&1 ;;
    esac
}
# Установить только отсутствующие пакеты (не обновлять если уже стоят)
pkg_ensure() {
    local missing=()
    for p in "$@"; do
        case "$OS_FAMILY" in
            debian)  dpkg -l "$p" 2>/dev/null | grep -q "^ii" || missing+=("$p") ;;
            freebsd) pkg info -e "$p" 2>/dev/null || missing+=("$p") ;;
        esac
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        info "Устанавливаю: ${missing[*]}"
        pkg_update
        pkg_install "${missing[@]}"
    fi
}

# ── sshd_config helper ────────────────────────────────────────────────────────
sshd_set() {
    local key="$1" val="$2" cfg="${3:-/etc/ssh/sshd_config}"
    if grep -qE "^#?[[:space:]]*${key}[[:space:]]" "$cfg"; then
        perl -i -pe "s|^#?[[:space:]]*${key}[[:space:]].*|${key} ${val}|" "$cfg"
    else
        printf '%s %s\n' "$key" "$val" >> "$cfg"
    fi
}

# ── Dialog / Whiptail wrappers ────────────────────────────────────────────────
# FreeBSD: dialog (base system) | Linux: whiptail
# Своп 3>&1 1>&2 2>&3: UI рисуется на терминал, результат в stdout
BT="Server Hardening v${HARDEN_VER}"
DIALOG_CMD=""

setup_dialog() {
    if   command -v whiptail &>/dev/null; then DIALOG_CMD="whiptail"
    elif command -v dialog   &>/dev/null; then DIALOG_CMD="dialog"
    else
        case "$OS_FAMILY" in
            debian)  pkg_install whiptail && DIALOG_CMD="whiptail" ;;
            freebsd) die "dialog не найден — должен быть в base system" ;;
        esac
    fi
    info "Dialog: $DIALOG_CMD"
}

wh_in()  { $DIALOG_CMD --backtitle "$BT" --title "$1" --inputbox    "$2" 10 68 "$3" 3>&1 1>&2 2>&3; }
wh_pw()  { $DIALOG_CMD --backtitle "$BT" --title "$1" --passwordbox "$2" 10 68       3>&1 1>&2 2>&3; }
wh_yn()  { $DIALOG_CMD --backtitle "$BT" --title "$1" --yesno       "$2" 12 68; }
wh_msg() { $DIALOG_CMD --backtitle "$BT" --title "$1" --msgbox      "$2" 20 72; }
wh_menu(){ local t="$1" txt="$2"; shift 2
    $DIALOG_CMD --backtitle "$BT" --title "$t" \
        --menu "$txt" 14 65 6 "$@" 3>&1 1>&2 2>&3; }
wh_chk() { local t="$1" txt="$2"; shift 2
    $DIALOG_CMD --backtitle "$BT" --title "$t" \
        --checklist "$txt" 22 72 12 "$@" 3>&1 1>&2 2>&3 | tr -d '"'; }


# ── Gather settings ───────────────────────────────────────────────────────────
gather() {
    hdr "Interactive Setup"

    # Hostname — спрашиваем только если выглядит как дефолтный
    local cur_host; cur_host=$(hostname -s 2>/dev/null || echo "localhost")
    if [[ "$cur_host" =~ ^(localhost|debian|ubuntu|raspberrypi|server|vps)$ ]]; then
        CFG_HOST=$(wh_in "Hostname" \
            "Hostname выглядит дефолтным. Введи нормальный:" "$cur_host")
        CFG_HOST=$(trim "$CFG_HOST")
        [[ -z "$CFG_HOST" ]] && CFG_HOST="$cur_host"
    else
        CFG_HOST="$cur_host"
        info "Hostname: $CFG_HOST (уже задан, пропускаем)"
    fi

    # Timezone — определяем автоматически, не спрашиваем
    CFG_TZ=$(timedatectl show --property=Timezone --value 2>/dev/null \
          || cat /etc/timezone 2>/dev/null \
          || readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||' \
          || echo "UTC")
    CFG_TZ=$(trim "$CFG_TZ")
    [[ -z "$CFG_TZ" ]] && CFG_TZ="UTC"
    info "Timezone: $CFG_TZ (определена автоматически)"

    # Admin user
    CFG_MK_USER=false; CFG_USER=""; CFG_USER_PW=""; CFG_PW_GENERATED=false; CFG_USER_SUDO=false
    if wh_yn "Новый пользователь" "Создать нового пользователя в системе?"; then
        CFG_MK_USER=true
        CFG_USER=$(wh_in "Новый пользователь" "Username:" "$D_USER")
        CFG_USER=$(trim "$CFG_USER")
        [[ -z "$CFG_USER" ]] && CFG_USER="$D_USER"

        if id "$CFG_USER" &>/dev/null; then
            wh_msg "Новый пользователь" "Пользователь '$CFG_USER' уже существует.\n\nПароль менять не будем.\nMожно настроить sudo и ключи ниже."
        else
            CFG_USER_PW=$(wh_pw "Новый пользователь" "Пароль для ${CFG_USER}:\n(пустой = сгенерировать случайный)")
            if [[ -z "$CFG_USER_PW" ]]; then
                CFG_USER_PW=$(openssl rand -base64 16 | tr -d '/+=\n' | head -c 16)
                CFG_PW_GENERATED=true
            else
                CFG_PW_GENERATED=false
            fi
        fi

        wh_yn "Sudo права" "Добавить '$CFG_USER' в группу sudo/wheel?" \
            && CFG_USER_SUDO=true || true
    fi

    # Существующие юзеры — sudo и ключи (Вариант B)
    CFG_EXTRA_USERS=(); CFG_EXTRA_SUDO=()
    if wh_yn "Существующие пользователи" \
        "Настроить права/ключи для уже существующих пользователей?\n(sudo, SSH ключи)"; then

        # Собираем список: UID>=1000, есть /home, не nologin
        local user_list=()
        while IFS=: read -r uname _ uid _ _ uhome ushell; do
            [[ $uid -ge 1000 && $uid -lt 65534 ]] || continue
            [[ "$ushell" =~ (nologin|false) ]] && continue
            [[ -d "$uhome" ]] || continue
            [[ "$uname" == "${CFG_USER:-}" ]] && continue  # уже обработан выше
            user_list+=("$uname" "$uname (${uhome})" "OFF")
        done < /etc/passwd

        if [[ ${#user_list[@]} -eq 0 ]]; then
            wh_msg "Существующие пользователи" "Подходящих пользователей не найдено."
        else
            local selected
            selected=$(wh_chk "Существующие пользователи" \
                "Выбери пользователей для настройки (SPACE = выбрать):" \
                "${user_list[@]}") || selected=""

            for uname in $selected; do
                [[ -z "$uname" ]] && continue
                CFG_EXTRA_USERS+=("$uname")
                if wh_yn "Sudo — $uname" "Добавить '$uname' в sudo/wheel?"; then
                    CFG_EXTRA_SUDO+=("true")
                else
                    CFG_EXTRA_SUDO+=("false")
                fi
            done
        fi
    fi

    # SSH port
    CFG_SSH_PORT=$(wh_in "SSH" "SSH listen port (default 22 or custom e.g. 2222):" "$D_SSH_PORT")
    CFG_SSH_PORT=$(trim "$CFG_SSH_PORT")
    [[ -z "$CFG_SSH_PORT" ]] && CFG_SSH_PORT="$D_SSH_PORT"

    # SSH options
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

    # SSH pubkey — несколько ключей (3 компа = 3 разных ключа)
    CFG_PUBKEYS=(); CFG_ADD_KEY=false
    if $CFG_SSH_KEY_ONLY || wh_yn "SSH Public Key" \
        "Добавить SSH публичный ключ(и) для входа?\n\nКаждый компьютер — СВОЙ ключ.\nКак получить ключ на каждой машине:\n  cat ~/.ssh/id_ed25519.pub\n\nПриватный ключ никуда не вводи!"; then
        local keynum=1
        while true; do
            local key valid_key=false
            while ! $valid_key; do
                key=$(wh_in "SSH Public Key — компьютер $keynum" \
                    "Полный ключ из: cat ~/.ssh/id_ed25519.pub\n\nФормат: ssh-ed25519 AAAA....(длинная строка).... user@pc\n\n(пустая строка = закончить):" "")
                key=$(trim "$key")
                [[ -z "$key" ]] && break 2
                # Валидация формата ключа
                if [[ "$key" =~ ^(ssh-ed25519|ssh-rsa|ssh-ecdsa|ecdsa-sha2-nistp256)[[:space:]][A-Za-z0-9+/]{20,}([[:space:]].*)?$ ]]; then
                    valid_key=true
                else
                    wh_msg "Ошибка ключа" "Ключ выглядит неправильно!\n\nОжидается:\nssh-ed25519 AAAAC3Nz....(длинная строка)\n\nПолучи его на своей машине:\n  cat ~/.ssh/id_ed25519.pub\n\nПопробуй ещё раз."
                fi
            done
            $valid_key || break
            CFG_PUBKEYS+=("$key")
            keynum=$(( keynum + 1 ))
            wh_yn "SSH Keys" "Добавлено ключей: $((keynum-1))\nДобавить ещё (другой компьютер)?" || break
        done
        [[ ${#CFG_PUBKEYS[@]} -gt 0 ]] && CFG_ADD_KEY=true
    fi


    # 2FA
    CFG_2FA=false; CFG_2FA_USERS=()
    if wh_yn "Two-Factor Auth" \
        "Включить 2FA (Google Authenticator / TOTP)?\n\nСкрипт сам запустит настройку для выбранных пользователей — покажет QR-код для сканирования."; then
        CFG_2FA=true

        # Собираем список существующих пользователей с /home
        local existing_users=()
        while IFS= read -r u; do
            existing_users+=("$u" "$u" "OFF")
        done < <(awk -F: '$3>=1000 && $3<65534 && $7 !~ /nologin|false/ {print $1}' /etc/passwd)

        # root отдельно
        local fa_opts
        fa_opts=$(wh_chk "2FA — выбери пользователей" \
            "Для каких пользователей настроить 2FA?" \
            "root" "root" "OFF" \
            "${existing_users[@]+"${existing_users[@]}"}" \
        ) || fa_opts=""

        # Добавим создаваемого юзера если он ещё не существует
        IFS=' ' read -ra CFG_2FA_USERS <<< "$fa_opts"
    fi

    # Firewall — на Linux всегда включён (iptables + ipset)
    # Спрашиваем только какие порты открыть публично
    CFG_FW=true; CFG_PORTS=""
    if [[ "$OS_FAMILY" == "debian" ]]; then
        CFG_PORTS=$(wh_in "Firewall — открытые порты" \
            "iptables + ipset будут настроены в любом случае.\nКакие TCP порты открыть публично (кроме SSH)?\n\nПример: 80,443\nОставь пустым — не открывать дополнительных портов." "$D_PORTS")
        CFG_PORTS=$(trim "$CFG_PORTS")
    elif wh_yn "Firewall (FreeBSD)" "Настроить firewall (ipfw/pf)?"; then
        CFG_FW=true
        CFG_PORTS=$(wh_in "Firewall" \
            "Allowed TCP ports, comma-separated (SSH added automatically):" "$D_PORTS")
        CFG_PORTS=$(trim "$CFG_PORTS")
        [[ -z "$CFG_PORTS" ]] && CFG_PORTS="$D_PORTS"
    else
        CFG_FW=false
    fi

    # FreeBSD: выбор firewall
    CFG_FW_TYPE="ipfw"
    if $CFG_FW && [[ "$OS_FAMILY" == "freebsd" ]]; then
        CFG_FW_TYPE=$(wh_menu "FreeBSD Firewall" "Выбери firewall:" \
            "ipfw" "ipfw — классический, rule-based (рекомендуется)" \
            "pf"   "pf  — современный, stateful") || CFG_FW_TYPE="ipfw"
        CFG_FW_TYPE=$(trim "$CFG_FW_TYPE")
    fi

    # Port knocking (только Linux)
    CFG_KNOCK=false; CFG_KNOCK_SEQ=""
    if $CFG_FW && [[ "$OS_FAMILY" == "debian" ]]; then
        if wh_yn "Port Knocking" \
            "Enable port knocking for SSH?\n(SSH stays closed until correct knock sequence\n — opens only for your IP)"; then
            CFG_KNOCK=true
            CFG_KNOCK_SEQ=$(wh_in "Port Knocking" \
                "Knock sequence — 3 ports, space-separated:" "$D_KNOCK")
            CFG_KNOCK_SEQ=$(trim "$CFG_KNOCK_SEQ")
            [[ -z "$CFG_KNOCK_SEQ" ]] && CFG_KNOCK_SEQ="$D_KNOCK"
        fi
    fi

    # fail2ban
    CFG_F2B=false
    if [[ "$OS_FAMILY" == "debian" ]]; then
        wh_yn "fail2ban" "Install fail2ban (auto-ban SSH brute-force)?" \
            && CFG_F2B=true || true
    fi

    # Sysctl
    CFG_SYSCTL=false
    wh_yn "Kernel Hardening" \
        "Apply sysctl security settings?\n(rp_filter, SYN cookies, ASLR, disable redirects...)" \
        && CFG_SYSCTL=true || true

    # Auto-updates
    CFG_AUTOUPD=false
    if [[ "$OS_FAMILY" == "debian" ]]; then
        wh_yn "Auto-updates" "Enable automatic security updates (unattended-upgrades)?" \
            && CFG_AUTOUPD=true || true
    fi

    # PVE / VM guest
    CFG_PVE=false
    if $IS_PVE || $IS_VM; then
        local pve_msg=""
        if $IS_PVE; then
            pve_msg="Обнаружен Proxmox VE хост.\n\n• Install qemu-guest-agent\n• SSH отключается по умолчанию\n• Если port knocking — SSH управляется через knock\n• ssh-toggle для ручного управления"
        else
            pve_msg="Обнаружена VM ($VIRT_TYPE).\n\n• Установить qemu-guest-agent?\n• SSH будет отключён по умолчанию\n  (если port knocking — управляется через knock)\n• ssh-toggle для ручного включения через консоль"
        fi
        wh_yn "VM / Proxmox VE" "$pve_msg" && CFG_PVE=true || true
    fi

    # Summary / Confirm
    local s
    s="Hostname    : $CFG_HOST\n"
    s+="Timezone    : $CFG_TZ\n"
    s+="Admin user  : $CFG_MK_USER"
    $CFG_MK_USER && s+=" → $CFG_USER (sudo: $CFG_USER_SUDO)"
    [[ ${#CFG_EXTRA_USERS[@]} -gt 0 ]] && s+="\nExtra users : ${CFG_EXTRA_USERS[*]}"
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
    ($IS_PVE || $IS_VM) && s+="qemu-agent  : $CFG_PVE\n"

    wh_yn "✓ Confirm Settings" "$(printf '%b' "$s")"$'\n\n'"Apply now?" \
        || die "Aborted by user"
}

# ── Hostname & Timezone ───────────────────────────────────────────────────────
apply_host_tz() {
    hdr "Hostname & Timezone"

    if [[ -n "$CFG_HOST" ]]; then
        # Только допустимые символы для static hostname
        local clean_host
        clean_host=$(printf '%s' "$CFG_HOST" | tr -cd '[:alnum:].-' | cut -c1-63)
        if [[ -z "$clean_host" ]]; then
            warn "Hostname пустой после очистки — пропускаю"
        else
            CFG_HOST="$clean_host"
            if command -v hostnamectl &>/dev/null; then
                hostnamectl set-hostname --static "$CFG_HOST"
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
    fi

    case "$OS_FAMILY" in
        debian)
            if command -v timedatectl &>/dev/null; then
                timedatectl set-timezone "$CFG_TZ"
            else
                ln -sf "/usr/share/zoneinfo/$CFG_TZ" /etc/localtime
                echo "$CFG_TZ" > /etc/timezone
            fi ;;
        freebsd)
            cp "/usr/share/zoneinfo/$CFG_TZ" /etc/localtime
            echo "$CFG_TZ" > /etc/timezone ;;
    esac
    info "Timezone → $CFG_TZ"
}

# ── Admin User ────────────────────────────────────────────────────────────────
apply_user() {
    $CFG_MK_USER || return 0
    hdr "Admin User"

    if id "$CFG_USER" &>/dev/null; then
        warn "User $CFG_USER уже существует — пропускаю создание"
    else
        case "$OS_FAMILY" in
            debian)
                useradd -m -s /bin/bash "$CFG_USER"
                echo "$CFG_USER:$CFG_USER_PW" | chpasswd ;;
            freebsd)
                pw useradd "$CFG_USER" -m -s /bin/sh
                printf '%s\n' "$CFG_USER_PW" | pw usermod "$CFG_USER" -h 0 ;;
        esac
        info "User $CFG_USER created"
    fi

    # Sudo — только если явно выбрано в диалоге
    if $CFG_USER_SUDO; then
        case "$OS_FAMILY" in
            debian)  usermod -aG sudo "$CFG_USER" ;;
            freebsd) pw groupmod wheel -m "$CFG_USER" ;;
        esac
        info "User $CFG_USER добавлен в sudo/wheel"
    fi

    # SSH ключи (новый и существующий юзер, без дублирования)
    if $CFG_ADD_KEY && [[ ${#CFG_PUBKEYS[@]} -gt 0 ]]; then
        local home; home=$(eval echo "~$CFG_USER")
        mkdir -p "${home}/.ssh"
        local added=0
        for key in "${CFG_PUBKEYS[@]}"; do
            [[ -z "$key" ]] && continue
            if grep -qF "$key" "${home}/.ssh/authorized_keys" 2>/dev/null; then
                warn "Ключ уже есть для $CFG_USER, пропускаю"
            else
                echo "$key" >> "${home}/.ssh/authorized_keys"
                added=$(( added + 1 ))
            fi
        done
        chmod 700 "${home}/.ssh"
        chmod 600 "${home}/.ssh/authorized_keys"
        chown -R "$CFG_USER:$CFG_USER" "${home}/.ssh"
        info "Добавлено $added SSH ключ(а) для $CFG_USER"
    fi
}

# ── Существующие пользователи — sudo + ключи ──────────────────────────────────
apply_extra_users() {
    [[ ${#CFG_EXTRA_USERS[@]} -eq 0 ]] && return 0
    hdr "Существующие пользователи"

    local i
    for i in "${!CFG_EXTRA_USERS[@]}"; do
        local uname="${CFG_EXTRA_USERS[$i]}"
        local do_sudo="${CFG_EXTRA_SUDO[$i]:-false}"

        if ! id "$uname" &>/dev/null; then
            warn "Пользователь $uname не найден, пропускаю"
            continue
        fi

        # Sudo
        if [[ "$do_sudo" == "true" ]]; then
            case "$OS_FAMILY" in
                debian)  usermod -aG sudo "$uname" ;;
                freebsd) pw groupmod wheel -m "$uname" ;;
            esac
            info "$uname → добавлен в sudo/wheel"
        fi

        # SSH ключи (те же что вводили выше)
        if $CFG_ADD_KEY && [[ ${#CFG_PUBKEYS[@]} -gt 0 ]]; then
            local home; home=$(eval echo "~$uname")
            mkdir -p "${home}/.ssh"
            local added=0
            for key in "${CFG_PUBKEYS[@]}"; do
                [[ -z "$key" ]] && continue
                if grep -qF "$key" "${home}/.ssh/authorized_keys" 2>/dev/null; then
                    warn "Ключ уже есть для $uname, пропускаю"
                else
                    echo "$key" >> "${home}/.ssh/authorized_keys"
                    added=$(( added + 1 ))
                fi
            done
            chmod 700 "${home}/.ssh"
            chmod 600 "${home}/.ssh/authorized_keys"
            chown -R "$uname:$uname" "${home}/.ssh"
            info "$uname → добавлено $added SSH ключ(а)"
        fi
    done
}
apply_ssh() {
    hdr "SSH Hardening"
    local cfg="/etc/ssh/sshd_config"
    cp "$cfg" "${cfg}.bak.$(date +%s)"

    # ListenAddress не трогаем — дефолт уже 0.0.0.0, двойная запись ломает sshd
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

    if $CFG_ADD_KEY && ! $CFG_MK_USER && [[ ${#CFG_PUBKEYS[@]} -gt 0 ]]; then
        mkdir -p /root/.ssh
        local added=0
        for key in "${CFG_PUBKEYS[@]}"; do
            [[ -z "$key" ]] && continue
            grep -qF "$key" /root/.ssh/authorized_keys 2>/dev/null || {
                echo "$key" >> /root/.ssh/authorized_keys
                added=$(( added + 1 ))
            }
        done
        chmod 700 /root/.ssh
        chmod 600 /root/.ssh/authorized_keys
        info "Добавлено $added SSH ключ(а) для root"
    fi

    # Privilege separation directory
    case "$OS_FAMILY" in
        debian)
            mkdir -p /run/sshd
            chmod 755 /run/sshd
            chown root:root /run/sshd
            ;;
        freebsd)
            mkdir -p /var/run/sshd
            chmod 755 /var/run/sshd
            chown root:wheel /var/run/sshd
            ;;
    esac
    sshd -t >> "$LOG" 2>&1 || die "sshd config validation failed — see $LOG"

    case "$OS_FAMILY" in
        debian)  systemctl restart sshd ;;
        freebsd) service sshd restart >> "$LOG" 2>&1 ;;
    esac

    info "SSH hardened — port $CFG_SSH_PORT | root: $CFG_SSH_NO_ROOT | key-only: $CFG_SSH_KEY_ONLY"
}

# ── 2FA ───────────────────────────────────────────────────────────────────────
apply_2fa() {
    $CFG_2FA || return 0
    hdr "Two-Factor Authentication (TOTP)"

    case "$OS_FAMILY" in
        debian)  pkg_install libpam-google-authenticator ;;
        freebsd) pkg_install pam_google_authenticator ;;
    esac

    # Убрать из common-auth если туда случайно попало
    if [[ -f /etc/pam.d/common-auth ]]; then
        perl -ni -e 'print unless /pam_google_authenticator/' /etc/pam.d/common-auth
        info "Cleaned pam_google_authenticator from common-auth"
    fi

    # Добавить только в sshd
    local pam_sshd="/etc/pam.d/sshd"
    if ! grep -q "pam_google_authenticator" "$pam_sshd"; then
        echo "auth required pam_google_authenticator.so" >> "$pam_sshd"
    fi

    sshd_set KbdInteractiveAuthentication "yes"
    sshd_set UsePAM                       "yes"

    if $CFG_SSH_KEY_ONLY; then
        sshd_set AuthenticationMethods "publickey,keyboard-interactive"
    else
        sshd_set PasswordAuthentication "no"
        sshd_set AuthenticationMethods  "keyboard-interactive"
    fi

    sshd -t >> "$LOG" 2>&1 || die "sshd config error after 2FA setup"

    case "$OS_FAMILY" in
        debian)  systemctl restart sshd ;;
        freebsd) service sshd restart >> "$LOG" 2>&1 ;;
    esac

    info "2FA PAM configured"

    # Если создаём нового юзера — добавляем его в список
    local all_2fa_users=("${CFG_2FA_USERS[@]+"${CFG_2FA_USERS[@]}"}")
    if $CFG_MK_USER && [[ -n "$CFG_USER" ]]; then
        local already=false
        for u in "${all_2fa_users[@]+"${all_2fa_users[@]}"}"; do
            [[ "$u" == "$CFG_USER" ]] && already=true
        done
        $already || all_2fa_users+=("$CFG_USER")
    fi

    if [[ ${#all_2fa_users[@]} -eq 0 ]]; then
        warn "Пользователи для 2FA не выбраны — запусти google-authenticator вручную"
        return 0
    fi

    echo ""
    for fa_user in "${all_2fa_users[@]}"; do
        [[ -z "$fa_user" ]] && continue
        info "Настройка 2FA для: $fa_user"
        echo -e "  ${Y}Сканируй QR-код в Authenticator (Google / Aegis / Authy)${NC}"
        echo -e "  ${Y}Ответь на вопросы: рекомендуется Y Y N Y${NC}\n"
        if [[ "$fa_user" == "root" ]]; then
            google-authenticator -t -d -f -r 3 -R 30 -W || \
                warn "Ошибка google-authenticator для root"
        else
            # sudo -u работает на Linux и FreeBSD (su синтаксис разный)
            sudo -u "$fa_user" google-authenticator -t -d -f -r 3 -R 30 -W || \
                warn "Ошибка google-authenticator для $fa_user"
        fi
        echo ""
    done
}

# ── Firewall — Linux (iptables + knockd) ──────────────────────────────────────
# ── Firewall — Linux (iptables + ipset + knockd) ──────────────────────────────
apply_fw_linux() {
    hdr "Firewall — iptables + ipset"
    pkg_install iptables iptables-persistent netfilter-persistent ipset

    # ── Systemd сервис для загрузки ipset при boot ────────────────────────────
    cat > /etc/systemd/system/ipset-restore.service << 'EOF'
[Unit]
Description=Restore ipsets from /etc/ipset.conf
Before=netfilter-persistent.service
DefaultDependencies=no
ConditionFileNotEmpty=/etc/ipset.conf

[Service]
Type=oneshot
ExecStart=/sbin/ipset restore -f /etc/ipset.conf
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable ipset-restore.service >> "$LOG" 2>&1

    # ── Создаём ipset: ssh_allow — IPs для SSH ────────────────────────────────
    ipset create ssh_allow hash:ip family inet hashsize 1024 maxelem 65536 2>/dev/null \
        || ipset flush ssh_allow
    ipset save > /etc/ipset.conf
    info "ipset ssh_allow создан → /etc/ipset.conf"

    # ── iptables правила ──────────────────────────────────────────────────────
    iptables -F; iptables -X; iptables -Z
    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  ACCEPT

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A INPUT -p icmp -j ACCEPT

    # Anti-scan
    iptables -A INPUT -p tcp ! --syn -m state --state NEW    -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL ALL             -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL NONE            -j DROP

    # SSH только для IP из ipset ssh_allow
    iptables -A INPUT -p tcp --dport "$CFG_SSH_PORT" \
        -m set --match-set ssh_allow src -j ACCEPT
    info "SSH port $CFG_SSH_PORT → только через ipset ssh_allow (остальные DROP по политике)"

    # Публичные порты — только если указаны
    if [[ -n "$CFG_PORTS" ]]; then
        IFS=',' read -ra ALLOW_PORTS <<< "$CFG_PORTS"
        for p in "${ALLOW_PORTS[@]}"; do
            p="${p// /}"; [[ -z "$p" ]] && continue
            iptables -A INPUT -p tcp --dport "$p" -j ACCEPT
            info "Allowed TCP port $p"
        done
    else
        info "Дополнительных публичных портов нет"
    fi

    # ── Port knocking → добавляет IP в ssh_allow ──────────────────────────────
    # Определяем IP текущей SSH сессии (SSH_CONNECTION не передаётся через sudo)
    local cur_ip=""
    # Method 1: SSH_CONNECTION (работает без sudo)
    cur_ip=$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')
    # Method 2: who am i (работает через sudo)
    [[ -z "$cur_ip" ]] && \
        cur_ip=$(who am i 2>/dev/null | grep -oE '\([0-9.]+\)' | tr -d '()')
    # Method 3: ss (Linux) или sockstat (FreeBSD)
    if [[ -z "$cur_ip" ]]; then
        if command -v ss &>/dev/null; then
            cur_ip=$(ss -tn state established 2>/dev/null \
                | awk -v p=":$CFG_SSH_PORT" '$4 ~ p {split($5,a,":");print a[1]}' \
                | grep -v '^$' | head -1)
        elif command -v sockstat &>/dev/null; then
            cur_ip=$(sockstat -4c 2>/dev/null \
                | awk -v p="$CFG_SSH_PORT" '$5 ~ ":"p"$" {split($6,a,":");print a[1]}' \
                | head -1)
        fi
    fi

    if $CFG_KNOCK; then
        read -ra KP <<< "$CFG_KNOCK_SEQ"
        local k1="${KP[0]:-7000}" k2="${KP[1]:-8000}" k3="${KP[2]:-9000}"
        pkg_install knockd

        # Текущий IP — добавляем чтобы не оборвать сессию
        if [[ -n "$cur_ip" ]]; then
            ipset add ssh_allow "$cur_ip" -exist
            ipset save > /etc/ipset.conf
            warn "Текущий IP $cur_ip добавлен в ssh_allow"
            warn "Удалить: ipset del ssh_allow $cur_ip && ipset save > /etc/ipset.conf"
        fi

        local iface
        iface=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1 || echo "eth0")

        cat > /etc/knockd.conf << KNOCKEOF
[options]
    UseSyslog
    Interface = ${iface}

# Открыть: knock HOST ${k1} ${k2} ${k3}
[openSSH]
    sequence    = ${k1},${k2},${k3}
    seq_timeout = 5
    command     = /sbin/ipset add ssh_allow %IP% -exist && /sbin/ipset save > /etc/ipset.conf
    tcpflags    = syn

# Закрыть: knock HOST ${k3} ${k2} ${k1}
[closeSSH]
    sequence    = ${k3},${k2},${k1}
    seq_timeout = 5
    command     = /sbin/ipset del ssh_allow %IP% -exist && /sbin/ipset save > /etc/ipset.conf
    tcpflags    = syn
KNOCKEOF

        [[ -f /etc/default/knockd ]] && \
            perl -i -pe 's/START_KNOCKD=0/START_KNOCKD=1/' /etc/default/knockd

        systemctl enable knockd >> "$LOG" 2>&1
        systemctl restart knockd >> "$LOG" 2>&1

        info "Port knocking: $k1 → $k2 → $k3 → добавляет IP в ssh_allow"
        warn "Открыть SSH: knock HOST $k1 $k2 $k3"
        warn "Закрыть SSH: knock HOST $k3 $k2 $k1"

        # Клиентский скрипт
        cat > /root/ssh-knock.sh << SKEOF
#!/bin/bash
# Использование: ssh-knock.sh <HOST> [user] [ssh-port]
HOST="\${1:?Укажи хост: ./ssh-knock.sh host user}"
SSHUSER="\${2:-root}"
PORT="\${3:-$CFG_SSH_PORT}"
knock "\$HOST" $k1 $k2 $k3
sleep 1
ssh -p "\$PORT" "\$SSHUSER@\$HOST"
SKEOF
        chmod +x /root/ssh-knock.sh
        info "Клиентский скрипт: /root/ssh-knock.sh <HOST> [user]"

    else
        # Без port knocking — добавляем текущий IP сразу
        if [[ -n "$cur_ip" ]]; then
            ipset add ssh_allow "$cur_ip" -exist
            ipset save > /etc/ipset.conf
            info "Твой IP $cur_ip добавлен в ssh_allow"
        fi
        warn "SSH доступен только для IP из ssh_allow"
        warn "Добавить IP: ipset add ssh_allow <IP> -exist && ipset save > /etc/ipset.conf"
    fi

    # ── Сохраняем (persistent) ────────────────────────────────────────────────
    netfilter-persistent save >> "$LOG" 2>&1
    info "iptables rules → /etc/iptables/rules.v4"
    info "ipset state   → /etc/ipset.conf"

    # ── IPv6 ──────────────────────────────────────────────────────────────────
    if command -v ip6tables &>/dev/null; then
        ip6tables -P INPUT DROP; ip6tables -P FORWARD DROP; ip6tables -P OUTPUT ACCEPT
        ip6tables -A INPUT -i lo -j ACCEPT
        ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
        netfilter-persistent save >> "$LOG" 2>&1
        info "IPv6 hardened"
    fi
}


# ── Firewall — FreeBSD / pf ───────────────────────────────────────────────────
apply_fw_freebsd_pf() {
    hdr "Firewall — pf"
    local iface
    iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' || echo "em0")
    local pf_ports="{ $(echo "$CFG_PORTS" | tr ',' ' ') }"
    local pf_conf="/etc/pf.conf"
    cp "$pf_conf" "${pf_conf}.bak.$(date +%s)" 2>/dev/null || true

    cat > "$pf_conf" << EOF
# Generated by server-harden.sh $(date)
ext_if = "$iface"
table <bruteforce> persist
set block-policy drop
set skip on lo0
scrub in all
block in  all
pass  out all keep state
pass in inet  proto icmp  icmp-type echoreq keep state
pass in inet6 proto icmp6           all     keep state
block in quick from <bruteforce>
pass in on \$ext_if proto tcp to port $CFG_SSH_PORT \\
    flags S/SA keep state \\
    (max-src-conn 5, max-src-conn-rate 3/30, overload <bruteforce> flush global)
pass in on \$ext_if proto tcp to port $pf_ports keep state
EOF

    sysrc pf_enable=YES pflog_enable=YES >> "$LOG" 2>&1
    pfctl -nf "$pf_conf" >> "$LOG" 2>&1 \
        && { pfctl -f "$pf_conf" >> "$LOG" 2>&1; pfctl -e >> "$LOG" 2>&1; info "pf enabled"; } \
        || warn "pf config errors — check $LOG"

    echo "0 * * * * root /sbin/pfctl -t bruteforce -T expire 3600" > /etc/cron.d/pf-expire
}

# ── Firewall — FreeBSD / ipfw ─────────────────────────────────────────────────
apply_fw_freebsd_ipfw() {
    hdr "Firewall — ipfw (tables)"

    # Загружаем модуль ipfw если не загружен
    if ! kldstat -qn ipfw 2>/dev/null; then
        info "Загружаю модуль ipfw..."
        kldload ipfw 2>/dev/null || \
            die "Не удалось загрузить ipfw. Добавь ipfw_load=\"YES\" в /boot/loader.conf и перезагрузись."
    fi
    grep -q 'ipfw_load' /boot/loader.conf 2>/dev/null || \
        echo 'ipfw_load="YES"' >> /boot/loader.conf

    local iface
    iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' || echo "em0")

    local fw_file="/etc/firewall.conf"

    # Бэкап существующего файла
    if [[ -f "$fw_file" ]]; then
        local bak="${fw_file}.bak.$(date +%s)"
        cp "$fw_file" "$bak"
        warn "Бэкап: $bak"
    fi

    # Правила для публичных портов
    local n=400 port_rules=""
    if [[ -n "$CFG_PORTS" ]]; then
        IFS=',' read -ra ALLOW_PORTS <<< "$CFG_PORTS"
        for p in "${ALLOW_PORTS[@]}"; do
            p="${p// /}"; [[ -z "$p" ]] && continue
            port_rules+="\${FwCMD} add $n allow tcp from any to me $p in via \${pif}\n"
            n=$(( n + 10 ))
        done
    fi

    cat > "$fw_file" << FWEOF
#!/bin/sh
# /etc/firewall.conf
# Generated by server-harden.sh $(date)

FwCMD="/sbin/ipfw -q"
pif="$iface"

# ── Flush ─────────────────────────────────────────────────────────────────────
\${FwCMD} -f flush

# ── Tables ────────────────────────────────────────────────────────────────────
# Table 10: ssh_allow — IPs с доступом по SSH
#   Добавить IP:  ipfw table 10 add <IP>
#   Удалить IP:   ipfw table 10 delete <IP>
#   Список:       ipfw table 10 list
\${FwCMD} table 10 flush

# ── Loopback ──────────────────────────────────────────────────────────────────
\${FwCMD} add 100 allow ip from any to any via lo0

# ── Established TCP (ответы на наши соединения) ───────────────────────────────
\${FwCMD} add 200 allow tcp from any to any established

# ── ICMP ──────────────────────────────────────────────────────────────────────
\${FwCMD} add 210 allow icmp from any to any icmptypes 0,3,8,11

# ── Anti-scan: недопустимые комбинации TCP флагов ─────────────────────────────
\${FwCMD} add 220 deny tcp from any to any tcpflags syn,fin
\${FwCMD} add 225 deny tcp from any to any tcpflags syn,rst
\${FwCMD} add 230 deny tcp from any to any tcpflags fin,syn,rst,psh,ack,urg

# ── SSH: только из таблицы 10 ─────────────────────────────────────────────────
\${FwCMD} add 300 allow tcp from "table(10)" to me $CFG_SSH_PORT in via \${pif}

# ── Публичные порты ───────────────────────────────────────────────────────────
$(printf '%b' "$port_rules")
# ── Исходящий трафик + keep-state (UDP ответы через таблицу состояний) ────────
\${FwCMD} add 900 allow ip from me to any out via \${pif} keep-state

# ── Default deny ──────────────────────────────────────────────────────────────
\${FwCMD} add 65000 deny log ip from any to any
FWEOF

    chmod +x "$fw_file"

    # Определяем текущий IP и добавляем в таблицу 10 ДО применения правил
    local cur_ip=""
    cur_ip=$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')
    [[ -z "$cur_ip" ]] && cur_ip=$(who am i 2>/dev/null | grep -oE '\([0-9.]+\)' | tr -d '()')
    [[ -z "$cur_ip" ]] && cur_ip=$(sockstat -4c 2>/dev/null \
        | awk -v p="$CFG_SSH_PORT" '$5 ~ ":"p"$" {split($6,a,":");print a[1]}' | head -1)

    # Применяем правила
    sh "$fw_file" >> "$LOG" 2>&1 \
        && info "ipfw rules applied → $fw_file" \
        || warn "ipfw: проверь $fw_file и $LOG"

    # Добавляем текущий IP в таблицу после применения правил
    if [[ -n "$cur_ip" ]]; then
        /sbin/ipfw table 10 add "$cur_ip" 2>/dev/null && \
            info "Твой IP $cur_ip добавлен в ipfw table 10 (ssh_allow)"
        warn "Удалить: ipfw table 10 delete $cur_ip"
        warn "Добавить постоянно — в конец $fw_file:"
        warn "  \${FwCMD} table 10 add $cur_ip"
    else
        warn "Текущий IP не определён — добавь вручную: ipfw table 10 add <IP>"
    fi

    sysrc firewall_enable=YES firewall_logging=YES \
          firewall_script="$fw_file" >> "$LOG" 2>&1
    info "Firewall: $fw_file | Table 10 = ssh_allow"
}

apply_firewall() {
    case "$OS_FAMILY" in
        debian)
            # iptables + ipset — всегда, это основа безопасности
            apply_fw_linux
            ;;
        freebsd)
            $CFG_FW || return 0
            case "${CFG_FW_TYPE:-ipfw}" in
                ipfw) apply_fw_freebsd_ipfw ;;
                pf|*) apply_fw_freebsd_pf   ;;
            esac
            ;;
    esac
}

# ── fail2ban ──────────────────────────────────────────────────────────────────
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

# ── Sysctl ────────────────────────────────────────────────────────────────────
apply_sysctl() {
    $CFG_SYSCTL || return 0
    hdr "Kernel Hardening (sysctl)"

    case "$OS_FAMILY" in
        debian)
            cat > /etc/sysctl.d/99-harden.conf << 'EOF'
net.ipv4.conf.all.rp_filter                 = 1
net.ipv4.conf.default.rp_filter             = 1
net.ipv4.conf.all.accept_redirects          = 0
net.ipv4.conf.default.accept_redirects      = 0
net.ipv4.conf.all.send_redirects            = 0
net.ipv6.conf.all.accept_redirects          = 0
net.ipv4.conf.all.accept_source_route       = 0
net.ipv4.conf.default.accept_source_route   = 0
net.ipv4.tcp_syncookies                     = 1
net.ipv4.tcp_max_syn_backlog                = 4096
net.ipv4.conf.all.log_martians              = 1
net.ipv4.icmp_echo_ignore_broadcasts        = 1
net.ipv4.icmp_ignore_bogus_error_responses  = 1
net.ipv4.tcp_rfc1337                        = 1
net.ipv6.conf.all.accept_ra                 = 0
net.ipv6.conf.default.accept_ra             = 0
kernel.randomize_va_space                   = 2
kernel.sysrq                                = 0
kernel.dmesg_restrict                       = 1
kernel.yama.ptrace_scope                    = 1
fs.suid_dumpable                            = 0
net.core.somaxconn                          = 65535
EOF
            sysctl -p /etc/sysctl.d/99-harden.conf >> "$LOG" 2>&1
            info "sysctl settings applied" ;;
        freebsd)
            # Наши настройки — применяем каждый параметр отдельно
            # (не через sysctl -f — это применит ВЕСЬ файл включая чужие настройки)
            local bsd_settings=(
                "net.inet.ip.redirect=0"
                "net.inet.icmp.drop_redirect=1"
                "net.inet.tcp.drop_synfin=1"
                "net.inet.ip.sourceroute=0"
                "net.inet.ip.accept_sourceroute=0"
                "kern.randompid=1"
                "security.bsd.see_other_uids=0"
                "security.bsd.see_other_gids=0"
                "security.bsd.unprivileged_read_msgbuf=0"
            )
            # Добавляем в sysctl.conf (если ещё нет)
            for s in "${bsd_settings[@]}"; do
                local key="${s%%=*}"
                grep -q "^${key}" /etc/sysctl.conf 2>/dev/null || \
                    echo "$s" >> /etc/sysctl.conf
                # Применяем сейчас (игнорируем неизвестные OID — модуль может не быть загружен)
                sysctl "$s" >> "$LOG" 2>/dev/null || true
            done
            info "sysctl settings applied (FreeBSD)" ;;
    esac
}

# ── Auto-updates ──────────────────────────────────────────────────────────────
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

# ── PVE / VM guest ────────────────────────────────────────────────────────────
apply_pve() {
    $CFG_PVE || return 0
    hdr "VM / Proxmox VE Setup"

    # qemu-guest-agent
    pkg_install qemu-guest-agent
    case "$OS_FAMILY" in
        debian)
            systemctl enable qemu-guest-agent >> "$LOG" 2>&1
            systemctl start  qemu-guest-agent >> "$LOG" 2>&1
            ;;
        freebsd)
            sysrc qemu_guest_agent_enable="YES" >> "$LOG" 2>&1
            service qemu-guest-agent start >> "$LOG" 2>&1 || true
            ;;
    esac
    info "qemu-guest-agent installed and started"

    # ssh-toggle — универсальный: работает на Linux и FreeBSD
    cat > /usr/local/bin/ssh-toggle << 'SCRIPT'
#!/bin/sh
# ssh-toggle [on|off|persist|status]
if command -v systemctl >/dev/null 2>&1; then
    # Linux (systemd)
    SSH_SVC=$(systemctl list-unit-files 2>/dev/null \
        | awk '/^ssh(d)?\.service/{print $1; exit}')
    case "${1:-status}" in
        on)       systemctl start  "$SSH_SVC" && echo "SSH started (temporary)" ;;
        off)      systemctl stop   "$SSH_SVC" && echo "SSH stopped" ;;
        persist)  systemctl enable "$SSH_SVC"; systemctl start "$SSH_SVC" && echo "SSH permanent" ;;
        disable)  systemctl disable "$SSH_SVC"; systemctl stop "$SSH_SVC" ;;
        *)        systemctl is-active --quiet "$SSH_SVC" && echo "running" || echo "stopped" ;;
    esac
else
    # FreeBSD (rc.d)
    case "${1:-status}" in
        on)       service sshd start ;;
        off)      service sshd stop ;;
        persist)  sysrc sshd_enable="YES"; service sshd start && echo "SSH permanent" ;;
        disable)  sysrc sshd_enable="NO";  service sshd stop ;;
        *)        service sshd status ;;
    esac
fi
SCRIPT
    chmod +x /usr/local/bin/ssh-toggle
    info "ssh-toggle installed: ssh-toggle [on|off|persist|disable|status]"

    # SSH: с port knocking — сервис работает (ipfw/ipset контролируют доступ)
    #       без knock — выключаем, доступ через консоль гипервизора
    if ${CFG_KNOCK:-false}; then
        info "Port knocking активен — SSH сервис работает, доступ через knock"
    else
        case "$OS_FAMILY" in
            debian)
                local ssh_svc
                ssh_svc=$(systemctl list-unit-files 2>/dev/null \
                    | awk '/^ssh(d)?\.service/{print $1; exit}' || echo "sshd.service")
                systemctl disable "$ssh_svc" >> "$LOG" 2>&1 || true
                systemctl stop    "$ssh_svc" >> "$LOG" 2>&1 || true
                ;;
            freebsd)
                sysrc sshd_enable="NO" >> "$LOG" 2>&1 || true
                service sshd stop >> "$LOG" 2>&1 || true
                ;;
        esac
        info "SSH отключён по умолчанию"
        warn "Включить (через консоль): ssh-toggle on"
        warn "Включить постоянно:       ssh-toggle persist"
    fi
}

# ── Misc ──────────────────────────────────────────────────────────────────────
apply_misc() {
    hdr "Miscellaneous Hardening"

    # PATH глобально через profile.d (работает и на Linux и FreeBSD)
    cat > /etc/profile.d/99-sbin-path.sh << 'EOF'
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
EOF
    chmod 644 /etc/profile.d/99-sbin-path.sh

    # /etc/bash.bashrc — только Linux
    if [[ "$OS_FAMILY" == "debian" ]]; then
        if ! grep -q "99-sbin-path" /etc/bash.bashrc 2>/dev/null; then
            echo 'source /etc/profile.d/99-sbin-path.sh' >> /etc/bash.bashrc
        fi
    fi

    # sudo secure_path — только если sudo установлен
    if command -v sudo &>/dev/null && [[ -d /etc/sudoers.d ]]; then
        echo 'Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' \
            > /etc/sudoers.d/99-sbin-path
        chmod 440 /etc/sudoers.d/99-sbin-path
    fi
    info "PATH глобально прописан"

    cat > /etc/issue.net << 'EOF'
***************************************************************************
              AUTHORIZED ACCESS ONLY — ALL SESSIONS ARE MONITORED
***************************************************************************
EOF
    info "Login banner set"

    # Хелпер для добавления ключей после установки
    cat > /usr/local/bin/add-ssh-key << 'SCRIPT'
#!/bin/bash
# add-ssh-key — добавить SSH публичный ключ пользователю
# Использование:
#   add-ssh-key <user>                  # спросит ключ интерактивно
#   add-ssh-key <user> "ssh-ed25519 .." # ключ как аргумент
#   cat key.pub | add-ssh-key <user>    # через pipe
USER="${1:?Использование: add-ssh-key <username> [public_key]}"
if [[ -n "${2:-}" ]]; then
    KEY="$2"
elif [ -p /dev/stdin ]; then
    KEY=$(cat)
else
    echo "Вставь публичный ключ и нажми Enter:"
    read -r KEY
fi
[[ -z "$KEY" ]] && { echo "Ошибка: ключ пустой"; exit 1; }
HOME_DIR=$(eval echo "~$USER")
mkdir -p "${HOME_DIR}/.ssh"
if grep -qF "$KEY" "${HOME_DIR}/.ssh/authorized_keys" 2>/dev/null; then
    echo "Ключ уже существует для $USER"
else
    echo "$KEY" >> "${HOME_DIR}/.ssh/authorized_keys"
    chmod 700 "${HOME_DIR}/.ssh"
    chmod 600 "${HOME_DIR}/.ssh/authorized_keys"
    chown -R "$USER:$USER" "${HOME_DIR}/.ssh"
    echo "✓ Ключ добавлен для $USER"
fi
SCRIPT
    chmod +x /usr/local/bin/add-ssh-key
    info "Хелпер установлен: add-ssh-key <user> [key]"

    printf 'TMOUT=600; readonly TMOUT; export TMOUT\n' \
        > /etc/profile.d/99-timeout.sh
    chmod 644 /etc/profile.d/99-timeout.sh
    info "Idle session timeout: 10 minutes"

    if [[ "$OS_FAMILY" == "debian" ]]; then
        cat >> /etc/security/limits.conf << 'EOF'

# server-harden.sh
*    soft core 0
*    hard core 0
root soft core 0
root hard core 0
EOF
        echo "install usb-storage /bin/true" > /etc/modprobe.d/disable-usb-storage.conf
        info "USB storage module disabled"

        if ! grep -qE "tmpfs.*/dev/shm" /etc/fstab 2>/dev/null; then
            echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec 0 0" >> /etc/fstab
            mount -o remount /dev/shm 2>/dev/null || true
            info "Shared memory secured (nosuid,nodev,noexec)"
        fi
    fi
}

# ── Final report ──────────────────────────────────────────────────────────────
final_report() {
    echo ""
    echo -e "${G}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${G}║   ✓  Hardening complete!                     ║${NC}"
    echo -e "${G}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${C}Log:${NC}      $LOG"
    echo -e "  ${C}SSH port:${NC} $CFG_SSH_PORT"
    if $CFG_MK_USER && ${CFG_PW_GENERATED:-false}; then
        echo ""
        echo -e "  ${Y}⚠ Сгенерированный пароль для $CFG_USER:${NC}"
        echo -e "  ${R}  $CFG_USER_PW${NC}"
        echo -e "  ${Y}  Сохрани! Сменить: passwd $CFG_USER${NC}"
    fi
    $CFG_KNOCK && {
        echo -e "\n  ${C}Port knocking:${NC}"
        echo -e "    knock HOST $CFG_KNOCK_SEQ"
        echo -e "    ssh -p $CFG_SSH_PORT user@HOST"
        echo -e "  Client helper: /root/ssh-knock.sh"
    }
    $CFG_2FA && echo -e "\n  ${Y}⚠ 2FA:${NC} Run 'google-authenticator' per user"
    $IS_PVE && $CFG_PVE && echo -e "\n  ${Y}⚠ SSH off:${NC} ssh-toggle on / ssh-toggle persist"
    echo ""
    echo -e "  ${R}⚠  Не закрывай сессию! Проверь вход в новом окне.${NC}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    # Debian 13+ не кладёт /usr/sbin в PATH при sudo — фиксим
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

    : > "$LOG"
    check_root
    detect_os

    printf '\n%b' "$C"
    echo "  ┌──────────────────────────────────────────────┐"
    printf '  │  Server Hardening Script  v%-18s│\n' "${HARDEN_VER}"
    printf '  │  OS: %-38s│\n' "${OS_ID:-?} ${OS_VER:-}"
    printf '  │  PVE: %-5s  VM: %-5s %-20s│\n' \
        "${IS_PVE}" "${IS_VM}" "${IS_VM:+($VIRT_TYPE)}"
    echo "  └──────────────────────────────────────────────┘"
    printf '%b\n\n' "$NC"

    if ! command -v whiptail &>/dev/null && ! command -v dialog &>/dev/null; then
        info "Устанавливаю whiptail/dialog..."
        pkg_update
        pkg_install whiptail 2>/dev/null || pkg_install dialog 2>/dev/null || true
    fi
    setup_dialog

    # Устанавливаем базовые инструменты только если отсутствуют
    hdr "Essential Tools"
    pkg_ensure sudo mc curl wget
    info "Базовые инструменты: sudo, mc, curl, wget"

    gather
    apply_host_tz
    apply_user
    apply_extra_users
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
