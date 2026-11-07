#!/bin/bash
# =====================================================================
#  NETIFAY - tunnel management panel
#  Install / update:
#    bash <(curl -fsSL https://raw.githubusercontent.com/NETplusiran/NETIFAY/main/install.sh)
#  After install, open this menu any time with:  netifay
# =====================================================================

REPO="NETplusiran/NETIFAY"     # <-- your GitHub user/repo
BRANCH="main"

APP_DIR="/opt/netifay"
APP="${APP_DIR}/netifay.py"
CONF_DIR="/etc/netifay"
CONF="${CONF_DIR}/config.json"
UNIT="/etc/systemd/system/netifay.service"
SHORTCUT="/usr/local/bin/netifay"
G="\033[32m"; R="\033[31m"; Y="\033[33m"; C="\033[36m"; B="\033[1m"; N="\033[0m"

if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo -i)"; exit 1; fi

banner() {
    echo -e "${C}${B}"
    echo "  _   _ _____ _____ ___ _____ _____   __"
    echo " | \\ | | ____|_   _|_ _|  ___/ \\ \\ / /"
    echo " |  \\| |  _|   | |  | || |_ / _ \\ V / "
    echo " | |\\  | |___  | |  | ||  _/ ___ \\| |  "
    echo " |_| \\_|_____| |_| |___|_|/_/   \\_\\_|  "
    echo -e "${N}        Tunnel management panel"
    echo -e "        ${Y}github.com/${REPO}${N}"
    echo
}

fetch() {   # fetch <path-in-repo> <dest>
    local p="$1" d="$2"
    curl -fsSL --connect-timeout 15 "https://raw.githubusercontent.com/${REPO}/${BRANCH}/${p}" -o "$d" 2>/dev/null && return 0
    curl -fsSL --connect-timeout 15 "https://github.com/${REPO}/raw/${BRANCH}/${p}" -o "$d" 2>/dev/null && return 0
    return 1
}

need_deps() {
    local pkgs=()
    command -v python3 >/dev/null 2>&1 || pkgs+=(python3)
    command -v curl    >/dev/null 2>&1 || pkgs+=(curl)
    command -v dig     >/dev/null 2>&1 || pkgs+=(dnsutils)
    command -v crontab >/dev/null 2>&1 || pkgs+=(cron)
    command -v openssl >/dev/null 2>&1 || pkgs+=(openssl)
    command -v ip      >/dev/null 2>&1 || pkgs+=(iproute2)
    command -v iptables >/dev/null 2>&1 || pkgs+=(iptables)
    if ((${#pkgs[@]})); then
        echo -e "${Y}Installing: ${pkgs[*]}${N}"
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" >/dev/null || true
        else
            echo -e "${R}Please install manually: ${pkgs[*]}${N}"
        fi
    fi
    command -v python3 >/dev/null 2>&1 || { echo -e "${R}python3 is required${N}"; exit 1; }
    systemctl enable --now cron >/dev/null 2>&1 || true
}

server_ip() { ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -n1; }

conf_get() {
    python3 -c "import json;c=json.load(open('$CONF'));v=c.get('$1');print(v if v is not None else '$2')" 2>/dev/null || echo "$2"
}

is_public() { [[ "$(conf_get listen 0.0.0.0)" != "127.0.0.1" ]]; }

open_firewall() {
    local port="$1"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${port}/tcp" >/dev/null && echo -e "${G}ufw: port ${port}/tcp opened${N}"
    fi
}

show_url() {
    local port base ip scheme="http"
    port=$(conf_get port 8800); base=$(conf_get base ""); ip=$(server_ip)
    [[ -n "$base" ]] && base="${base}/"
    [[ -n "$(conf_get cert '')" ]] && scheme="https"
    echo
    echo -e "${G}${B}Panel URL:${N}  ${scheme}://${ip:-SERVER_IP}:${port}/${base}"
    [[ "$scheme" == "http" ]] && echo -e "${Y}Tip: turn on HTTPS (option 8) so your password is encrypted.${N}"
}

# ---- migrate an old "rathole-panel" install (same author, previous name)
migrate_old() {
    if [[ -f /etc/rathole-panel/config.json && ! -f "$CONF" ]]; then
        echo -e "${C}Migrating previous rathole-panel install to NETIFAY...${N}"
        mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
        cp -a /etc/rathole-panel/. "$CONF_DIR/"
        python3 - "$CONF" <<'PY'
import json, sys
p = sys.argv[1]
c = json.load(open(p))
for k in ("cert", "key"):
    if c.get(k):
        c[k] = c[k].replace("/etc/rathole-panel/", "/etc/netifay/")
json.dump(c, open(p, "w"), indent=2)
PY
        chmod 600 "$CONF"
    fi
    if systemctl list-unit-files 2>/dev/null | grep -q '^rathole-panel.service'; then
        systemctl disable --now rathole-panel.service >/dev/null 2>&1
        rm -f /etc/systemd/system/rathole-panel.service
        systemctl daemon-reload
    fi
    rm -rf /opt/rathole-panel /usr/local/bin/rathole-panel
    if [[ -d /root/rathole-backups && ! -d /root/netifay-backups ]]; then
        mv /root/rathole-backups /root/netifay-backups
    fi
}

write_unit() {
    cat > "$UNIT" <<EOF
[Unit]
Description=NETIFAY tunnel panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env python3 ${APP}
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

install_files() {
    mkdir -p "$APP_DIR"; chmod 700 "$APP_DIR"
    local tmp; tmp=$(mktemp -d)
    echo -e "${C}Downloading NETIFAY from github.com/${REPO} ...${N}"
    if fetch "netifay.py" "$tmp/netifay.py" && python3 -m py_compile "$tmp/netifay.py" 2>/dev/null; then
        cp -f "$tmp/netifay.py" "$APP"
        fetch "install.sh" "$tmp/install.sh" && cp -f "$tmp/install.sh" "${APP_DIR}/install.sh"
    else
        local here; here="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
        if [[ -f "${here}/netifay.py" ]]; then
            echo -e "${Y}GitHub not reachable - using local files.${N}"
            cp -f "${here}/netifay.py" "$APP"
            [[ -f "${here}/install.sh" ]] && cp -f "${here}/install.sh" "${APP_DIR}/install.sh"
        elif [[ ! -f "$APP" ]]; then
            echo -e "${R}Could not download NETIFAY from GitHub. Check that this server can reach github.com.${N}"
            rm -rf "$tmp"; return 1
        else
            echo -e "${Y}GitHub not reachable - keeping the installed version.${N}"
        fi
    fi
    rm -rf "$tmp"
    chmod 700 "$APP"
    [[ -f "${APP_DIR}/install.sh" ]] && chmod 700 "${APP_DIR}/install.sh"
    printf '#!/bin/bash\nexec bash %s "$@"\n' "${APP_DIR}/install.sh" > "$SHORTCUT"
    chmod 755 "$SHORTCUT"
}

configure_new() {
    local def_port def_base user pass pass2 port base
    def_port=$(( (RANDOM % 20000) + 20000 ))
    def_base=$(tr -dc 'a-z0-9' </dev/urandom | head -c 10)
    read -p "Panel port [${def_port}]: " port; port=${port:-$def_port}
    read -p "Secret path (empty = none) [${def_base}]: " base; base=${base:-$def_base}
    read -p "Username [admin]: " user; user=${user:-admin}
    while true; do
        read -s -p "Password (min 8 chars): " pass; echo
        read -s -p "Repeat password: " pass2; echo
        [[ "$pass" == "$pass2" && ${#pass} -ge 8 ]] && break
        echo -e "${R}Passwords do not match or too short.${N}"
    done
    RP_USER="$user" RP_PASS="$pass" RP_PORT="$port" RP_BASE="$base" \
        RATHOLE_PANEL_CONF="$CONF" python3 "$APP" --setup || exit 1
}

install_panel() {
    need_deps
    migrate_old
    install_files || return
    if [[ -f "$CONF" ]] && grep -q '"hash"' "$CONF"; then
        echo -e "${C}Existing settings found - updating (users, port and tunnels kept).${N}"
    else
        configure_new
    fi
    python3 "$APP" --repo "$REPO" >/dev/null 2>&1
    write_unit
    systemctl enable netifay.service >/dev/null 2>&1
    systemctl restart netifay.service
    sleep 1.5
    if systemctl is-active --quiet netifay.service; then
        echo -e "${G}${B}NETIFAY is running.${N}"
        if is_public; then open_firewall "$(conf_get port 8800)"; show_url
        else echo -e "${Y}Web access from outside is OFF (local only). Use option 7 to turn it on.${N}"; fi
        echo -e "Open this menu any time with: ${C}netifay${N}"
    else
        echo -e "${R}Panel failed to start:${N}"
        journalctl -u netifay.service -n 20 --no-pager
    fi
}

reset_password() {
    [[ -f "$APP" ]] || { echo -e "${R}Not installed${N}"; return; }
    local user pass
    read -p "Username [admin]: " user; user=${user:-admin}
    read -s -p "New password (min 8 chars): " pass; echo
    RP_USER="$user" RP_PASS="$pass" python3 "$APP" --setup && \
        systemctl restart netifay.service && echo -e "${G}Password changed.${N}"
}

toggle_external() {
    [[ -f "$CONF" ]] || { echo -e "${R}Not installed${N}"; return; }
    local port; port=$(conf_get port 8800)
    if is_public; then
        python3 "$APP" --listen local >/dev/null
        if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw delete allow "${port}/tcp" >/dev/null 2>&1
        fi
        systemctl restart netifay.service
        echo -e "${G}Web access from outside is now OFF.${N} Panel listens on 127.0.0.1:${port} only; tunnels are not affected."
        echo -e "To use it anyway, on YOUR computer run:  ${C}ssh -L ${port}:127.0.0.1:${port} root@$(server_ip)${N}"
    else
        python3 "$APP" --listen public >/dev/null
        open_firewall "$port"
        systemctl restart netifay.service
        echo -e "${G}Web access from outside is now ON.${N}"; show_url
    fi
}

toggle_https() {
    [[ -f "$CONF" ]] || { echo -e "${R}Not installed${N}"; return; }
    if [[ -n "$(conf_get cert '')" ]]; then
        python3 "$APP" --https off && systemctl restart netifay.service && echo -e "${Y}HTTPS is now OFF.${N}"
    else
        python3 "$APP" --https on && systemctl restart netifay.service && \
            echo -e "${G}HTTPS is now ON${N} (self-signed: the browser warns once -> Advanced -> Proceed)."
    fi
    show_url
}

uninstall_panel() {
    read -p "Remove the NETIFAY panel? Tunnels keep running. (y/n): " a
    [[ "$a" == [yY] ]] || return
    systemctl disable --now netifay.service >/dev/null 2>&1
    rm -f "$UNIT"; systemctl daemon-reload
    rm -rf "$APP_DIR" "$CONF_DIR" "$SHORTCUT"
    echo -e "${G}NETIFAY panel removed. Your tunnels keep running.${N}"
    exit 0
}

menu() {
    while true; do
        clear; banner
        if systemctl is-active --quiet netifay.service 2>/dev/null; then
            echo -e " Panel: ${G}running${N}  ($(python3 "$APP" --version 2>/dev/null || echo installed))"
        elif [[ -f "$APP" ]]; then echo -e " Panel: ${R}stopped${N}"
        else echo -e " Panel: ${Y}not installed${N}"; fi
        if [[ -f "$CONF" ]]; then
            is_public && echo -e " Web access from outside: ${Y}ON${N}" || echo -e " Web access from outside: ${G}OFF${N}"
            [[ -n "$(conf_get cert '')" ]] && echo -e " HTTPS: ${G}ON${N}" || echo -e " HTTPS: ${R}OFF${N}"
        fi
        echo
        echo " 1) Install / Update from GitHub"
        echo " 2) Show panel URL"
        echo " 3) Reset username / password"
        echo " 4) Restart panel"
        echo " 5) Panel logs"
        echo " 6) Uninstall panel"
        echo " 7) Web access from outside ON/OFF"
        echo " 8) HTTPS ON/OFF"
        echo " 0) Exit"
        echo
        read -p " Choice: " c
        case "$c" in
            1) install_panel ;;
            2) [[ -f "$CONF" ]] && show_url || echo "Not installed" ;;
            3) reset_password ;;
            4) systemctl restart netifay.service && echo -e "${G}Restarted${N}" ;;
            5) journalctl -u netifay.service -n 40 --no-pager ;;
            6) uninstall_panel ;;
            7) toggle_external ;;
            8) toggle_https ;;
            0) exit 0 ;;
            *) echo "Invalid" ;;
        esac
        echo; read -p " Press Enter to continue..." _
    done
}

# First run (not installed yet): install straight away, then show the menu.
if [[ ! -f "$APP" ]]; then
    banner
    install_panel
    echo; read -p " Press Enter to open the menu..." _
fi
menu
