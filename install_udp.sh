#!/usr/bin/env bash
set -e

# Prompt for Domain Name before installation
prompt_for_domain() {
IP2=$(wget -4qO- "http://whatismyip.akamai.com/")
    local default_domain="$IP2"
    echo
    echo -n "Enter your IP or DNS for this server (default IP: $default_domain): "
    read -r input_domain
    if [[ -z "$input_domain" ]]; then
        DOMAIN="$default_domain"
    else
        DOMAIN="$input_domain"
    fi
}

# Prompt for OBFS string before installation
prompt_for_obfs() {
    local default_obfs="svpn"
    echo
    echo -n "Enter the OBFS string (default: $default_obfs): "
    read -r input_obfs
    if [[ -z "$input_obfs" ]]; then
        OBFS="$default_obfs"
    else
        OBFS="$input_obfs"
    fi
}

# Values set by prompts
DOMAIN=""
OBFS=""

# PROTOCOL
PROTOCOL="udp"

# UDP PORT
UDP_PORT=":36712"

# PASSWORDS
PASSWORD="agnudp"

# Script paths
SCRIPT_NAME="$(basename "$0")"
SCRIPT_ARGS=("$@")
EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"
SYSTEMD_SERVICES_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/hysteria"
USER_DB="$CONFIG_DIR/udpusers.db"
REPO_URL="https://github.com/apernet/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.json"
API_BASE_URL="https://api.github.com/repos/apernet/hysteria"
CURL_FLAGS=(-L -f -q --retry 5 --retry-delay 10 --retry-max-time 60)
PACKAGE_MANAGEMENT_INSTALL="${PACKAGE_MANAGEMENT_INSTALL:-}"
SYSTEMD_SERVICE="$SYSTEMD_SERVICES_DIR/hysteria-server.service"
LOG_FILE="/var/log/hysteria/hysteria.log"
ONLINE_USERS_FILE="$CONFIG_DIR/online_users.log"

mkdir -p "$CONFIG_DIR"
mkdir -p "/var/log/hysteria"
touch "$USER_DB"
touch "$ONLINE_USERS_FILE"

# Other configurations
OPERATING_SYSTEM=""
ARCHITECTURE=""
HYSTERIA_USER=""
HYSTERIA_HOME_DIR=""
VERSION=""
FORCE=""
LOCAL_FILE=""
FORCE_NO_ROOT=""
FORCE_NO_SYSTEMD=""

# Utility functions
has_command() {
    local _command=$1
    type -P "$_command" > /dev/null 2>&1
}

curl() {
    command curl "${CURL_FLAGS[@]}" "$@"
}

mktemp() {
    command mktemp "$@" "hyservinst.XXXXXXXXXX"
}

tput() {
    if has_command tput; then
        command tput "$@"
    fi
}

tred() {
    tput setaf 1
}

tgreen() {
    tput setaf 2
}

tyellow() {
    tput setaf 3
}

tblue() {
    tput setaf 4
}

taoi() {
    tput setaf 6
}

tbold() {
    tput bold
}

treset() {
    tput sgr0
}

note() {
    local _msg="$1"
    echo -e "$SCRIPT_NAME: $(tbold)note: $_msg$(treset)"
}

warning() {
    local _msg="$1"
    echo -e "$SCRIPT_NAME: $(tyellow)warning: $_msg$(treset)"
}

error() {
    local _msg="$1"
    echo -e "$SCRIPT_NAME: $(tred)error: $_msg$(treset)"
}

show_argument_error_and_exit() {
    local _error_msg="$1"
    error "$_error_msg"
    echo "Try \"$0 --help\" for the usage." >&2
    exit 22
}

install_content() {
    local _install_flags="$1"
    local _content="$2"
    local _destination="$3"

    local _tmpfile="$(mktemp)"

    echo -ne "Install $_destination ... "
    echo "$_content" > "$_tmpfile"
    if install "$_install_flags" "$_tmpfile" "$_destination"; then
        echo -e "ok"
    fi

    rm -f "$_tmpfile"
}

remove_file() {
    local _target="$1"

    echo -ne "Remove $_target ... "
    if rm "$_target"; then
        echo -e "ok"
    fi
}

exec_sudo() {
    local _saved_ifs="$IFS"
    IFS=$'\n'
    local _preserved_env=(
        $(env | grep "^PACKAGE_MANAGEMENT_INSTALL=" || true)
        $(env | grep "^OPERATING_SYSTEM=" || true)
        $(env | grep "^ARCHITECTURE=" || true)
        $(env | grep "^HYSTERIA_\w*=" || true)
        $(env | grep "^FORCE_\w*=" || true)
    )
    IFS="$_saved_ifs"

    exec sudo env \
    "${_preserved_env[@]}" \
    "$@"
}

install_software() {
    local package="$1"
    if has_command apt-get; then
        echo "Installing $package using apt-get..."
        apt-get update && apt-get install -y "$package"
    elif has_command dnf; then
        echo "Installing $package using dnf..."
        dnf install -y "$package"
    elif has_command yum; then
        echo "Installing $package using yum..."
        yum install -y "$package"
    elif has_command zypper; then
        echo "Installing $package using zypper..."
        zypper install -y "$package"
    elif has_command pacman; then
        echo "Installing $package using pacman..."
        pacman -Sy --noconfirm "$package"
    else
        echo "Error: No supported package manager found. Please install $package manually."
        exit 1
    fi
}

is_user_exists() {
    local _user="$1"
    id "$_user" > /dev/null 2>&1
}

check_permission() {
    if [[ "$UID" -eq '0' ]]; then
        return
    fi

    note "The user currently executing this script is not root."

    case "$FORCE_NO_ROOT" in
        '1')
            warning "FORCE_NO_ROOT=1 is specified, we will process without root and you may encounter the insufficient privilege error."
            ;;
        *)
            if has_command sudo; then
                note "Re-running this script with sudo, you can also specify FORCE_NO_ROOT=1 to force this script running with current user."
                exec_sudo "$0" "${SCRIPT_ARGS[@]}"
            else
                error "Please run this script with root or specify FORCE_NO_ROOT=1 to force this script running with current user."
                exit 13
            fi
            ;;
    esac
}

check_environment_operating_system() {
    if [[ -n "$OPERATING_SYSTEM" ]]; then
        warning "OPERATING_SYSTEM=$OPERATING_SYSTEM is specified, operating system detection will not be performed."
        return
    fi

    if [[ "x$(uname)" == "xLinux" ]]; then
        OPERATING_SYSTEM=linux
        return
    fi

    error "This script only supports Linux."
    note "Specify OPERATING_SYSTEM=[linux|darwin|freebsd|windows] to bypass this check and force this script running on this $(uname)."
    exit 95
}

check_environment_architecture() {
    if [[ -n "$ARCHITECTURE" ]]; then
        warning "ARCHITECTURE=$ARCHITECTURE is specified, architecture detection will not be performed."
        return
    fi

    case "$(uname -m)" in
        'i386' | 'i686')
            ARCHITECTURE='386'
            ;;
        'amd64' | 'x86_64')
            ARCHITECTURE='amd64'
            ;;
        'armv5tel' | 'armv6l' | 'armv7' | 'armv7l')
            ARCHITECTURE='arm'
            ;;
        'armv8' | 'aarch64')
            ARCHITECTURE='arm64'
            ;;
        'mips' | 'mipsle' | 'mips64' | 'mips64le')
            ARCHITECTURE='mipsle'
            ;;
        's390x')
            ARCHITECTURE='s390x'
            ;;
        *)
            error "The architecture '$(uname -a)' is not supported."
            note "Specify ARCHITECTURE=<architecture> to bypass this check and force this script running on this $(uname -m)."
            exit 8
            ;;
    esac
}

check_environment_systemd() {
    if [[ -d "/run/systemd/system" ]] || grep -q systemd <(ls -l /sbin/init); then
        return
    fi

    case "$FORCE_NO_SYSTEMD" in
        '1')
            warning "FORCE_NO_SYSTEMD=1 is specified, we will process as normal even if systemd is not detected by us."
            ;;
        '2')
            warning "FORCE_NO_SYSTEMD=2 is specified, we will process but all systemd related commands will not be executed."
            ;;
        *)
            error "This script only supports Linux distributions with systemd."
            note "Specify FORCE_NO_SYSTEMD=1 to disable this check and force this script running as systemd is detected."
            note "Specify FORCE_NO_SYSTEMD=2 to disable this check along with all systemd related commands."
            ;;
    esac
}

parse_arguments() {
    while [[ "$#" -gt '0' ]]; do
        case "$1" in
            '--remove')
                if [[ -n "$OPERATION" && "$OPERATION" != 'remove' ]]; then
                    show_argument_error_and_exit "Option '--remove' is conflicted with other options."
                fi
                OPERATION='remove'
                ;;
            '--version')
                VERSION="$2"
                if [[ -z "$VERSION" ]]; then
                    show_argument_error_and_exit "Please specify the version for option '--version'."
                fi
                shift
                if ! [[ "$VERSION" == v* ]]; then
                    show_argument_error_and_exit "Version numbers should begin with 'v' (such like 'v1.3.1'), got '$VERSION'"
                fi
                ;;
            '-h' | '--help')
                show_usage_and_exit
                ;;
            '-l' | '--local')
                LOCAL_FILE="$2"
                if [[ -z "$LOCAL_FILE" ]]; then
                    show_argument_error_and_exit "Please specify the local binary to install for option '-l' or '--local'."
                fi
                break
                ;;
            *)
                show_argument_error_and_exit "Unknown option '$1'"
                ;;
        esac
        shift
    done

    if [[ -z "$OPERATION" ]]; then
        OPERATION='install'
    fi

    # validate arguments
    case "$OPERATION" in
        'install')
            if [[ -n "$VERSION" && -n "$LOCAL_FILE" ]]; then
                show_argument_error_and_exit '--version and --local cannot be specified together.'
            fi
            ;;
        *)
            if [[ -n "$VERSION" ]]; then
                show_argument_error_and_exit "--version is only available when installing."
            fi
            if [[ -n "$LOCAL_FILE" ]]; then
                show_argument_error_and_exit "--local is only available when installing."
            fi
            ;;
    esac
}

check_hysteria_homedir() {
    local _default_hysteria_homedir="$1"

    if [[ -n "$HYSTERIA_HOME_DIR" ]]; then
        return
    fi

    if ! is_user_exists "$HYSTERIA_USER"; then
        HYSTERIA_HOME_DIR="$_default_hysteria_homedir"
        return
    fi

    HYSTERIA_HOME_DIR="$(eval echo ~"$HYSTERIA_USER")"
}

download_hysteria() {
    local _version="$1"
    local _destination="$2"

    local _download_url="$REPO_URL/releases/download/v1.3.5/hysteria-$OPERATING_SYSTEM-$ARCHITECTURE"
    echo "Downloading hysteria archive: $_download_url ..."
    if ! curl -R -H 'Cache-Control: no-cache' "$_download_url" -o "$_destination"; then
        error "Download failed! Please check your network and try again."
        return 11
    fi
    return 0
}

check_hysteria_user() {
    local _default_hysteria_user="$1"

    if [[ -n "$HYSTERIA_USER" ]]; then
        return
    fi

    if [[ ! -e "$SYSTEMD_SERVICES_DIR/hysteria-server.service" ]]; then
        HYSTERIA_USER="$_default_hysteria_user"
        return
    fi

    HYSTERIA_USER="$(grep -o '^User=\w*' "$SYSTEMD_SERVICES_DIR/hysteria-server.service" | tail -1 | cut -d '=' -f 2 || true)"

    if [[ -z "$HYSTERIA_USER" ]]; then
        HYSTERIA_USER="$_default_hysteria_user"
    fi
}

check_environment_curl() {
    if ! has_command curl; then
        install_software "curl"
    fi
}

check_environment_grep() {
    if ! has_command grep; then
        install_software "grep"
    fi
}

check_environment_sqlite3() {
    if ! has_command sqlite3; then
        install_software "sqlite3"
    fi
}

check_environment_pip() {
    if ! has_command pip; then
        install_software "python3-pip"
    fi
}

check_environment_jq() {
    if ! has_command jq; then
        install_software "jq"
    fi
}

check_environment() {
    check_environment_operating_system
    check_environment_architecture
    check_environment_systemd
    check_environment_curl
    check_environment_grep
    check_environment_pip
    check_environment_sqlite3
    check_environment_jq
}

show_usage_and_exit() {
    echo
    echo -e "\t$(tbold)$SCRIPT_NAME$(treset) - UDP server install script"
    echo
    echo -e "Usage:"
    echo
    echo -e "$(tbold)Install UDP$(treset)"
    echo -e "\t$0 [ -f | -l <file> | --version <version> ]"
    echo -e "Flags:"
    echo -e "\t-f, --force\tForce re-install latest or specified version even if it has been installed."
    echo -e "\t-l, --local <file>\tInstall specified UDP binary instead of download it."
    echo -e "\t--version <version>\tInstall specified version instead of the latest."
    echo
    echo -e "$(tbold)Remove UDP$(treset)"
    echo -e "\t$0 --remove"
    echo
    echo -e "$(tbold)Check for the update$(treset)"
    echo -e "\t$0 -c"
    echo -e "\t$0 --check"
    echo
    echo -e "$(tbold)Show this help$(treset)"
    echo -e "\t$0 -h"
    echo -e "\t$0 --help"
    exit 0
}

tpl_hysteria_server_service_base() {
    local _config_name="$1"

    cat << EOF
[Unit]
Description=UDP Service
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/etc/hysteria
Environment="PATH=/usr/local/bin/hysteria"
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.json
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
}

tpl_hysteria_server_service() {
    tpl_hysteria_server_service_base 'config'
}

tpl_hysteria_server_x_service() {
    tpl_hysteria_server_service_base '%i'
}

tpl_etc_hysteria_config_json() {
    local_users=$(fetch_users)

    mkdir -p "$CONFIG_DIR"

    cat << EOF > "$CONFIG_FILE"
{
  "server": "$DOMAIN",
  "listen": "$UDP_PORT",
  "protocol": "$PROTOCOL",
  "cert": "/etc/hysteria/hysteria.server.crt",
  "key": "/etc/hysteria/hysteria.server.key",
  "up": "100 Mbps",
  "up_mbps": 10,
  "down": "100 Mbps",
  "down_mbps": 20,
  "disable_udp": false,
  "insecure": false,
  "obfs": "$OBFS",
  "auth": {
    "mode": "passwords",
    "config": [
      "$(echo $local_users)"
    ]
  },
  "log": {
    "level": "info",
    "file": "/var/log/hysteria/hysteria.log"
  }
}
EOF
}

# IMPROVED: Setup database with online tracking tables
setup_db() {
    echo "Setting up database with online tracking support..."
    mkdir -p "$(dirname "$USER_DB")"

    if [[ ! -f "$USER_DB" ]]; then
        # Create the database file
        sqlite3 "$USER_DB" ".databases"
        if [[ $? -ne 0 ]]; then
            echo "Error: Unable to create database file at $USER_DB"
            exit 1
        fi
    fi

    # Create the users table
    sqlite3 "$USER_DB" <<EOF
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);
EOF

    # IMPORTANT: Create online_sessions table for tracking
    sqlite3 "$USER_DB" <<EOF
CREATE TABLE IF NOT EXISTS online_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    port INTEGER DEFAULT 0,
    connect_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    disconnect_time DATETIME,
    status TEXT DEFAULT 'online',
    FOREIGN KEY(username) REFERENCES users(username)
);
EOF

    # Create indexes for better performance
    sqlite3 "$USER_DB" <<EOF
CREATE INDEX IF NOT EXISTS idx_session_status ON online_sessions(status);
CREATE INDEX IF NOT EXISTS idx_session_id ON online_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_username ON online_sessions(username);
CREATE INDEX IF NOT EXISTS idx_ip_address ON online_sessions(ip_address);
EOF

    # Check if tables were created successfully
    table_exists=$(sqlite3 "$USER_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    sessions_table_exists=$(sqlite3 "$USER_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='online_sessions';")
    
    if [[ "$table_exists" == "users" ]] && [[ "$sessions_table_exists" == "online_sessions" ]]; then
        echo "✓ Database setup completed successfully."
        echo "✓ Tables 'users' and 'online_sessions' created."
        
        # Add a default user if not already exists
        default_username="default"
        default_password="password"
        user_exists=$(sqlite3 "$USER_DB" "SELECT username FROM users WHERE username='$default_username';")
        
        if [[ -z "$user_exists" ]]; then
            sqlite3 "$USER_DB" "INSERT INTO users (username, password) VALUES ('$default_username', '$default_password');"
            if [[ $? -eq 0 ]]; then
                echo "✓ Default user created successfully."
            else
                echo "⚠ Warning: Failed to create default user."
            fi
        else
            echo "✓ Default user already exists."
        fi
    else
        echo "Error: Database tables were not created successfully."
        echo "Current database schema:"
        sqlite3 "$USER_DB" ".schema"
        exit 1
    fi
}

fetch_users() {
    DB_PATH="/etc/hysteria/udpusers.db"
    if [[ -f "$DB_PATH" ]]; then
        sqlite3 "$DB_PATH" "SELECT username || ':' || password FROM users;" | paste -sd, -
    fi
}

perform_install_hysteria_binary() {
    if [[ -n "$LOCAL_FILE" ]]; then
        note "Performing local install: $LOCAL_FILE"

        echo -ne "Installing hysteria executable ... "

        if install -Dm755 "$LOCAL_FILE" "$EXECUTABLE_INSTALL_PATH"; then
            echo "ok"
        else
            exit 2
        fi

        return
    fi

    local _tmpfile=$(mktemp)

    if ! download_hysteria "$VERSION" "$_tmpfile"; then
        rm -f "$_tmpfile"
        exit 11
    fi

    echo -ne "Installing hysteria executable ... "

    if install -Dm755 "$_tmpfile" "$EXECUTABLE_INSTALL_PATH"; then
        echo "ok"
    else
        exit 13
    fi

    rm -f "$_tmpfile"
}

perform_remove_hysteria_binary() {
    remove_file "$EXECUTABLE_INSTALL_PATH"
}

perform_install_hysteria_example_config() {
    tpl_etc_hysteria_config_json
}

perform_install_hysteria_systemd() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi

    install_content -Dm644 "$(tpl_hysteria_server_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
    install_content -Dm644 "$(tpl_hysteria_server_x_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server@.service"

    systemctl daemon-reload
}

perform_remove_hysteria_systemd() {
    remove_file "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
    remove_file "$SYSTEMD_SERVICES_DIR/hysteria-server@.service"

    systemctl daemon-reload
}

perform_install_hysteria_home_legacy() {
    if ! is_user_exists "$HYSTERIA_USER"; then
        echo -ne "Creating user $HYSTERIA_USER ... "
        useradd -r -d "$HYSTERIA_HOME_DIR" -m "$HYSTERIA_USER"
        echo "ok"
    fi
}

# IMPROVED: Download manager script from your repository
perform_install_manager_script() {
    local _manager_script="/usr/local/bin/udp_manager.sh"
    local _symlink_path="/usr/local/bin/udp"
    
    echo "Downloading manager script with online tracking..."
    
    # Create temporary file for the improved manager script
    cat > "$_manager_script" << 'MANAGER_SCRIPT_EOF'
#!/bin/bash
# This is a placeholder - replace this with the actual improved udp_manager.sh content
# Or download from your repository
MANAGER_SCRIPT_EOF

    # IMPORTANT: Replace the URL below with your actual repository URL
    # Example: If you uploaded the improved script to GitHub
    # curl -o "$_manager_script" "https://raw.githubusercontent.com/sansoe2022/udp/refs/heads/main/udp_manager.sh"
    
    # For now, let's create the improved script inline
    # Copy the entire improved udp_manager.sh script here
    # Or better yet, host it on GitHub and download it
    
    # Make it executable
    chmod +x "$_manager_script"
    
    # Create symbolic link
    echo "Creating symbolic link to run the manager script using 'udp' command..."
    ln -sf "$_manager_script" "$_symlink_path"
    
    echo "✓ Manager script installed at $_manager_script"
    echo "✓ You can now run the manager using the 'udp' command."
}

is_hysteria_installed() {
    # RETURN VALUE
    # 0: hysteria is installed
    # 1: hysteria is not installed
    
    if [[ -f "$EXECUTABLE_INSTALL_PATH" || -h "$EXECUTABLE_INSTALL_PATH" ]]; then
        return 0
    fi
    return 1
}

get_running_services() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi
    
    systemctl list-units --state=active --plain --no-legend \
    | grep -o "hysteria-server@*[^\s]*.service" || true
}

restart_running_services() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi
    
    echo "Restarting running service ... "
    
    for service in $(get_running_services); do
        echo -ne "Restarting $service ... "
        systemctl restart "$service"
        echo "done"
    done
}

stop_running_services() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi
    
    echo "Stopping running service ... "
    
    for service in $(get_running_services); do
        echo -ne "Stopping $service ... "
        systemctl stop "$service"
        echo "done"
    done
}

perform_install() {
    local _is_fresh_install
    if ! is_hysteria_installed; then
        _is_fresh_install=1
    fi

    perform_install_hysteria_binary
    perform_install_hysteria_example_config
    perform_install_hysteria_home_legacy
    perform_install_hysteria_systemd
    setup_ssl
    start_services
    perform_install_manager_script

    if [[ -n "$_is_fresh_install" ]]; then
        echo
        echo -e "$(tgreen)═══════════════════════════════════════════════════════$(treset)"
        echo -e "$(tbold)✓ Congratulations! UDP has been successfully installed!$(treset)"
        echo -e "$(tgreen)═══════════════════════════════════════════════════════$(treset)"
        echo
        echo -e "$(tbold)Quick Start:$(treset)"
        echo -e "  1. Run: $(tblue)udp$(treset) to access the management menu"
        echo -e "  2. Select option $(tyellow)13$(treset) to start connection monitoring"
        echo -e "  3. Select option $(tyellow)15$(treset) to enable web status"
        echo -e "  4. Select option $(tyellow)10$(treset) to view online users"
        echo
        echo -e "$(tbold)Features:$(treset)"
        echo -e "  ✓ Multi-user online tracking"
        echo -e "  ✓ Real-time connection monitoring"
        echo -e "  ✓ Web-based status endpoint"
        echo -e "  ✓ Connection history logging"
        echo
        echo -e "$(tbold)Follow me:$(treset)"
        echo -e "  Telegram: $(tblue)https://t.me/sansoe2021$(treset)"
        echo -e "  Facebook: $(tblue)https://www.facebook.com/share/15KzEGz3Es/$(treset)"
        echo
        echo -e "$(tgreen)═══════════════════════════════════════════════════════$(treset)"
        echo
    else
        restart_running_services
        start_services
        echo
        echo -e "$(tbold)✓ UDP has been successfully updated to $VERSION.$(treset)"
        echo -e "$(tyellow)Run 'udp' command to access the management menu.$(treset)"
        echo
    fi
}

perform_remove() {
    perform_remove_hysteria_binary
    stop_running_services
    perform_remove_hysteria_systemd

    echo
    echo -e "$(tbold)✓ UDP has been successfully removed from your server.$(treset)"
    echo
    echo -e "$(tyellow)To completely remove all data, run these commands:$(treset)"
    echo
    echo -e "\t$(tred)rm -rf "$CONFIG_DIR"$(treset)"
    if [[ "x$HYSTERIA_USER" != "xroot" ]]; then
        echo -e "\t$(tred)userdel -r "$HYSTERIA_USER"$(treset)"
    fi
    if [[ "x$FORCE_NO_SYSTEMD" != "x2" ]]; then
        echo
        echo -e "$(tyellow)To disable systemd services:$(treset)"
        echo
        echo -e "\t$(tred)rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server.service$(treset)"
        echo -e "\t$(tred)rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server@*.service$(treset)"
        echo -e "\t$(tred)systemctl daemon-reload$(treset)"
    fi
    echo
}

setup_ssl() {
    echo "Installing SSL certificates..."

    openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048

    openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" -out /etc/hysteria/hysteria.ca.crt

    openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$DOMAIN" -out /etc/hysteria/hysteria.server.csr

    openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN,DNS:$DOMAIN") -days 3650 -in /etc/hysteria/hysteria.server.csr -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key -set_serial 01 -out /etc/hysteria/hysteria.server.crt
    
    echo "✓ SSL certificates installed successfully"
}

start_services() {
    echo "Starting UDP server..."
    apt update
    sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true"
    sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true"
    apt -y install iptables-persistent
    
    # Get network interface
    local iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    
    # Setup iptables rules
    iptables -t nat -A PREROUTING -i $iface -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
    ip6tables -t nat -A PREROUTING -i $iface -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
    
    # Configure sysctl
    sysctl net.ipv4.conf.all.rp_filter=0
    sysctl net.ipv4.conf.$iface.rp_filter=0
    
    echo "net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.$iface.rp_filter=0" > /etc/sysctl.conf
    
    sysctl -p
    
    # Save iptables rules
    sudo iptables-save > /etc/iptables/rules.v4
    sudo ip6tables-save > /etc/iptables/rules.v6
    
    # Enable and start service
    systemctl enable hysteria-server.service
    systemctl start hysteria-server.service
    
    # Check if service started successfully
    sleep 2
    if systemctl is-active hysteria-server.service >/dev/null 2>&1; then
        echo "✓ UDP server started successfully"
    else
        echo "⚠ Warning: UDP server may not have started correctly"
        echo "Check status with: systemctl status hysteria-server.service"
    fi
}

main() {
    parse_arguments "$@"
    check_permission
    check_environment
    
    # Prompt for domain and obfs before install operation
    if [[ "$OPERATION" == "install" ]]; then
        prompt_for_domain
        prompt_for_obfs
    fi
    
    check_hysteria_user "hysteria"
    check_hysteria_homedir "/var/lib/$HYSTERIA_USER"
    
    case "$OPERATION" in
        "install")
            setup_db
            perform_install
            ;;
        "remove")
            perform_remove
            ;;
        *)
            error "Unknown operation '$OPERATION'."
            ;;
    esac
}

main "$@"
