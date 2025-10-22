#!/bin/bash

CONFIG_DIR="/etc/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.json"
USER_DB="$CONFIG_DIR/udpusers.db"
SYSTEMD_SERVICE="/etc/systemd/system/hysteria-server.service"
LOG_FILE="/var/log/hysteria/hysteria.log"
ONLINE_USERS_FILE="$CONFIG_DIR/online_users.log"
WEB_DIR="/var/www/html/udpserver"
WEB_STATUS_FILE="$WEB_DIR/online"
WEB_SERVICE_FILE="/etc/systemd/system/udp-web-status.service"
WEB_STATUS_ENABLED="$CONFIG_DIR/web_status_enabled"
TRACKER_PID_FILE="$CONFIG_DIR/.tracker_pid"

mkdir -p "$CONFIG_DIR"
mkdir -p "/var/log/hysteria"
mkdir -p "$WEB_DIR"
touch "$USER_DB"
touch "$ONLINE_USERS_FILE"

# Initialize database with improved schema
init_database() {
    sqlite3 "$USER_DB" "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT);"
    sqlite3 "$USER_DB" "CREATE TABLE IF NOT EXISTS online_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE,
        username TEXT,
        ip_address TEXT,
        port INTEGER,
        connect_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        disconnect_time DATETIME,
        status TEXT DEFAULT 'online',
        FOREIGN KEY(username) REFERENCES users(username)
    );"
    
    # Create index for faster queries
    sqlite3 "$USER_DB" "CREATE INDEX IF NOT EXISTS idx_session_status ON online_sessions(status);"
    sqlite3 "$USER_DB" "CREATE INDEX IF NOT EXISTS idx_session_id ON online_sessions(session_id);"
}

fetch_users() {
    if [[ -f "$USER_DB" ]]; then
        sqlite3 "$USER_DB" "SELECT username || ':' || password FROM users;" | paste -sd, -
    fi
}

update_userpass_config() {
    local users=$(fetch_users)
    local user_array=$(echo "$users" | awk -F, '{for(i=1;i<=NF;i++) printf "\"" $i "\"" ((i==NF) ? "" : ",")}')
    jq ".auth.config = [$user_array]" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

# Update web status file with online count - with file locking
update_web_status() {
    if [[ -f "$WEB_STATUS_ENABLED" ]]; then
        (
            flock -x 200
            local online_count=$(sqlite3 "$USER_DB" "SELECT COUNT(DISTINCT session_id) FROM online_sessions WHERE status='online';" 2>/dev/null || echo "0")
            echo "$online_count" > "$WEB_STATUS_FILE"
            chmod 644 "$WEB_STATUS_FILE" 2>/dev/null
        ) 200>/var/lock/udp_web_status.lock
    fi
}

# IMPROVED: Enhanced connection tracking with better log parsing
track_connections() {
    echo "Starting enhanced connection tracker..."
    
    # Clear stale connections on startup
    sqlite3 "$USER_DB" "UPDATE online_sessions SET status='offline', disconnect_time=datetime('now') WHERE status='online';"
    update_web_status
    
    journalctl -u hysteria-server -f -n 0 --no-pager 2>/dev/null | while read -r line; do
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        
        # Match various connection patterns in Hysteria logs
        if echo "$line" | grep -qiE "client.*connect|new.*connection|accept.*client|session.*start"; then
            # Extract IP and port with multiple patterns
            local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
            local port=$(echo "$line" | grep -oE ':([0-9]{4,5})' | head -1 | tr -d ':')
            
            if [[ -n "$ip" ]]; then
                # Create unique session ID
                local session_id="${ip}_${port}_$(date +%s%N)"
                local username=$(echo "$line" | grep -oP 'user[=:]?\s*\K[^\s,]+' | head -1)
                
                # If no username found in log, use IP-based username
                if [[ -z "$username" || "$username" == "null" ]]; then
                    username="user_${ip}"
                fi
                
                # Use flock to prevent race conditions
                (
                    flock -x 200
                    sqlite3 "$USER_DB" "INSERT INTO online_sessions (session_id, username, ip_address, port, connect_time, status) VALUES ('$session_id', '$username', '$ip', ${port:-0}, '$timestamp', 'online');" 2>/dev/null
                    echo "$timestamp - $username ($ip:${port:-unknown}) connected [Session: $session_id]" >> "$ONLINE_USERS_FILE"
                ) 200>/var/lock/udp_sessions.lock
                
                update_web_status
                echo "[CONNECT] $username from $ip:${port:-unknown} at $timestamp"
            fi
            
        elif echo "$line" | grep -qiE "client.*disconnect|connection.*clos|TCP EOF|session.*end|client.*left"; then
            local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
            local port=$(echo "$line" | grep -oE ':([0-9]{4,5})' | head -1 | tr -d ':')
            
            if [[ -n "$ip" ]]; then
                # Use flock to prevent race conditions
                (
                    flock -x 200
                    # Find the most recent online session for this IP
                    local session_id=$(sqlite3 "$USER_DB" "SELECT session_id FROM online_sessions WHERE ip_address='$ip' AND status='online' ORDER BY connect_time DESC LIMIT 1;" 2>/dev/null)
                    
                    if [[ -n "$session_id" ]]; then
                        sqlite3 "$USER_DB" "UPDATE online_sessions SET disconnect_time='$timestamp', status='offline' WHERE session_id='$session_id';" 2>/dev/null
                        local username=$(sqlite3 "$USER_DB" "SELECT username FROM online_sessions WHERE session_id='$session_id';" 2>/dev/null)
                        echo "$timestamp - $username ($ip:${port:-unknown}) disconnected [Session: $session_id]" >> "$ONLINE_USERS_FILE"
                        echo "[DISCONNECT] $username from $ip:${port:-unknown} at $timestamp"
                    fi
                ) 200>/var/lock/udp_sessions.lock
                
                update_web_status
            fi
        fi
    done
}

# IMPROVED: Better netstat-based tracking for systems without detailed logs
track_netstat_connections() {
    echo -e "\e[1;34mStarting netstat-based connection tracking...\e[0m"
    
    local hysteria_port=$(jq -r '.listen' "$CONFIG_FILE" | cut -d: -f2)
    if [[ -z "$hysteria_port" || "$hysteria_port" == "null" ]]; then
        echo -e "\e[1;31mCannot determine Hysteria port from config\e[0m"
        return
    fi
    
    echo "Monitoring port: $hysteria_port"
    
    # Declare associative array for tracking seen connections
    declare -A seen_connections
    
    while true; do
        if [[ -f "$WEB_STATUS_ENABLED" ]]; then
            # Get current connections
            local current_conns=$(ss -Hun 2>/dev/null | grep ":$hysteria_port " || netstat -un 2>/dev/null | grep ":$hysteria_port ")
            
            # Clear tracking array for new scan
            declare -A active_connections
            
            # Process current connections
            while IFS= read -r conn_line; do
                if [[ -n "$conn_line" ]]; then
                    # Extract foreign address
                    local foreign=$(echo "$conn_line" | awk '{print $5}' | head -1)
                    if [[ -n "$foreign" ]]; then
                        local ip=$(echo "$foreign" | cut -d: -f1)
                        local port=$(echo "$foreign" | cut -d: -f2)
                        local conn_key="${ip}_${port}"
                        
                        active_connections[$conn_key]=1
                        
                        # New connection detected
                        if [[ -z "${seen_connections[$conn_key]}" ]]; then
                            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                            local session_id="${ip}_${port}_$(date +%s%N)"
                            local username="user_${ip}"
                            
                            (
                                flock -x 200
                                sqlite3 "$USER_DB" "INSERT INTO online_sessions (session_id, username, ip_address, port, connect_time, status) VALUES ('$session_id', '$username', '$ip', $port, '$timestamp', 'online');" 2>/dev/null
                                echo "$timestamp - $username ($ip:$port) connected [netstat]" >> "$ONLINE_USERS_FILE"
                            ) 200>/var/lock/udp_sessions.lock
                            
                            seen_connections[$conn_key]=$session_id
                            echo "[NETSTAT-CONNECT] $username from $ip:$port"
                        fi
                    fi
                fi
            done <<< "$current_conns"
            
            # Check for disconnected sessions
            for conn_key in "${!seen_connections[@]}"; do
                if [[ -z "${active_connections[$conn_key]}" ]]; then
                    local session_id="${seen_connections[$conn_key]}"
                    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                    
                    (
                        flock -x 200
                        sqlite3 "$USER_DB" "UPDATE online_sessions SET disconnect_time='$timestamp', status='offline' WHERE session_id='$session_id' AND status='online';" 2>/dev/null
                        local username=$(sqlite3 "$USER_DB" "SELECT username FROM online_sessions WHERE session_id='$session_id';" 2>/dev/null)
                        echo "$timestamp - $username disconnected [netstat]" >> "$ONLINE_USERS_FILE"
                    ) 200>/var/lock/udp_sessions.lock
                    
                    unset seen_connections[$conn_key]
                    echo "[NETSTAT-DISCONNECT] Session $session_id"
                fi
            done
            
            # Update web status
            update_web_status
        fi
        
        sleep 5
    done
}

show_online_users() {
    echo -e "\n\e[1;34m=== Currently Online Users ===\e[0m"
    
    # Show online count prominently
    local online_count=$(sqlite3 "$USER_DB" "SELECT COUNT(DISTINCT session_id) FROM online_sessions WHERE status='online';" 2>/dev/null || echo "0")
    echo -e "\e[1;32m╔══════════════════════════════════╗\e[0m"
    echo -e "\e[1;32m║     ONLINE USERS COUNT: $(printf '%2d' $online_count)       ║\e[0m"
    echo -e "\e[1;32m╚══════════════════════════════════╝\e[0m"
    
    if [[ $online_count -gt 0 ]]; then
        echo -e "\n\e[1;36mSession ID\t\t\tUsername\tIP Address\tPort\tConnect Time\e[0m"
        echo -e "\e[1;36m----------\t\t\t--------\t----------\t----\t------------\e[0m"
        sqlite3 "$USER_DB" "SELECT session_id, username, ip_address, port, connect_time FROM online_sessions WHERE status='online' ORDER BY connect_time DESC;" | while IFS='|' read -r session_id username ip port connect_time; do
            printf "\e[1;37m%-25s\t%-12s\t%-15s\t%-6s\t%s\e[0m\n" "${session_id:0:24}..." "$username" "$ip" "$port" "$connect_time"
        done
    else
        echo -e "\e[1;33mNo users currently online.\e[0m"
    fi
    
    # Show web status info
    if [[ -f "$WEB_STATUS_ENABLED" ]]; then
        local server_ip=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        echo -e "\n\e[1;34m=== Web Status Endpoint ===\e[0m"
        echo -e "\e[1;36mURL: http://$server_ip:81/udpserver/online\e[0m"
        echo -e "\e[1;37mReturns: $online_count\e[0m"
    fi
}

# Enable web status endpoint
enable_web_status() {
    echo -e "\n\e[1;34mEnabling web status endpoint...\e[0m"
    
    # Install nginx if not installed
    if ! command -v nginx &> /dev/null; then
        echo -e "\e[1;33mInstalling nginx...\e[0m"
        apt update && apt install -y nginx
    fi
    
    # Create nginx config for udp status
    cat > /etc/nginx/sites-available/udp-status << 'EOF'
server {
    listen 81;
    server_name _;
    root /var/www/html;
    
    location /udpserver/online {
        default_type text/plain;
        add_header Access-Control-Allow-Origin *;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        try_files /udpserver/online =404;
    }
    
    location /udpserver/ {
        deny all;
        return 403;
    }
}
EOF
    
    # Enable the site
    ln -sf /etc/nginx/sites-available/udp-status /etc/nginx/sites-enabled/
    
    # Test nginx config
    nginx -t
    if [[ $? -eq 0 ]]; then
        systemctl reload nginx
        systemctl enable nginx
        
        # Create improved web status update service
        cat > "$WEB_SERVICE_FILE" << 'EOF'
[Unit]
Description=UDP Server Online Status Updater
After=network.target hysteria-server.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do if [[ -f /etc/hysteria/web_status_enabled ]]; then ( flock -x 200; count=$(sqlite3 /etc/hysteria/udpusers.db "SELECT COUNT(DISTINCT session_id) FROM online_sessions WHERE status='\''online'\'';" 2>/dev/null || echo "0"); echo "$count" > /var/www/html/udpserver/online; chmod 644 /var/www/html/udpserver/online; ) 200>/var/lock/udp_web_status.lock; fi; sleep 3; done'
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
        
        # Enable and start the service
        systemctl daemon-reload
        systemctl enable udp-web-status
        systemctl restart udp-web-status
        
        # Mark web status as enabled
        touch "$WEB_STATUS_ENABLED"
        
        # Initialize with current count
        update_web_status
        
        local server_ip=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        echo -e "\e[1;32mWeb status endpoint enabled successfully!\e[0m"
        echo -e "\e[1;36mAccess URL: http://$server_ip:81/udpserver/online\e[0m"
        echo -e "\e[1;33mThis will show the number of online users (updates every 3 seconds)\e[0m"
    else
        echo -e "\e[1;31mNginx configuration error. Please check manually.\e[0m"
    fi
}

# Disable web status endpoint
disable_web_status() {
    echo -e "\n\e[1;34mDisabling web status endpoint...\e[0m"
    
    systemctl stop udp-web-status 2>/dev/null
    systemctl disable udp-web-status 2>/dev/null
    rm -f "$WEB_SERVICE_FILE"
    rm -f /etc/nginx/sites-enabled/udp-status
    rm -f /etc/nginx/sites-available/udp-status
    systemctl reload nginx 2>/dev/null
    rm -f "$WEB_STATUS_ENABLED"
    rm -f "$WEB_STATUS_FILE"
    systemctl daemon-reload
    
    echo -e "\e[1;32mWeb status endpoint disabled successfully!\e[0m"
}

# Enable logging in Hysteria config
enable_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    if [[ -f "$CONFIG_FILE" ]]; then
        jq '.log.level = "info" | .log.file = "/var/log/hysteria/hysteria.log"' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        echo -e "\e[1;32mLogging enabled in configuration\e[0m"
    else
        echo -e "\e[1;31mConfig file not found: $CONFIG_FILE\e[0m"
    fi
}

# IMPROVED: Enhanced start monitoring with method selection
start_monitoring() {
    echo -e "\e[1;34m=== Select Monitoring Method ===\e[0m"
    echo "1. Journald log parsing (recommended for detailed logs)"
    echo "2. Netstat monitoring (recommended for simple counting)"
    echo "3. Both methods (most accurate)"
    echo -n "Select method [1-3]: "
    read -r method_choice
    
    stop_monitoring  # Stop any previous monitoring
    
    case $method_choice in
        1)
            echo -e "\e[1;34mStarting journald-based monitoring...\e[0m"
            (track_connections) &
            echo $! > "$TRACKER_PID_FILE"
            ;;
        2)
            echo -e "\e[1;34mStarting netstat-based monitoring...\e[0m"
            (track_netstat_connections) &
            echo $! > "$TRACKER_PID_FILE"
            ;;
        3)
            echo -e "\e[1;34mStarting both monitoring methods...\e[0m"
            (track_connections) &
            echo $! > "$TRACKER_PID_FILE"
            (track_netstat_connections) &
            echo $! >> "$TRACKER_PID_FILE"
            ;;
        *)
            echo -e "\e[1;31mInvalid choice. Starting journald monitoring as default.\e[0m"
            (track_connections) &
            echo $! > "$TRACKER_PID_FILE"
            ;;
    esac
    
    echo -e "\e[1;32mConnection monitoring started successfully.\e[0m"
    echo -e "\e[1;36mMonitor logs: journalctl -u hysteria-server -f --no-pager\e[0m"
    echo -e "\e[1;36mView online users: Select option 10 from menu\e[0m"
}

# Stop connection monitoring
stop_monitoring() {
    if [[ -f "$TRACKER_PID_FILE" ]]; then
        while IFS= read -r pid; do
            if ps -p "$pid" > /dev/null 2>&1; then
                kill "$pid" 2>/dev/null
                echo -e "\e[1;32mStopped monitoring process (PID $pid).\e[0m"
            fi
        done < "$TRACKER_PID_FILE"
        rm -f "$TRACKER_PID_FILE"
    fi
    
    # Kill any remaining monitoring processes
    pkill -f "track_connections" 2>/dev/null
    pkill -f "track_netstat_connections" 2>/dev/null
    pkill -f "journalctl -u hysteria-server -f" 2>/dev/null
    
    echo -e "\e[1;32mAll monitoring processes stopped.\e[0m"
}

# Rest of the functions remain the same...
# (I'll include the essential remaining functions)

show_user_history() {
    echo -e "\n\e[1;34mEnter username to view history:\e[0m"
    read -r username
    
    echo -e "\n\e[1;34m=== Connection History for $username ===\e[0m"
    local history_count=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM online_sessions WHERE username='$username';")
    
    if [[ $history_count -gt 0 ]]; then
        echo -e "\e[1;36mSession ID\t\t\tIP Address\tPort\tConnect Time\t\tDisconnect Time\t\tStatus\e[0m"
        echo -e "\e[1;36m----------\t\t\t----------\t----\t------------\t\t---------------\t\t------\e[0m"
        sqlite3 "$USER_DB" "SELECT session_id, ip_address, port, connect_time, COALESCE(disconnect_time, 'Online'), status FROM online_sessions WHERE username='$username' ORDER BY connect_time DESC LIMIT 50;" | while IFS='|' read -r session_id ip port connect_time disconnect_time status; do
            if [[ "$status" == "online" ]]; then
                printf "\e[1;32m%-25s\t%-15s\t%-6s\t%-20s\t%-20s\t%s\e[0m\n" "${session_id:0:24}..." "$ip" "$port" "$connect_time" "$disconnect_time" "$status"
            else
                printf "\e[1;37m%-25s\t%-15s\t%-6s\t%-20s\t%-20s\t%s\e[0m\n" "${session_id:0:24}..." "$ip" "$port" "$connect_time" "$disconnect_time" "$status"
            fi
        done
    else
        echo -e "\e[1;33mNo connection history found for user $username.\e[0m"
    fi
}

kick_user() {
    echo -e "\n\e[1;34mEnter session ID or username to kick:\e[0m"
    read -r identifier
    
    # Check if it's a session ID or username
    if echo "$identifier" | grep -q "_"; then
        # Likely a session ID
        sqlite3 "$USER_DB" "UPDATE online_sessions SET disconnect_time=datetime('now'), status='kicked' WHERE session_id='$identifier' AND status='online';"
    else
        # Likely a username - kick all sessions
        sqlite3 "$USER_DB" "UPDATE online_sessions SET disconnect_time=datetime('now'), status='kicked' WHERE username='$identifier' AND status='online';"
    fi
    
    update_web_status
    echo -e "\e[1;32mUser/session kicked successfully.\e[0m"
    echo -e "\e[1;33mNote: Hysteria server restart may be needed for full disconnection.\e[0m"
}

cleanup_sessions() {
    local cleaned=$(sqlite3 "$USER_DB" "DELETE FROM online_sessions WHERE status IN ('offline', 'kicked') AND datetime(disconnect_time) < datetime('now', '-7 days'); SELECT changes();")
    echo -e "\e[1;32mCleaned up $cleaned old sessions (older than 7 days).\e[0m"
    update_web_status
}

check_web_status() {
    echo -e "\n\e[1;34m=== Web Status Check ===\e[0m"
    
    if [[ -f "$WEB_STATUS_ENABLED" ]]; then
        echo -e "\e[1;32m✓ Web status is enabled\e[0m"
        
        if systemctl is-active udp-web-status >/dev/null 2>&1; then
            echo -e "\e[1;32m✓ Web status service is running\e[0m"
        else
            echo -e "\e[1;31m❌ Web status service is not running\e[0m"
            systemctl start udp-web-status
        fi
        
        if systemctl is-active nginx >/dev/null 2>&1; then
            echo -e "\e[1;32m✓ Nginx is running\e[0m"
        else
            echo -e "\e[1;31m❌ Nginx is not running\e[0m"
            systemctl start nginx
        fi
        
        if [[ -f "$WEB_STATUS_FILE" ]]; then
            local current_count=$(cat "$WEB_STATUS_FILE" 2>/dev/null || echo "error")
            echo -e "\e[1;32m✓ Web status file exists\e[0m"
            echo -e "\e[1;36mCurrent online count: $current_count\e[0m"
        else
            echo -e "\e[1;31m❌ Web status file not found\e[0m"
            update_web_status
        fi
        
        local server_ip=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        echo -e "\n\e[1;34mTesting endpoint:\e[0m"
        echo -e "\e[1;36mURL: http://$server_ip:81/udpserver/online\e[0m"
        
        local test_result=$(curl -s http://localhost:81/udpserver/online 2>/dev/null || echo "connection_failed")
        if [[ "$test_result" =~ ^[0-9]+$ ]]; then
            echo -e "\e[1;32m✓ Local test successful: $test_result users online\e[0m"
        else
            echo -e "\e[1;31m❌ Local test failed: $test_result\e[0m"
        fi
    else
        echo -e "\e[1;31m❌ Web status is disabled\e[0m"
        echo -e "\e[1;33mUse option 15 to enable web status\e[0m"
    fi
}

# [Additional functions like add_user, edit_user, delete_user, show_users, etc. remain unchanged]
# [Include all other original functions here...]

add_user() {
    echo -e "\n\e[1;34mEnter username:\e[0m"
    read -r username
    echo -e "\e[1;34mEnter password:\e[0m"
    read -r password
    sqlite3 "$USER_DB" "INSERT INTO users (username, password) VALUES ('$username', '$password');"
    if [[ $? -eq 0 ]]; then
        echo -e "\e[1;32mUser $username added successfully.\e[0m"
        update_userpass_config
        restart_server
    else
        echo -e "\e[1;31mError: Failed to add user $username.\e[0m"
    fi
}

edit_user() {
    echo -e "\n\e[1;34mEnter username to edit:\e[0m"
    read -r username
    echo -e "\e[1;34mEnter new password:\e[0m"
    read -r password
    sqlite3 "$USER_DB" "UPDATE users SET password = '$password' WHERE username = '$username';"
    if [[ $? -eq 0 ]]; then
        echo -e "\e[1;32mUser $username updated successfully.\e[0m"
        update_userpass_config
        restart_server
    else
        echo -e "\e[1;31mError: Failed to update user $username.\e[0m"
    fi
}

delete_user() {
    echo -e "\n\e[1;34mEnter username to delete:\e[0m"
    read -r username
    sqlite3 "$USER_DB" "DELETE FROM users WHERE username = '$username';"
    if [[ $? -eq 0 ]]; then
        echo -e "\e[1;32mUser $username deleted successfully.\e[0m"
        update_userpass_config
        restart_server
    else
        echo -e "\e[1;31mError: Failed to delete user $username.\e[0m"
    fi
}

show_users() {
    echo -e "\n\e[1;34mCurrent users:\e[0m"
    sqlite3 "$USER_DB" "SELECT username FROM users;"
}

change_domain() {
    echo -e "\n\e[1;34mEnter new domain:\e[0m"
    read -r domain
    jq ".server = \"$domain\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo -e "\e[1;32mDomain changed to $domain successfully.\e[0m"
    restart_server
}

change_obfs() {
    echo -e "\n\e[1;34mEnter new obfuscation string:\e[0m"
    read -r obfs
    jq ".obfs.password = \"$obfs\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo -e "\e[1;32mObfuscation string changed to $obfs successfully.\e[0m"
    restart_server
}

change_up_speed() {
    echo -e "\n\e[1;34mEnter new upload speed (Mbps):\e[0m"
    read -r up_speed
    jq ".up_mbps = $up_speed" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    jq ".up = \"$up_speed Mbps\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo -e "\e[1;32mUpload speed changed to $up_speed Mbps successfully.\e[0m"
    restart_server
}

change_down_speed() {
    echo -e "\n\e[1;34mEnter new download speed (Mbps):\e[0m"
    read -r down_speed
    jq ".down_mbps = $down_speed" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    jq ".down = \"$down_speed Mbps\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo -e "\e[1;32mDownload speed changed to $down_speed Mbps successfully.\e[0m"
    restart_server
}

restart_server() {
    systemctl restart hysteria-server
    echo -e "\e[1;32mServer restarted successfully.\e[0m"
}

uninstall_server() {
    echo -e "\n\e[1;34mUninstalling UDP server...\e[0m"
    stop_monitoring
    disable_web_status
    systemctl stop hysteria-server
    systemctl disable hysteria-server
    rm -f "$SYSTEMD_SERVICE"
    systemctl daemon-reload
    rm -rf "$CONFIG_DIR"
    rm -f /usr/local/bin/hysteria
    echo -e "\e[1;32mUDP server uninstalled successfully.\e[0m"
}

check_hysteria_config() {
    echo -e "\n\e[1;34m=== Checking Hysteria Configuration ===\e[0m"
    
    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "\e[1;32m✓ Config file exists\e[0m"
        
        local has_log_section=$(jq -r '.log' "$CONFIG_FILE" 2>/dev/null)
        if [[ "$has_log_section" == "null" ]]; then
            echo -e "\e[1;33m⚠ Log section missing, adding...\e[0m"
            jq '. + {"log": {"level": "info", "file": "/var/log/hysteria/hysteria.log"}}' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            echo -e "\e[1;32m✓ Log configuration added\e[0m"
        else
            echo -e "\e[1;32m✓ Log section exists\e[0m"
        fi
        
        local log_file_in_config=$(jq -r '.log.file' "$CONFIG_FILE" 2>/dev/null)
        if [[ "$log_file_in_config" != "/var/log/hysteria/hysteria.log" ]]; then
            jq '.log.file = "/var/log/hysteria/hysteria.log"' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            echo -e "\e[1;32m✓ Log file path fixed\e[0m"
        fi
    else
        echo -e "\e[1;31m❌ Config file not found\e[0m"
    fi
}

show_banner() {
    clear
    echo -e "\e[1;36m============================================="
    echo " UDP Manager with Multi-User Tracking v2.0"
    echo " Improved for Multiple Concurrent Connections"
    echo " (c) 2025 UDP"
    echo " Telegram: @sansoe2021"
    echo "=============================================\e[0m"
}

show_menu() {
    echo -e "\n\e[1;36m========== UDP Manager Menu ==========\e[0m"
    echo -e "\e[1;32m1.  Add new user"
    echo "2.  Edit user password"
    echo "3.  Delete user"
    echo "4.  Show all users"
    echo "5.  Change domain"
    echo "6.  Change obfuscation"
    echo "7.  Change upload speed"
    echo "8.  Change download speed"
    echo "9.  Restart server"
    echo "10. Show online users"
    echo "11. Show user history"
    echo "12. Kick user/session"
    echo "13. Start monitoring"
    echo "14. Stop monitoring"
    echo "15. Enable web status"
    echo "16. Disable web status"
    echo "17. Check web status"
    echo "18. Cleanup old sessions"
    echo "19. Check/Fix config"
    echo "20. Uninstall server"
    echo -e "21. Exit\e[0m"
    echo -e "\e[1;36m======================================\e[0m"
    echo -n "Enter your choice: "
}

# Initialize database on first run
init_database

# Main loop
show_banner
while true; do
    show_menu
    read -r choice
    case $choice in
        1) add_user ;;
        2) edit_user ;;
        3) delete_user ;;
        4) show_users ;;
        5) change_domain ;;
        6) change_obfs ;;
        7) change_up_speed ;;
        8) change_down_speed ;;
        9) restart_server ;;
        10) show_online_users ;;
        11) show_user_history ;;
        12) kick_user ;;
        13) start_monitoring ;;
        14) stop_monitoring ;;
        15) enable_web_status ;;
        16) disable_web_status ;;
        17) check_web_status ;;
        18) cleanup_sessions ;;
        19) check_hysteria_config ;;
        20) uninstall_server; exit 0 ;;
        21) clear; exit 0 ;;
        *) echo -e "\e[1;31mInvalid choice. Try again.\e[0m" ;;
    esac
    
    echo -e "\n\e[1;33mPress Enter to continue...\e[0m"
    read
    clear
    show_banner
done
