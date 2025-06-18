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

mkdir -p "$CONFIG_DIR"
mkdir -p "/var/log/hysteria"
mkdir -p "$WEB_DIR"
touch "$USER_DB"
touch "$ONLINE_USERS_FILE"

# Initialize database with online_sessions table
init_database() {
    sqlite3 "$USER_DB" "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT);"
    sqlite3 "$USER_DB" "CREATE TABLE IF NOT EXISTS online_sessions (
        id INTEGER PRIMARY KEY,
        username TEXT,
        ip_address TEXT,
        connect_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        disconnect_time DATETIME,
        status TEXT DEFAULT 'online',
        FOREIGN KEY(username) REFERENCES users(username)
    );"
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

# Update web status file with online count
update_web_status() {
    if [[ -f "$WEB_STATUS_ENABLED" ]]; then
        local online_count=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM online_sessions WHERE status='online';")
        echo "$online_count" > "$WEB_STATUS_FILE"
        chmod 644 "$WEB_STATUS_FILE"
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
        
        # Create web status update service
        cat > "$WEB_SERVICE_FILE" << 'EOF'
[Unit]
Description=UDP Server Online Status Updater
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do if [[ -f /etc/hysteria/web_status_enabled ]]; then count=$(sqlite3 /etc/hysteria/udpusers.db "SELECT COUNT(*) FROM online_sessions WHERE status='\''online'\'';" 2>/dev/null || echo "0"); echo "$count" > /var/www/html/udpserver/online; chmod 644 /var/www/html/udpserver/online; fi; sleep 5; done'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        # Enable and start the service
        systemctl daemon-reload
        systemctl enable udp-web-status
        systemctl start udp-web-status
        
        # Mark web status as enabled
        touch "$WEB_STATUS_ENABLED"
        
        # Initialize with current count
        update_web_status
        
        local server_ip=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        echo -e "\e[1;32mWeb status endpoint enabled successfully!\e[0m"
        echo -e "\e[1;36mAccess URL: http://$server_ip:81/udpserver/online\e[0m"
        echo -e "\e[1;33mThis will show the number of online users (e.g., 13)\e[0m"
    else
        echo -e "\e[1;31mNginx configuration error. Please check manually.\e[0m"
    fi
}

# Disable web status endpoint
disable_web_status() {
    echo -e "\n\e[1;34mDisabling web status endpoint...\e[0m"
    
    # Stop and disable the service
    systemctl stop udp-web-status 2>/dev/null
    systemctl disable udp-web-status 2>/dev/null
    
    # Remove service file
    rm -f "$WEB_SERVICE_FILE"
    
    # Remove nginx site
    rm -f /etc/nginx/sites-enabled/udp-status
    rm -f /etc/nginx/sites-available/udp-status
    
    # Reload nginx
    systemctl reload nginx 2>/dev/null
    
    # Remove status files
    rm -f "$WEB_STATUS_ENABLED"
    rm -f "$WEB_STATUS_FILE"
    
    systemctl daemon-reload
    
    echo -e "\e[1;32mWeb status endpoint disabled successfully!\e[0m"
}

# Enable logging in Hysteria config
enable_logging() {
    jq '.log.level = "info" | .log.file = "/var/log/hysteria/hysteria.log"' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

# Parse logs to track connections
track_connections() {
    if [[ ! -f "$LOG_FILE" ]]; then
        echo -e "\e[1;33mLog file not found. Make sure logging is enabled.\e[0m"
        return
    fi
    
    # Monitor new connections
    tail -f "$LOG_FILE" | while read line; do
        # Look for connection patterns in Hysteria logs
        if echo "$line" | grep -q "client connected"; then
            local timestamp=$(echo "$line" | awk '{print $1 " " $2}')
            local ip=$(echo "$line" | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
            local username=$(echo "$line" | grep -o 'user=[^ ]*' | cut -d= -f2)
            
            if [[ -n "$username" && -n "$ip" ]]; then
                sqlite3 "$USER_DB" "INSERT INTO online_sessions (username, ip_address, connect_time, status) VALUES ('$username', '$ip', '$timestamp', 'online');"
                echo "$timestamp - $username ($ip) connected" >> "$ONLINE_USERS_FILE"
                update_web_status
            fi
        elif echo "$line" | grep -q "client disconnected"; then
            local timestamp=$(echo "$line" | awk '{print $1 " " $2}')
            local ip=$(echo "$line" | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
            local username=$(echo "$line" | grep -o 'user=[^ ]*' | cut -d= -f2)
            
            if [[ -n "$username" && -n "$ip" ]]; then
                sqlite3 "$USER_DB" "UPDATE online_sessions SET disconnect_time='$timestamp', status='offline' WHERE username='$username' AND ip_address='$ip' AND status='online';"
                echo "$timestamp - $username ($ip) disconnected" >> "$ONLINE_USERS_FILE"
                update_web_status
            fi
        fi
    done &
}

# Show currently online users
show_online_users() {
    echo -e "\n\e[1;34m=== Currently Online Users ===\e[0m"
    
    # Show online count prominently
    local online_count=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM online_sessions WHERE status='online';")
    echo -e "\e[1;32m╔══════════════════════════════════╗\e[0m"
    echo -e "\e[1;32m║     ONLINE USERS COUNT: $online_count        ║\e[0m"
    echo -e "\e[1;32m╚══════════════════════════════════╝\e[0m"
    
    if [[ $online_count -gt 0 ]]; then
        echo -e "\n\e[1;36mUsername\t\tIP Address\t\tConnect Time\e[0m"
        echo -e "\e[1;36m--------\t\t----------\t\t------------\e[0m"
        sqlite3 "$USER_DB" "SELECT username, ip_address, connect_time FROM online_sessions WHERE status='online';" | while IFS='|' read -r username ip connect_time; do
            printf "\e[1;37m%-15s\t%-15s\t%s\e[0m\n" "$username" "$ip" "$connect_time"
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

# Show user connection history
show_user_history() {
    echo -e "\n\e[1;34mEnter username to view history:\e[0m"
    read -r username
    
    echo -e "\n\e[1;34m=== Connection History for $username ===\e[0m"
    local history_count=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM online_sessions WHERE username='$username';")
    
    if [[ $history_count -gt 0 ]]; then
        echo -e "\e[1;36mIP Address\t\tConnect Time\t\tDisconnect Time\t\tStatus\e[0m"
        echo -e "\e[1;36m----------\t\t------------\t\t---------------\t\t------\e[0m"
        sqlite3 "$USER_DB" "SELECT ip_address, connect_time, COALESCE(disconnect_time, 'Still Online'), status FROM online_sessions WHERE username='$username' ORDER BY connect_time DESC LIMIT 20;" | while IFS='|' read -r ip connect_time disconnect_time status; do
            if [[ "$status" == "online" ]]; then
                printf "\e[1;32m%-15s\t%-20s\t%-20s\t%s\e[0m\n" "$ip" "$connect_time" "$disconnect_time" "$status"
            else
                printf "\e[1;37m%-15s\t%-20s\t%-20s\t%s\e[0m\n" "$ip" "$connect_time" "$disconnect_time" "$status"
            fi
        done
    else
        echo -e "\e[1;33mNo connection history found for user $username.\e[0m"
    fi
}

# Kick/disconnect a user
kick_user() {
    echo -e "\n\e[1;34mEnter username to kick:\e[0m"
    read -r username
    
    # Mark user as disconnected in database
    sqlite3 "$USER_DB" "UPDATE online_sessions SET disconnect_time=datetime('now'), status='kicked' WHERE username='$username' AND status='online';"
    update_web_status
    
    # Get user's current connections and kill them
    local hysteria_port=$(jq -r '.listen' "$CONFIG_FILE" | cut -d: -f2)
    if [[ -n "$hysteria_port" ]]; then
        # This is a basic approach - you might need to implement more sophisticated user tracking
        echo -e "\e[1;33mUser $username marked as kicked. You may need to restart the server to fully disconnect them.\e[0m"
        echo -e "\e[1;34mRestart server now? (y/n):\e[0m"
        read -r restart_choice
        if [[ "$restart_choice" == "y" || "$restart_choice" == "Y" ]]; then
            restart_server
        fi
    fi
}

# Clear offline users from database
cleanup_sessions() {
    local cleaned=$(sqlite3 "$USER_DB" "DELETE FROM online_sessions WHERE status='offline' AND datetime(disconnect_time) < datetime('now', '-7 days'); SELECT changes();")
    echo -e "\e[1;32mCleaned up $cleaned old offline sessions (older than 7 days).\e[0m"
}

# Start connection monitoring daemon
start_monitoring() {
    # Kill existing monitoring process if any
    pkill -f "tail -f $LOG_FILE"
    
    echo -e "\e[1;34mStarting connection monitoring...\e[0m"
    enable_logging
    restart_server
    sleep 3
    track_connections
    echo -e "\e[1;32mConnection monitoring started in background.\e[0m"
}

# Stop connection monitoring
stop_monitoring() {
    pkill -f "tail -f $LOG_FILE"
    echo -e "\e[1;32mConnection monitoring stopped.\e[0m"
}

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
    echo -e "\n\e[1;34mUninstalling AGN-UDP server...\e[0m"
    stop_monitoring
    disable_web_status
    systemctl stop hysteria-server
    systemctl disable hysteria-server
    rm -f "$SYSTEMD_SERVICE"
    systemctl daemon-reload
    rm -rf "$CONFIG_DIR"
    rm -f /usr/local/bin/hysteria
    echo -e "\e[1;32mAGN-UDP server uninstalled successfully.\e[0m"
}

show_banner() {
    echo -e "\e[1;36m---------------------------------------------"
    echo " SVPN UDP Manager with Online User Tracking"
    echo " (c) 2025 SVPN"
    echo " Telegram: @sansoe2021"
    echo "---------------------------------------------\e[0m"
}

show_menu() {
    echo -e "\e[1;36m----------------------------"
    echo " SVPN UDP Manager"
    echo -e "----------------------------\e[0m"
    echo -e "\e[1;32m1. Add new user"
    echo "2. Edit user password"
    echo "3. Delete user"
    echo "4. Show users"
    echo "5. Change domain"
    echo "6. Change obfuscation string"
    echo "7. Change upload speed"
    echo "8. Change download speed"
    echo "9. Restart server"
    echo "10. Show online users"
    echo "11. Show user history"
    echo "12. Kick user"
    echo "13. Start monitoring"
    echo "14. Stop monitoring"
    echo "15. Enable web status link"
    echo "16. Disable web status link"
    echo "17. Check web status"
    echo "18. Cleanup old sessions"
    echo "19. Uninstall server"
    echo -e "20. Exit\e[0m"
    echo -e "\e[1;36m----------------------------"
    echo -e "Enter your choice: \e[0m"
}

# Initialize database on first run
init_database

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
        19) uninstall_server; exit 0 ;;
        20) exit 0 ;;
        *) echo -e "\e[1;31mInvalid choice. Please try again.\e[0m" ;;
    esac
done
