#!/bin/bash

CONFIG_DIR="/etc/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.json"
USER_DB="$CONFIG_DIR/udpusers.db"
SYSTEMD_SERVICE="/etc/systemd/system/hysteria-server.service"
LOG_FILE="/var/log/hysteria/hysteria.log"
ONLINE_USERS_FILE="$CONFIG_DIR/online_users.log"
WEB_DIR="/var/www/html/udpserver"
WEB_STATUS_FILE="$WEB_DIR/online"
WEB_APP_FILE="$WEB_DIR/online_app"
MONITOR_PID_FILE="$CONFIG_DIR/.monitor_pid"

mkdir -p "$CONFIG_DIR"
mkdir -p "/var/log/hysteria"
mkdir -p "$WEB_DIR"
touch "$USER_DB"
touch "$ONLINE_USERS_FILE"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Initialize database with online_sessions table
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
    
    sqlite3 "$USER_DB" "CREATE INDEX IF NOT EXISTS idx_session_status ON online_sessions(status);"
    sqlite3 "$USER_DB" "CREATE INDEX IF NOT EXISTS idx_session_id ON online_sessions(session_id);"
    sqlite3 "$USER_DB" "CREATE INDEX IF NOT EXISTS idx_username ON online_sessions(username);"
    sqlite3 "$USER_DB" "CREATE INDEX IF NOT EXISTS idx_ip_address ON online_sessions(ip_address);"
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

fun_online() {
    # Database-based counting (primary method for QUIC)
    local _onli=0
    if [[ -f "$USER_DB" ]]; then
        _onli=$(sqlite3 "$USER_DB" "SELECT COUNT(DISTINCT session_id) FROM online_sessions WHERE status='online' AND datetime(connect_time) > datetime('now', '-10 minutes');" 2>/dev/null || echo "0")
    fi
    
    # Ensure non-negative
    [[ $_onli -lt 0 ]] && _onli=0
    
    # Format output
    _onlin=$(printf '%-5s' "$_onli")
    CURRENT_ONLINES="$(echo -e "${_onlin}" | sed -e 's/[[:space:]]*$//')"
    
    # Write to web files
    echo "{\"onlines\":\"$CURRENT_ONLINES\",\"limite\":\"2500\"}" > "$WEB_APP_FILE"
    echo "$CURRENT_ONLINES" > "$WEB_STATUS_FILE"
    
    # Set permissions
    chmod 644 "$WEB_STATUS_FILE" "$WEB_APP_FILE" 2>/dev/null
}

# Background monitoring loop
start_online_monitor() {
    echo -e "${BLUE}Starting online monitor (background loop)...${NC}"
    
    # Stop existing monitor if running
    stop_online_monitor
    
    # Start background loop
    (
        while true; do
            fun_online > /dev/null 2>&1
            sleep 15s
        done
    ) &
    
    # Save PID
    echo $! > "$MONITOR_PID_FILE"
    
    echo -e "${GREEN}✓ Online monitor started (PID: $(cat $MONITOR_PID_FILE))${NC}"
    echo -e "${CYAN}Updates every 15 seconds${NC}"
    echo -e "${CYAN}Files: $WEB_STATUS_FILE and $WEB_APP_FILE${NC}"
}

# Stop background monitor
stop_online_monitor() {
    if [[ -f "$MONITOR_PID_FILE" ]]; then
        local pid=$(cat "$MONITOR_PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            kill "$pid" 2>/dev/null
            echo -e "${GREEN}✓ Stopped online monitor (PID: $pid)${NC}"
        fi
        rm -f "$MONITOR_PID_FILE"
    fi
}

# Start connection tracker (uses systemd service)
start_connection_tracker() {
    echo -e "${BLUE}Starting connection tracker...${NC}"
    
    # Check if service exists
    if [[ ! -f "/etc/systemd/system/hysteria-tracker.service" ]]; then
        echo -e "${YELLOW}Creating hysteria-tracker systemd service...${NC}"
        setup_tracker_service
    fi
    
    # Start service
    systemctl start hysteria-tracker
    
    if systemctl is-active hysteria-tracker >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Connection tracker started (systemd service)${NC}"
        echo -e "${CYAN}Service: hysteria-tracker${NC}"
        echo -e "${CYAN}View logs: journalctl -u hysteria-tracker -f${NC}"
        echo -e "${CYAN}Connection log: tail -f $ONLINE_USERS_FILE${NC}"
    else
        echo -e "${RED}✗ Failed to start tracker${NC}"
        echo -e "${YELLOW}Check status: systemctl status hysteria-tracker${NC}"
    fi
}

# Stop connection tracker
stop_connection_tracker() {
    echo -e "${BLUE}Stopping connection tracker...${NC}"
    
    systemctl stop hysteria-tracker
    
    if ! systemctl is-active hysteria-tracker >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Connection tracker stopped${NC}"
    else
        echo -e "${RED}✗ Failed to stop tracker${NC}"
    fi
}

# Setup tracker systemd service
setup_tracker_service() {
    echo -e "${BLUE}Setting up hysteria-tracker service...${NC}"
    
    # Create service file
    cat > /etc/systemd/system/hysteria-tracker.service << 'EOF'
[Unit]
Description=Hysteria Connection Tracker
After=hysteria-server.service
Requires=hysteria-server.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc/hysteria
ExecStart=/usr/local/bin/hysteria-tracker.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Create tracker script
    cat > /usr/local/bin/hysteria-tracker.sh << 'TRACKEREOF'
#!/bin/bash

CONFIG_DIR="/etc/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.json"
USER_DB="$CONFIG_DIR/udpusers.db"
ONLINE_USERS_FILE="$CONFIG_DIR/online_users.log"

echo "Starting Hysteria Connection Tracker..."
echo "Log file: $ONLINE_USERS_FILE"
echo "Database: $USER_DB"

# Get port
HYSTERIA_PORT=$(jq -r '.listen' "$CONFIG_FILE" 2>/dev/null | sed 's/^://' | cut -d: -f1)
[[ -z "$HYSTERIA_PORT" ]] && HYSTERIA_PORT="36712"

echo "Monitoring port: $HYSTERIA_PORT"
echo "Auto-disconnect after 3 minutes inactivity"

# Clear stale connections
sqlite3 "$USER_DB" "UPDATE online_sessions SET status='offline', disconnect_time=datetime('now') WHERE status='online';"

# Background timeout checker
(
    while true; do
        sleep 30
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        sqlite3 "$USER_DB" "UPDATE online_sessions SET status='offline', disconnect_time='$timestamp' WHERE status='online' AND datetime(connect_time) < datetime('now', '-3 minutes');" 2>/dev/null
    done
) &
timeout_pid=$!

# Trap to cleanup on exit
cleanup() {
    echo "Shutting down tracker..."
    kill $timeout_pid 2>/dev/null
    exit 0
}
trap cleanup SIGTERM SIGINT

# Monitor logs
journalctl -u hysteria-server -f -n 0 --no-pager 2>/dev/null | while read -r line; do
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    ip=$(echo "$line" | grep -oP '\[src:\K[0-9.]+(?=:)' | head -1)
    [[ -z "$ip" ]] && continue
    
    port=$(echo "$line" | grep -oP '\[src:[0-9.]+:\K[0-9]+(?=\])' | head -1)
    
    (
        flock -x 200
        session_id=$(sqlite3 "$USER_DB" "SELECT session_id FROM online_sessions WHERE ip_address='$ip' AND status='online' LIMIT 1;" 2>/dev/null)
        
        if [[ -z "$session_id" ]]; then
            session_id="${ip}_${port}_$(date +%s%N)"
            username="user_${ip}"
            sqlite3 "$USER_DB" "INSERT INTO online_sessions (session_id, username, ip_address, port, connect_time, status) VALUES ('$session_id', '$username', '$ip', ${port:-0}, '$timestamp', 'online');" 2>/dev/null
            echo "$timestamp - $username ($ip:${port:-unknown}) connected [Session: $session_id]" >> "$ONLINE_USERS_FILE"
            echo "[CONNECT] $username from $ip:${port:-unknown}"
        else
            sqlite3 "$USER_DB" "UPDATE online_sessions SET connect_time='$timestamp' WHERE session_id='$session_id';" 2>/dev/null
        fi
    ) 200>/var/lock/udp_sessions.lock
done

kill $timeout_pid 2>/dev/null
TRACKEREOF

    chmod +x /usr/local/bin/hysteria-tracker.sh
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable auto-start
    systemctl enable hysteria-tracker
    
    echo -e "${GREEN}✓ Hysteria-tracker service created${NC}"
}

# Check monitor status
check_monitor_status() {
    echo -e "\n${BLUE}═══ Monitoring Status ═══${NC}"
    
    # Online monitor
    if [[ -f "$MONITOR_PID_FILE" ]]; then
        local pid=$(cat "$MONITOR_PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Online monitor is RUNNING (PID: $pid)${NC}"
        else
            echo -e "${RED}✗ Online monitor is NOT RUNNING${NC}"
        fi
    else
        echo -e "${RED}✗ Online monitor is NOT RUNNING${NC}"
    fi
    
    # Connection tracker (systemd)
    if systemctl is-active hysteria-tracker >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Connection tracker is RUNNING (systemd service)${NC}"
    else
        echo -e "${RED}✗ Connection tracker is NOT RUNNING${NC}"
    fi
    
    # Hysteria server
    if systemctl is-active hysteria-server >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Hysteria server is running${NC}"
    else
        echo -e "${RED}✗ Hysteria server is NOT running${NC}"
    fi
    
    # Nginx
    if systemctl is-active nginx >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Nginx is running${NC}"
    else
        echo -e "${YELLOW}⚠ Nginx is not running${NC}"
    fi
    
    # Current online users
    local online_count=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM online_sessions WHERE status='online';" 2>/dev/null || echo "0")
    echo -e "${CYAN}Current online users: $online_count${NC}"
}

# Show online users
show_online_users() {
    echo -e "\n${BLUE}═══ Online Users ═══${NC}"
    
    local online_count=$(sqlite3 "$USER_DB" "SELECT COUNT(DISTINCT session_id) FROM online_sessions WHERE status='online';" 2>/dev/null || echo "0")
    echo -e "${CYAN}Total online: $online_count${NC}\n"
    
    if [[ $online_count -gt 0 ]]; then
        echo -e "${GREEN}Username${NC}\t\t${GREEN}IP Address${NC}\t\t${GREEN}Connected At${NC}\t${GREEN}Duration${NC}"
        echo "─────────────────────────────────────────────────────────────────────────"
        
        sqlite3 "$USER_DB" "
            SELECT 
                username,
                ip_address,
                strftime('%Y-%m-%d %H:%M:%S', connect_time) as conn_time,
                CAST((julianday('now') - julianday(connect_time)) * 24 * 60 AS INTEGER) || ' min' as duration
            FROM online_sessions 
            WHERE status='online'
            ORDER BY connect_time DESC;
        " 2>/dev/null | while IFS='|' read username ip conn_time duration; do
            printf "%-20s %-15s %-20s %s\n" "$username" "$ip" "$conn_time" "$duration"
        done
    else
        echo -e "${YELLOW}No users currently online${NC}"
    fi
}

# Show user history
show_user_history() {
    echo -e "\n${BLUE}═══ User Connection History ═══${NC}"
    echo -e "${CYAN}Last 20 connections:${NC}\n"
    
    echo -e "${GREEN}Username${NC}\t\t${GREEN}IP Address${NC}\t\t${GREEN}Connect Time${NC}\t\t${GREEN}Disconnect Time${NC}\t${GREEN}Status${NC}"
    echo "────────────────────────────────────────────────────────────────────────────────────────────"
    
    sqlite3 "$USER_DB" "
        SELECT 
            username,
            ip_address,
            strftime('%Y-%m-%d %H:%M:%S', connect_time) as conn,
            COALESCE(strftime('%Y-%m-%d %H:%M:%S', disconnect_time), 'N/A') as disconn,
            status
        FROM online_sessions 
        ORDER BY connect_time DESC 
        LIMIT 20;
    " 2>/dev/null | while IFS='|' read username ip conn disconn status; do
        if [[ "$status" == "online" ]]; then
            printf "%-20s %-15s %-20s %-20s \033[0;32m%s\033[0m\n" "$username" "$ip" "$conn" "$disconn" "$status"
        else
            printf "%-20s %-15s %-20s %-20s %s\n" "$username" "$ip" "$conn" "$disconn" "$status"
        fi
    done
}

# Setup web server
setup_web_server() {
    echo -e "\n${BLUE}Setting up web server for online status...${NC}"
    
    # Create nginx config
    cat > /etc/nginx/sites-available/udp-status << 'NGINXEOF'
server {
    listen 80;
    server_name _;
    
    root /var/www/html;
    
    location /udpserver/ {
        autoindex on;
        add_header Access-Control-Allow-Origin *;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }
}
NGINXEOF

    # Enable site
    ln -sf /etc/nginx/sites-available/udp-status /etc/nginx/sites-enabled/udp-status
    
    # Create web directory
    mkdir -p "$WEB_DIR"
    chmod 755 "$WEB_DIR"
    
    # Create initial files
    echo "0" > "$WEB_STATUS_FILE"
    echo '{"onlines":"0","limite":"2500"}' > "$WEB_APP_FILE"
    chmod 644 "$WEB_STATUS_FILE" "$WEB_APP_FILE"
    
    # Test nginx config
    nginx -t
    
    # Reload nginx
    systemctl reload nginx
    
    echo -e "${GREEN}✓ Web server configured${NC}"
    echo -e "${CYAN}Access at: http://YOUR_SERVER_IP/udpserver/online${NC}"
    echo -e "${CYAN}JSON API: http://YOUR_SERVER_IP/udpserver/online_app${NC}"
}

# User management
add_user() {
    echo -e "\n${BLUE}Add New User${NC}"
    echo -e "${BLUE}Enter username:${NC}"
    read -r username
    echo -e "${BLUE}Enter password:${NC}"
    read -r password
    
    sqlite3 "$USER_DB" "INSERT INTO users (username, password) VALUES ('$username', '$password');" 2>/dev/null
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✓ User $username added successfully${NC}"
        update_userpass_config
        systemctl restart hysteria-server
        echo -e "${YELLOW}Server restarted${NC}"
    else
        echo -e "${RED}✗ Error: Failed to add user (may already exist)${NC}"
    fi
}

edit_user() {
    echo -e "\n${BLUE}Enter username to edit:${NC}"
    read -r username
    echo -e "${BLUE}Enter new password:${NC}"
    read -r password
    
    sqlite3 "$USER_DB" "UPDATE users SET password = '$password' WHERE username = '$username';" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✓ User $username updated successfully${NC}"
        update_userpass_config
        systemctl restart hysteria-server
    else
        echo -e "${RED}✗ Error: Failed to update user${NC}"
    fi
}

delete_user() {
    echo -e "\n${BLUE}Enter username to delete:${NC}"
    read -r username
    
    sqlite3 "$USER_DB" "DELETE FROM users WHERE username = '$username';" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✓ User $username deleted successfully${NC}"
        update_userpass_config
        systemctl restart hysteria-server
    else
        echo -e "${RED}✗ Error: Failed to delete user${NC}"
    fi
}

show_users() {
    echo -e "\n${BLUE}═══ Current Users ═══${NC}"
    local user_count=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "0")
    echo -e "${CYAN}Total users: $user_count${NC}\n"
    
    if [[ $user_count -gt 0 ]]; then
        sqlite3 "$USER_DB" "SELECT username FROM users;" 2>/dev/null | nl
    else
        echo -e "${YELLOW}No users found${NC}"
    fi
}

# Configuration functions
change_domain() {
    echo -e "\n${BLUE}Enter new domain:${NC}"
    read -r domain
    jq ".server = \"$domain\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo -e "${GREEN}✓ Domain changed to $domain${NC}"
    systemctl restart hysteria-server
}

change_obfs() {
    echo -e "\n${BLUE}Enter new obfuscation string:${NC}"
    read -r obfs
    jq ".obfs = \"$obfs\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo -e "${GREEN}✓ Obfuscation changed${NC}"
    systemctl restart hysteria-server
}

change_up_speed() {
    echo -e "\n${BLUE}Enter new upload speed (Mbps):${NC}"
    read -r up_speed
    jq ".up_mbps = $up_speed | .up = \"$up_speed Mbps\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo -e "${GREEN}✓ Upload speed changed to $up_speed Mbps${NC}"
    systemctl restart hysteria-server
}

change_down_speed() {
    echo -e "\n${BLUE}Enter new download speed (Mbps):${NC}"
    read -r down_speed
    jq ".down_mbps = $down_speed | .down = \"$down_speed Mbps\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo -e "${GREEN}✓ Download speed changed to $down_speed Mbps${NC}"
    systemctl restart hysteria-server
}

# Cleanup functions
cleanup_sessions() {
    local cleaned=$(sqlite3 "$USER_DB" "DELETE FROM online_sessions WHERE status='offline' AND datetime(disconnect_time) < datetime('now', '-7 days'); SELECT changes();" 2>/dev/null)
    echo -e "${GREEN}✓ Cleaned up $cleaned old sessions (>7 days)${NC}"
}

# Server control
restart_server() {
    systemctl restart hysteria-server
    echo -e "${GREEN}✓ Server restarted${NC}"
}

stop_server() {
    systemctl stop hysteria-server
    echo -e "${YELLOW}Server stopped${NC}"
}

start_server() {
    systemctl start hysteria-server
    echo -e "${GREEN}✓ Server started${NC}"
}

# Uninstall
uninstall_server() {
    echo -e "\n${RED}═══ WARNING: This will remove everything ═══${NC}"
    echo -e "${YELLOW}Are you sure? (yes/no):${NC}"
    read -r confirm
    
    if [[ "$confirm" == "yes" ]]; then
        echo -e "${BLUE}Uninstalling...${NC}"
        stop_online_monitor
        systemctl stop hysteria-tracker
        systemctl disable hysteria-tracker
        rm -f /etc/systemd/system/hysteria-tracker.service
        rm -f /usr/local/bin/hysteria-tracker.sh
        systemctl daemon-reload
        systemctl stop hysteria-server
        systemctl disable hysteria-server
        rm -f "$SYSTEMD_SERVICE"
        systemctl daemon-reload
        rm -rf "$CONFIG_DIR"
        rm -rf "$WEB_DIR"
        rm -f /usr/local/bin/hysteria
        rm -f /etc/nginx/sites-enabled/udp-status
        rm -f /etc/nginx/sites-available/udp-status
        systemctl reload nginx
        echo -e "${GREEN}✓ UDP server uninstalled${NC}"
    else
        echo -e "${YELLOW}Uninstall cancelled${NC}"
    fi
}

# Banner
show_banner() {
    clear
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${CYAN}   UDP Manager with Systemd Integration${NC}"
    echo -e "${GREEN}   Activity-Based Tracking - v3.0${NC}"
    echo -e "${YELLOW}   (c) 2025 - @sansoe2021${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
}

# Menu
show_menu() {
    echo -e "\n${BLUE}════════ UDP Manager Menu ════════${NC}"
    echo -e "${GREEN}1.  Add new user${NC}"
    echo -e "${GREEN}2.  Edit user password${NC}"
    echo -e "${GREEN}3.  Delete user${NC}"
    echo -e "${GREEN}4.  Show all users${NC}"
    echo -e "${CYAN}5.  Show online users${NC}"
    echo -e "${CYAN}6.  Show user history${NC}"
    echo -e "${CYAN}7.  Check monitor status${NC}"
    echo -e "${YELLOW}8.  Start online monitor${NC}"
    echo -e "${YELLOW}9.  Stop online monitor${NC}"
    echo -e "${YELLOW}10. Start connection tracker${NC}"
    echo -e "${YELLOW}11. Stop connection tracker${NC}"
    echo -e "${GREEN}12. Setup web server${NC}"
    echo -e "${GREEN}13. Change domain${NC}"
    echo -e "${GREEN}14. Change obfuscation${NC}"
    echo -e "${GREEN}15. Change upload speed${NC}"
    echo -e "${GREEN}16. Change download speed${NC}"
    echo -e "${CYAN}17. Restart server${NC}"
    echo -e "${CYAN}18. Stop server${NC}"
    echo -e "${CYAN}19. Start server${NC}"
    echo -e "${YELLOW}20. Cleanup old sessions${NC}"
    echo -e "${RED}21. Uninstall server${NC}"
    echo -e "${BLUE}22. Exit${NC}"
    echo -e "${BLUE}══════════════════════════════════${NC}"
    echo -n "Enter your choice: "
}

# Initialize database
init_database

# Main loop
show_banner

# Auto-start online monitor if not running
if [[ ! -f "$MONITOR_PID_FILE" ]] || ! ps -p "$(cat $MONITOR_PID_FILE 2>/dev/null)" > /dev/null 2>&1; then
    echo -e "${YELLOW}Auto-starting online monitor...${NC}"
    start_online_monitor
    sleep 1
fi

# Auto-start connection tracker if not running
if ! systemctl is-active hysteria-tracker >/dev/null 2>&1; then
    echo -e "${YELLOW}Auto-starting connection tracker...${NC}"
    
    # Check if service exists, if not create it
    if [[ ! -f "/etc/systemd/system/hysteria-tracker.service" ]]; then
        setup_tracker_service
    fi
    
    systemctl start hysteria-tracker
    sleep 1
fi

while true; do
    show_menu
    read -r choice
    
    case $choice in
        1) add_user ;;
        2) edit_user ;;
        3) delete_user ;;
        4) show_users ;;
        5) show_online_users ;;
        6) show_user_history ;;
        7) check_monitor_status ;;
        8) start_online_monitor ;;
        9) stop_online_monitor ;;
        10) start_connection_tracker ;;
        11) stop_connection_tracker ;;
        12) setup_web_server ;;
        13) change_domain ;;
        14) change_obfs ;;
        15) change_up_speed ;;
        16) change_down_speed ;;
        17) restart_server ;;
        18) stop_server ;;
        19) start_server ;;
        20) cleanup_sessions ;;
        21) uninstall_server ;;
        22) 
            echo -e "${YELLOW}Exiting... (monitors will continue running in background)${NC}"
            clear
            exit 0
            ;;
        *) 
            echo -e "${RED}✗ Invalid choice${NC}"
            ;;
    esac
    
    echo -e "\n${CYAN}Press Enter to continue...${NC}"
    read
    clear
    show_banner
done
