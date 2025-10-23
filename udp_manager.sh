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
TRACKER_PID_FILE="$CONFIG_DIR/.tracker_pid"

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

# FIXED: Background loop monitoring - Uses database only
fun_online() {
    # Count ONLY from database (connection tracker updates this)
    local _db_count=0
    if [[ -f "$USER_DB" ]]; then
        _db_count=$(sqlite3 "$USER_DB" "SELECT COUNT(DISTINCT session_id) FROM online_sessions WHERE status='online';" 2>/dev/null || echo "0")
    fi
    
    _onli=$_db_count
    
    # Format the output
    _onlin=$(printf '%-5s' "$_onli")
    CURRENT_ONLINES="$(echo -e "${_onlin}" | sed -e 's/[[:space:]]*$//')"
    
    # Write to web files
    echo "{\"onlines\":\"$CURRENT_ONLINES\",\"limite\":\"2500\"}" > "$WEB_APP_FILE"
    echo "$CURRENT_ONLINES" > "$WEB_STATUS_FILE"
    
    chmod 644 "$WEB_STATUS_FILE" 2>/dev/null
    chmod 644 "$WEB_APP_FILE" 2>/dev/null
}

# Background monitoring loop
start_online_monitor() {
    echo -e "${BLUE}Starting online monitor (background loop)...${NC}"
    
    # Stop existing monitor if running
    stop_online_monitor
    
    # Start background loop with nohup
    nohup bash -c "
        while true; do
            _db_count=\$(sqlite3 '$USER_DB' \"SELECT COUNT(DISTINCT session_id) FROM online_sessions WHERE status='online';\" 2>/dev/null || echo '0')
            _onlin=\$(printf '%-5s' \"\$_db_count\")
            CURRENT_ONLINES=\"\$(echo -e \"\${_onlin}\" | sed -e 's/[[:space:]]*\$//')\"
            echo \"{\\\"onlines\\\":\\\"\$CURRENT_ONLINES\\\",\\\"limite\\\":\\\"2500\\\"}\" > '$WEB_APP_FILE'
            echo \"\$CURRENT_ONLINES\" > '$WEB_STATUS_FILE'
            chmod 644 '$WEB_STATUS_FILE' '$WEB_APP_FILE' 2>/dev/null
            sleep 15
        done
    " > /dev/null 2>&1 &
    
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
    # Kill any remaining processes
    pkill -f "online monitor" 2>/dev/null
}

# FIXED: Enhanced connection tracking
track_connections() {
    # Get Hysteria port
    local HYSTERIA_PORT=$(jq -r '.listen' "$CONFIG_FILE" 2>/dev/null | sed 's/^://' | cut -d: -f1)
    [[ -z "$HYSTERIA_PORT" ]] && HYSTERIA_PORT="36712"
    
    # Clear stale connections on startup
    sqlite3 "$USER_DB" "UPDATE online_sessions SET status='offline', disconnect_time=datetime('now') WHERE status='online';"
    
    # Track using journalctl
    journalctl -u hysteria-server -f -n 0 --no-pager 2>/dev/null | while read -r line; do
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        
        # Match connection patterns
        if echo "$line" | grep -qiE "client.*connect|new.*connection|accept.*client|session.*start|authenticated"; then
            local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
            local port=$(echo "$line" | grep -oE ':([0-9]{4,5})' | head -1 | tr -d ':')
            
            if [[ -n "$ip" ]]; then
                local session_id="${ip}_${port}_$(date +%s%N)"
                local username=$(echo "$line" | grep -oP 'user[=:]?\s*\K[^\s,]+' | head -1)
                
                if [[ -z "$username" || "$username" == "null" ]]; then
                    # Try to match with database users
                    username=$(sqlite3 "$USER_DB" "SELECT username FROM users LIMIT 1;" 2>/dev/null)
                    [[ -z "$username" ]] && username="user_${ip}"
                fi
                
                (
                    flock -x 200
                    sqlite3 "$USER_DB" "INSERT INTO online_sessions (session_id, username, ip_address, port, connect_time, status) VALUES ('$session_id', '$username', '$ip', ${port:-0}, '$timestamp', 'online');" 2>/dev/null
                    echo "$timestamp - $username ($ip:${port:-unknown}) connected [Session: $session_id]" >> "$ONLINE_USERS_FILE"
                ) 200>/var/lock/udp_sessions.lock
            fi
            
        elif echo "$line" | grep -qiE "client.*disconnect|connection.*clos|TCP EOF|session.*end|client.*left"; then
            local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
            
            if [[ -n "$ip" ]]; then
                (
                    flock -x 200
                    local session_id=$(sqlite3 "$USER_DB" "SELECT session_id FROM online_sessions WHERE ip_address='$ip' AND status='online' ORDER BY connect_time DESC LIMIT 1;" 2>/dev/null)
                    
                    if [[ -n "$session_id" ]]; then
                        sqlite3 "$USER_DB" "UPDATE online_sessions SET disconnect_time='$timestamp', status='offline' WHERE session_id='$session_id';" 2>/dev/null
                        local username=$(sqlite3 "$USER_DB" "SELECT username FROM online_sessions WHERE session_id='$session_id';" 2>/dev/null)
                        echo "$timestamp - $username ($ip) disconnected [Session: $session_id]" >> "$ONLINE_USERS_FILE"
                    fi
                ) 200>/var/lock/udp_sessions.lock
            fi
        fi
    done
}

# FIXED: Start detailed tracking with nohup
start_connection_tracker() {
    echo -e "${BLUE}Starting detailed connection tracker...${NC}"
    
    stop_connection_tracker
    
    # Enable logging in Hysteria config first
    if [[ -f "$CONFIG_FILE" ]]; then
        local has_log=$(jq -r '.log' "$CONFIG_FILE" 2>/dev/null)
        if [[ "$has_log" == "null" ]]; then
            echo -e "${YELLOW}Enabling Hysteria logging...${NC}"
            jq '. + {"log": {"level": "info", "file": "/var/log/hysteria/hysteria.log"}}' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            systemctl restart hysteria-server
            sleep 2
        fi
    fi
    
    # Start tracker in background with nohup
    nohup bash -c "$(declare -f track_connections); track_connections" > /dev/null 2>&1 &
    echo $! > "$TRACKER_PID_FILE"
    
    echo -e "${GREEN}✓ Connection tracker started (PID: $(cat $TRACKER_PID_FILE))${NC}"
    echo -e "${CYAN}View logs: tail -f $ONLINE_USERS_FILE${NC}"
}

# Stop connection tracker
stop_connection_tracker() {
    if [[ -f "$TRACKER_PID_FILE" ]]; then
        local pid=$(cat "$TRACKER_PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            kill "$pid" 2>/dev/null
            echo -e "${GREEN}✓ Stopped connection tracker (PID: $pid)${NC}"
        fi
        rm -f "$TRACKER_PID_FILE"
    fi
    pkill -f "track_connections" 2>/dev/null
    pkill -f "journalctl -u hysteria-server -f" 2>/dev/null
}

# Show online users
show_online_users() {
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}       Currently Online Users${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    
    # Get current online count
    fun_online > /dev/null 2>&1
    local online_count=$(cat "$WEB_STATUS_FILE" 2>/dev/null || echo "0")
    
    echo -e "${GREEN}╔══════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ONLINE USERS COUNT: $(printf '%3d' $online_count)         ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════╝${NC}"
    
    # Show detailed sessions from database if available
    local db_count=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM online_sessions WHERE status='online';" 2>/dev/null || echo "0")
    
    if [[ $db_count -gt 0 ]]; then
        echo -e "\n${YELLOW}Detailed Sessions from Database:${NC}"
        echo -e "${CYAN}Username\t\tIP Address\t\tConnect Time${NC}"
        echo -e "${CYAN}--------\t\t----------\t\t------------${NC}"
        sqlite3 "$USER_DB" "SELECT username, ip_address, connect_time FROM online_sessions WHERE status='online' ORDER BY connect_time DESC;" 2>/dev/null | while IFS='|' read -r username ip connect_time; do
            printf "${GREEN}%-15s\t\t%-15s\t%s${NC}\n" "$username" "$ip" "$connect_time"
        done
    fi
    
    # Show web endpoint info
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    echo -e "\n${BLUE}═══ Web Status Endpoints ═══${NC}"
    echo -e "${CYAN}Simple: http://$server_ip:81/udpserver/online${NC}"
    echo -e "${CYAN}JSON:   http://$server_ip:81/udpserver/online_app${NC}"
}

# Show user connection history
show_user_history() {
    echo -e "\n${BLUE}Enter username to view history:${NC}"
    read -r username
    
    echo -e "\n${BLUE}═══ Connection History for $username ═══${NC}"
    local history_count=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM online_sessions WHERE username='$username';" 2>/dev/null || echo "0")
    
    if [[ $history_count -gt 0 ]]; then
        echo -e "${CYAN}IP Address\t\tConnect Time\t\t\tDisconnect Time\t\t\tStatus${NC}"
        echo -e "${CYAN}----------\t\t------------\t\t\t---------------\t\t\t------${NC}"
        sqlite3 "$USER_DB" "SELECT ip_address, connect_time, COALESCE(disconnect_time, 'Still Online'), status FROM online_sessions WHERE username='$username' ORDER BY connect_time DESC LIMIT 20;" 2>/dev/null | while IFS='|' read -r ip connect_time disconnect_time status; do
            if [[ "$status" == "online" ]]; then
                printf "${GREEN}%-15s\t%-24s\t%-24s\t%s${NC}\n" "$ip" "$connect_time" "$disconnect_time" "$status"
            else
                printf "${NC}%-15s\t%-24s\t%-24s\t%s${NC}\n" "$ip" "$connect_time" "$disconnect_time" "$status"
            fi
        done
        echo -e "\n${CYAN}Total sessions: $history_count${NC}"
    else
        echo -e "${YELLOW}No connection history found for user $username.${NC}"
        
        # Check if user exists
        local user_exists=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM users WHERE username='$username';" 2>/dev/null || echo "0")
        if [[ "$user_exists" -gt 0 ]]; then
            echo -e "${BLUE}Note: User exists but has no connection history yet.${NC}"
        else
            echo -e "${RED}Warning: User '$username' not found in database.${NC}"
        fi
    fi
}

# Setup web server (nginx)
setup_web_server() {
    echo -e "\n${BLUE}Setting up web server...${NC}"
    
    # Install nginx if not installed
    if ! command -v nginx &> /dev/null; then
        echo -e "${YELLOW}Installing nginx...${NC}"
        apt update && apt install -y nginx
    fi
    
    # Create nginx config
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
    
    location /udpserver/online_app {
        default_type application/json;
        add_header Access-Control-Allow-Origin *;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        try_files /udpserver/online_app =404;
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
        
        local server_ip=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        echo -e "${GREEN}✓ Web server configured successfully!${NC}"
        echo -e "${CYAN}Access URLs:${NC}"
        echo -e "${CYAN}  - http://$server_ip:81/udpserver/online${NC}"
        echo -e "${CYAN}  - http://$server_ip:81/udpserver/online_app${NC}"
    else
        echo -e "${RED}✗ Nginx configuration error${NC}"
    fi
}

# Check monitoring status
check_monitor_status() {
    echo -e "\n${BLUE}═══ Monitoring Status ═══${NC}"
    
    # Check online monitor
    if [[ -f "$MONITOR_PID_FILE" ]]; then
        local mon_pid=$(cat "$MONITOR_PID_FILE")
        if ps -p "$mon_pid" > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Online monitor is RUNNING (PID: $mon_pid)${NC}"
        else
            echo -e "${RED}✗ Online monitor is NOT running${NC}"
        fi
    else
        echo -e "${RED}✗ Online monitor is NOT running${NC}"
    fi
    
    # Check connection tracker
    if [[ -f "$TRACKER_PID_FILE" ]]; then
        local trk_pid=$(cat "$TRACKER_PID_FILE")
        if ps -p "$trk_pid" > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Connection tracker is RUNNING (PID: $trk_pid)${NC}"
        else
            echo -e "${RED}✗ Connection tracker is NOT running${NC}"
        fi
    else
        echo -e "${RED}✗ Connection tracker is NOT running${NC}"
    fi
    
    # Check nginx
    if systemctl is-active nginx >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Nginx is running${NC}"
    else
        echo -e "${RED}✗ Nginx is not running${NC}"
    fi
    
    # Check Hysteria service
    if systemctl is-active hysteria-server >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Hysteria server is running${NC}"
    else
        echo -e "${RED}✗ Hysteria server is not running${NC}"
    fi
    
    # Show current online count
    if [[ -f "$WEB_STATUS_FILE" ]]; then
        local count=$(cat "$WEB_STATUS_FILE")
        echo -e "\n${CYAN}Current online users: ${GREEN}$count${NC}"
    fi
    
    # Show web endpoints
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    echo -e "\n${BLUE}═══ Web Endpoints ═══${NC}"
    echo -e "${CYAN}http://$server_ip:81/udpserver/online${NC}"
    echo -e "${CYAN}http://$server_ip:81/udpserver/online_app${NC}"
}

# User management functions
add_user() {
    echo -e "\n${BLUE}Enter username:${NC}"
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
        stop_connection_tracker
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
    echo -e "${CYAN}   UDP Manager with Background Monitoring${NC}"
    echo -e "${GREEN}   Simple Loop Style - v2.1 FIXED${NC}"
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

# FIXED: Auto-start both monitors
if [[ ! -f "$MONITOR_PID_FILE" ]] || ! ps -p "$(cat $MONITOR_PID_FILE 2>/dev/null)" > /dev/null 2>&1; then
    echo -e "${YELLOW}Auto-starting online monitor...${NC}"
    start_online_monitor
    sleep 2
fi

if [[ ! -f "$TRACKER_PID_FILE" ]] || ! ps -p "$(cat $TRACKER_PID_FILE 2>/dev/null)" > /dev/null 2>&1; then
    echo -e "${YELLOW}Auto-starting connection tracker...${NC}"
    start_connection_tracker
    sleep 2
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
