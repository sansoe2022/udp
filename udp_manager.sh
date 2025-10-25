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

mkdir -p "$CONFIG_DIR"
mkdir -p "/var/log/hysteria"
mkdir -p "$WEB_DIR"
touch "$USER_DB"
touch "$ONLINE_USERS_FILE"

# Ensure web files exist with proper permissions
echo "0" > "$WEB_STATUS_FILE"
echo '{"onlines":"0","limite":"2500"}' > "$WEB_APP_FILE"
chmod 666 "$WEB_STATUS_FILE" "$WEB_APP_FILE"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Initialize database
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
    
    # Enable WAL mode for better concurrency
    sqlite3 "$USER_DB" "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;" >/dev/null 2>&1
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

# Setup online monitor systemd service
setup_online_monitor_service() {
    echo -e "${BLUE}Setting up online-monitor service...${NC}"
    
    cat > /etc/systemd/system/hysteria-online-monitor.service << 'EOF'
[Unit]
Description=Hysteria Online Users Monitor
After=hysteria-server.service hysteria-tracker.service
Requires=hysteria-server.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc/hysteria
ExecStart=/usr/local/bin/hysteria-online-monitor.sh
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    cat > /usr/local/bin/hysteria-online-monitor.sh << 'MONITOREOF'
#!/bin/bash

CONFIG_DIR="/etc/hysteria"
USER_DB="$CONFIG_DIR/udpusers.db"
WEB_DIR="/var/www/html/udpserver"
WEB_STATUS_FILE="$WEB_DIR/online"
WEB_APP_FILE="$WEB_DIR/online_app"

echo "Starting Online Users Monitor"
echo "Update interval: 15 seconds"
echo "Database: $USER_DB"

mkdir -p "$WEB_DIR"
chmod 777 "$WEB_DIR"

iteration=0

while true; do
    iteration=$((iteration + 1))
    
    # Simple query without PRAGMA
    _onli=$(sqlite3 "$USER_DB" "SELECT COUNT(DISTINCT session_id) FROM online_sessions WHERE status='online';" 2>/dev/null | tail -1)
    
    # Ensure numeric
    if ! [[ "$_onli" =~ ^[0-9]+$ ]]; then
        _onli=0
    fi
    
    # Write files
    echo "$_onli" > "$WEB_STATUS_FILE" 2>/dev/null
    echo "{\"onlines\":\"$_onli\",\"limite\":\"2500\"}" > "$WEB_APP_FILE" 2>/dev/null
    chmod 666 "$WEB_STATUS_FILE" "$WEB_APP_FILE" 2>/dev/null
    
    echo "[$(date '+%H:%M:%S')] #$iteration: $_onli users online"
    
    # Update every 15 seconds
    sleep 15
done
MONITOREOF

    chmod +x /usr/local/bin/hysteria-online-monitor.sh
    systemctl daemon-reload
    systemctl enable hysteria-online-monitor
    
    echo -e "${GREEN}✓ Online-monitor service created${NC}"
}

# Setup tracker systemd service
setup_tracker_service() {
    echo -e "${BLUE}Setting up hysteria-tracker service...${NC}"
    
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

    cat > /usr/local/bin/hysteria-tracker.sh << 'TRACKEREOF'
#!/bin/bash

CONFIG_DIR="/etc/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.json"
USER_DB="$CONFIG_DIR/udpusers.db"
ONLINE_USERS_FILE="$CONFIG_DIR/online_users.log"

echo "Starting Hysteria Connection Tracker"
echo "Disconnect timeout: 45 seconds"

# Enable WAL mode and set busy timeout
sqlite3 "$USER_DB" << 'SQL'
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
SQL

# Get port
HYSTERIA_PORT=$(jq -r '.listen' "$CONFIG_FILE" 2>/dev/null | sed 's/^://' | cut -d: -f1)
[[ -z "$HYSTERIA_PORT" ]] && HYSTERIA_PORT="36712"

echo "Monitoring port: $HYSTERIA_PORT"

# Clear stale connections
sqlite3 "$USER_DB" "UPDATE online_sessions SET status='offline', disconnect_time=datetime('now') WHERE status='online';" 2>/dev/null

# Background timeout checker - runs every 20 seconds
(
    while true; do
        sleep 20
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        
        # Mark offline after 45 seconds of no activity
        sqlite3 "$USER_DB" "UPDATE online_sessions SET status='offline', disconnect_time='$timestamp' WHERE status='online' AND datetime(connect_time) < datetime('now', '-45 seconds');" 2>/dev/null
    done
) &
timeout_pid=$!

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
        flock -w 10 -x 200 || exit 1
        
        session_id=$(sqlite3 "$USER_DB" "SELECT session_id FROM online_sessions WHERE ip_address='$ip' AND status='online' LIMIT 1;" 2>/dev/null)
        
        if [[ -z "$session_id" ]]; then
            session_id="${ip}_${port}_$(date +%s%N)"
            username="user_${ip}"
            sqlite3 "$USER_DB" "INSERT INTO online_sessions (session_id, username, ip_address, port, connect_time, status) VALUES ('$session_id', '$username', '$ip', ${port:-0}, '$timestamp', 'online');" 2>/dev/null
            echo "$timestamp - $username ($ip:${port:-unknown}) connected" >> "$ONLINE_USERS_FILE"
            echo "[CONNECT] $username from $ip:${port:-unknown}"
        else
            sqlite3 "$USER_DB" "UPDATE online_sessions SET connect_time='$timestamp' WHERE session_id='$session_id';" 2>/dev/null
        fi
    ) 200>/var/lock/udp_sessions.lock
done

kill $timeout_pid 2>/dev/null
TRACKEREOF

    chmod +x /usr/local/bin/hysteria-tracker.sh
    systemctl daemon-reload
    systemctl enable hysteria-tracker
    
    echo -e "${GREEN}✓ Hysteria-tracker service created${NC}"
}

# Start online monitor
start_online_monitor() {
    echo -e "${BLUE}Starting online monitor...${NC}"
    
    if [[ ! -f "/etc/systemd/system/hysteria-online-monitor.service" ]]; then
        echo -e "${YELLOW}Creating service...${NC}"
        setup_online_monitor_service
    fi
    
    systemctl restart hysteria-online-monitor
    sleep 2
    
    if systemctl is-active hysteria-online-monitor >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Online monitor started${NC}"
        echo -e "${CYAN}Updates every 15 seconds${NC}"
    else
        echo -e "${RED}✗ Failed to start${NC}"
    fi
}

# Stop online monitor
stop_online_monitor() {
    systemctl stop hysteria-online-monitor
    echo -e "${GREEN}✓ Online monitor stopped${NC}"
}

# Start connection tracker
start_connection_tracker() {
    echo -e "${BLUE}Starting connection tracker...${NC}"
    
    if [[ ! -f "/etc/systemd/system/hysteria-tracker.service" ]]; then
        echo -e "${YELLOW}Creating service...${NC}"
        setup_tracker_service
    fi
    
    systemctl restart hysteria-tracker
    sleep 2
    
    if systemctl is-active hysteria-tracker >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Connection tracker started${NC}"
        echo -e "${CYAN}Disconnect timeout: 45 seconds${NC}"
    else
        echo -e "${RED}✗ Failed to start${NC}"
    fi
}

# Stop connection tracker
stop_connection_tracker() {
    systemctl stop hysteria-tracker
    echo -e "${GREEN}✓ Connection tracker stopped${NC}"
}

# Check monitor status
check_monitor_status() {
    echo -e "\n${BLUE}═══ Monitoring Status ═══${NC}"
    
    # Online monitor
    if systemctl is-active hysteria-online-monitor >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Online monitor is RUNNING${NC}"
        echo -e "${CYAN}  Update interval: 15 seconds${NC}"
    else
        echo -e "${RED}✗ Online monitor is NOT RUNNING${NC}"
    fi
    
    # Connection tracker
    if systemctl is-active hysteria-tracker >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Connection tracker is RUNNING${NC}"
        echo -e "${CYAN}  Disconnect timeout: 45 seconds${NC}"
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
    
    echo -e "\n${BLUE}═══ User Count Status ═══${NC}"
    
    # Database count
    local db_count=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM online_sessions WHERE status='online';" 2>/dev/null || echo "0")
    echo -e "${CYAN}Database count: $db_count${NC}"
    
    # Web file count
    local web_count=$(cat "$WEB_STATUS_FILE" 2>/dev/null || echo "0")
    echo -e "${CYAN}Web file count: $web_count${NC}"
    
    # Check if they match
    if [[ "$db_count" == "$web_count" ]]; then
        echo -e "${GREEN}✓ Counts are synchronized${NC}"
    else
        echo -e "${YELLOW}⚠ Counts differ (normal if just updated)${NC}"
    fi
    
    # Show web URLs
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    if [[ -n "$server_ip" ]]; then
        echo -e "\n${BLUE}═══ Access URLs ═══${NC}"
        echo -e "${CYAN}Dashboard: http://${server_ip}/udpserver/${NC}"
        echo -e "${CYAN}API Text:  http://${server_ip}/udpserver/online${NC}"
        echo -e "${CYAN}API JSON:  http://${server_ip}/udpserver/online_app${NC}"
    fi
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
    echo -e "\n${BLUE}Setting up web server...${NC}"
    
    if ! command -v nginx &> /dev/null; then
        echo -e "${YELLOW}Installing nginx...${NC}"
        apt update && apt install -y nginx
        systemctl start nginx
        systemctl enable nginx
    fi
    
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
    
    if ! grep -q "sites-enabled" /etc/nginx/nginx.conf; then
        sed -i '/include \/etc\/nginx\/conf.d\/\*.conf;/a \    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
    fi
    
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
    
    location = /udpserver/online {
        default_type text/plain;
        add_header Content-Type "text/plain; charset=utf-8";
        add_header Access-Control-Allow-Origin *;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }
    
    location = /udpserver/online_app {
        default_type application/json;
        add_header Content-Type "application/json; charset=utf-8";
        add_header Access-Control-Allow-Origin *;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }
}
NGINXEOF

    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/udp-status /etc/nginx/sites-enabled/udp-status
    
    mkdir -p "$WEB_DIR"
    chmod 755 "$WEB_DIR"
    echo "0" > "$WEB_STATUS_FILE"
    echo '{"onlines":"0","limite":"2500"}' > "$WEB_APP_FILE"
    chmod 666 "$WEB_STATUS_FILE" "$WEB_APP_FILE"
    
    cat > "$WEB_DIR/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <title>UDP Server Status</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.95);
            padding: 60px 80px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            text-align: center;
            max-width: 500px;
            width: 100%;
        }
        h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
        .subtitle { color: #666; font-size: 14px; margin-bottom: 40px; }
        .count-wrapper {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px;
            border-radius: 15px;
            margin: 30px 0;
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
        }
        .count {
            font-size: 100px;
            color: #fff;
            font-weight: bold;
            line-height: 1;
            text-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }
        .label {
            font-size: 18px;
            color: rgba(255, 255, 255, 0.9);
            margin-top: 15px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        .status {
            display: inline-block;
            width: 12px;
            height: 12px;
            background: #4caf50;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .footer {
            margin-top: 30px;
            color: #999;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>UDP Server Monitor</h1>
        <p class="subtitle"><span class="status"></span>Live Status</p>
        <div class="count-wrapper">
            <div class="count" id="count">--</div>
            <div class="label">Online Users</div>
        </div>
        <div class="footer">Auto-refresh every 5 seconds</div>
    </div>
    <script>
        async function updateCount() {
            try {
                const response = await fetch('/udpserver/online_app');
                const data = await response.json();
                document.getElementById('count').textContent = data.onlines;
            } catch (error) {
                document.getElementById('count').textContent = 'Error';
            }
        }
        updateCount();
        setInterval(updateCount, 5000);
    </script>
</body>
</html>
HTMLEOF

    chmod 644 "$WEB_DIR/index.html"
    
    nginx -t && systemctl reload nginx
    
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    echo -e "${GREEN}✓ Web server configured${NC}"
    echo -e "${CYAN}Dashboard: http://${server_ip}/udpserver/${NC}"
}

# Force sync database to web files
force_sync() {
    echo -e "\n${BLUE}Force syncing database to web files...${NC}"
    
    local count=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM online_sessions WHERE status='online';" 2>/dev/null || echo "0")
    
    echo "$count" > "$WEB_STATUS_FILE"
    echo "{\"onlines\":\"$count\",\"limite\":\"2500\"}" > "$WEB_APP_FILE"
    chmod 666 "$WEB_STATUS_FILE" "$WEB_APP_FILE"
    
    echo -e "${GREEN}✓ Synced: $count users${NC}"
    echo -e "${CYAN}Database: $count${NC}"
    echo -e "${CYAN}Web file: $(cat $WEB_STATUS_FILE)${NC}"
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
        echo -e "${GREEN}✓ User added${NC}"
        update_userpass_config
        systemctl restart hysteria-server
    else
        echo -e "${RED}✗ Failed${NC}"
    fi
}

edit_user() {
    echo -e "\n${BLUE}Enter username to edit:${NC}"
    read -r username
    echo -e "${BLUE}Enter new password:${NC}"
    read -r password
    
    sqlite3 "$USER_DB" "UPDATE users SET password = '$password' WHERE username = '$username';" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✓ User updated${NC}"
        update_userpass_config
        systemctl restart hysteria-server
    else
        echo -e "${RED}✗ Failed${NC}"
    fi
}

delete_user() {
    echo -e "\n${BLUE}Enter username to delete:${NC}"
    read -r username
    
    sqlite3 "$USER_DB" "DELETE FROM users WHERE username = '$username';" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✓ User deleted${NC}"
        update_userpass_config
        systemctl restart hysteria-server
    else
        echo -e "${RED}✗ Failed${NC}"
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
    echo -e "${GREEN}✓ Domain changed${NC}"
    systemctl restart hysteria-server
}

change_obfs() {
    echo -e "\n${BLUE}Enter new obfuscation:${NC}"
    read -r obfs
    jq ".obfs = \"$obfs\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo -e "${GREEN}✓ Obfuscation changed${NC}"
    systemctl restart hysteria-server
}

change_up_speed() {
    echo -e "\n${BLUE}Enter new upload speed (Mbps):${NC}"
    read -r up_speed
    jq ".up_mbps = $up_speed | .up = \"$up_speed Mbps\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo -e "${GREEN}✓ Upload speed changed${NC}"
    systemctl restart hysteria-server
}

change_down_speed() {
    echo -e "\n${BLUE}Enter new download speed (Mbps):${NC}"
    read -r down_speed
    jq ".down_mbps = $down_speed | .down = \"$down_speed Mbps\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo -e "${GREEN}✓ Download speed changed${NC}"
    systemctl restart hysteria-server
}

cleanup_sessions() {
    local cleaned=$(sqlite3 "$USER_DB" "DELETE FROM online_sessions WHERE status='offline' AND datetime(disconnect_time) < datetime('now', '-7 days'); SELECT changes();" 2>/dev/null)
    echo -e "${GREEN}✓ Cleaned $cleaned old sessions${NC}"
}

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

uninstall_server() {
    echo -e "\n${RED}═══ WARNING ═══${NC}"
    echo -e "${YELLOW}Are you sure? (yes/no):${NC}"
    read -r confirm
    
    if [[ "$confirm" == "yes" ]]; then
        systemctl stop hysteria-online-monitor hysteria-tracker hysteria-server
        systemctl disable hysteria-online-monitor hysteria-tracker hysteria-server
        rm -f /etc/systemd/system/hysteria-{online-monitor,tracker,server}.service
        rm -f /usr/local/bin/hysteria-{online-monitor,tracker}.sh
        systemctl daemon-reload
        rm -rf "$CONFIG_DIR" "$WEB_DIR"
        rm -f /usr/local/bin/hysteria
        rm -f /etc/nginx/sites-{enabled,available}/udp-status
        systemctl reload nginx
        echo -e "${GREEN}✓ Uninstalled${NC}"
    else
        echo -e "${YELLOW}Cancelled${NC}"
    fi
}

show_banner() {
    clear
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${CYAN}   UDP Manager - Complete Edition${NC}"
    echo -e "${GREEN}   Auto-start | Terminal Independent${NC}"
    echo -e "${YELLOW}   15s Updates | 45s Disconnect Timeout${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
}

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
    echo -e "${YELLOW}23. Force sync DB to web files${NC}"
    echo -e "${BLUE}══════════════════════════════════${NC}"
    echo -n "Enter your choice: "
}

# Initialize
init_database

show_banner

# Auto-start services if not running
if ! systemctl is-active hysteria-online-monitor >/dev/null 2>&1; then
    echo -e "${YELLOW}Auto-starting online monitor...${NC}"
    [[ ! -f "/etc/systemd/system/hysteria-online-monitor.service" ]] && setup_online_monitor_service
    systemctl start hysteria-online-monitor
    sleep 1
fi

if ! systemctl is-active hysteria-tracker >/dev/null 2>&1; then
    echo -e "${YELLOW}Auto-starting connection tracker...${NC}"
    [[ ! -f "/etc/systemd/system/hysteria-tracker.service" ]] && setup_tracker_service
    systemctl start hysteria-tracker
    sleep 1
fi

# Main loop
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
            echo -e "${YELLOW}Exiting (services continue in background)...${NC}"
            exit 0
            ;;
        23) force_sync ;;
        *) 
            echo -e "${RED}✗ Invalid choice${NC}"
            ;;
    esac
    
    echo -e "\n${CYAN}Press Enter to continue...${NC}"
    read
    clear
    show_banner
done
