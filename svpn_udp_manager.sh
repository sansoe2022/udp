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
    journalctl -u hysteria-server -f --no-pager | while read line; do
        echo "DEBUG: $line"   # <-- Add this line
        if echo "$line" | grep -qE "Client connected"; then
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            local ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            local username="user_$ip"
            echo "DEBUG: CONNECT $username $ip $timestamp"
            if [[ -n "$ip" ]]; then
                sqlite3 "$USER_DB" "INSERT OR IGNORE INTO online_sessions (username, ip_address, connect_time, status) VALUES ('$username', '$ip', '$timestamp', 'online');"
                echo "$timestamp - $username ($ip) connected" >> "$ONLINE_USERS_FILE"
                update_web_status
            fi
        elif echo "$line" | grep -qE "TCP EOF|Client disconnected"; then
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            local ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            local username="user_$ip"
            echo "DEBUG: DISCONNECT $username $ip $timestamp"
            if [[ -n "$ip" ]]; then
                sqlite3 "$USER_DB" "UPDATE online_sessions SET disconnect_time='$timestamp', status='offline' WHERE username='$username' AND ip_address='$ip' AND status='online';"
                echo "$timestamp - $username ($ip) disconnected" >> "$ONLINE_USERS_FILE"
                update_web_status
            fi
        fi
    done
}

# Alternative method: Track connections via netstat
track_netstat_connections() {
    echo -e "\e[1;34mStarting netstat-based connection tracking...\e[0m"
    
    local hysteria_port=$(jq -r '.listen' "$CONFIG_FILE" | cut -d: -f2)
    if [[ -z "$hysteria_port" || "$hysteria_port" == "null" ]]; then
        echo -e "\e[1;31mCannot determine Hysteria port from config\e[0m"
        return
    fi
    
    # Background process to monitor connections
    (
        while true; do
            if [[ -f "$WEB_STATUS_ENABLED" ]]; then
                # Count active UDP connections on Hysteria port
                local active_count=$(netstat -un | grep ":$hysteria_port " | wc -l)
                
                # Alternative: use ss command if available
                if command -v ss >/dev/null 2>&1; then
                    active_count=$(ss -u -n | grep ":$hysteria_port " | wc -l)
                fi
                
                # Update web status with active connection count
                echo "$active_count" > "$WEB_STATUS_FILE"
                chmod 644 "$WEB_STATUS_FILE" 2>/dev/null
                
                echo "$(date): Active connections: $active_count" >> "$ONLINE_USERS_FILE"
            fi
            sleep 10
        done
    ) &
    
    echo -e "\e[1;32mNetstat monitoring started (updates every 10 seconds)\e[0m"
}
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

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_error() {
    echo -e "${RED}❌${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

check_command() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    else
        log_error "Required command '$1' not found"
        return 1
    fi
}

# debug log
debug_connection_tracking() {


echo "=== ENHANCED HYSTERIA CONNECTION TRACKING DEBUG ==="
echo "Timestamp: $(date)"
echo "User: $(whoami)"
echo

# 0. Check required tools
echo "0. Checking required tools..."
check_command sqlite3 || { log_error "sqlite3 is required but not installed"; exit 1; }
check_command jq || log_warning "jq not found - JSON parsing may fail"
check_command netstat || log_warning "netstat not found - network checks may fail"
echo

# 1. Enhanced database check
echo "1. Checking database..."
if [[ -f "$USER_DB" ]]; then
    log_success "Database exists: $USER_DB"
    
    # Check file permissions
    echo "Database permissions: $(ls -l "$USER_DB")"
    
    # Check if file is actually a SQLite database
    if file "$USER_DB" | grep -q "SQLite"; then
        log_success "File is a valid SQLite database"
    else
        log_error "File exists but is not a valid SQLite database"
    fi
    
    # Check tables
    echo -e "\nTables in database:"
    tables=$(sqlite3 "$USER_DB" ".tables" 2>/dev/null)
    if [[ -n "$tables" ]]; then
        echo "$tables"
    else
        log_error "No tables found or database is corrupted"
    fi
    
    # Check online_sessions table structure
    echo -e "\nTable structure for online_sessions:"
    if sqlite3 "$USER_DB" ".schema online_sessions" 2>/dev/null; then
        log_success "online_sessions table exists"
        
        # Check current data with better error handling
        echo -e "\nCurrent online sessions:"
        online_sessions=$(sqlite3 "$USER_DB" "SELECT username, ip_address, connect_time, status FROM online_sessions WHERE status='online' ORDER BY connect_time DESC;" 2>/dev/null)
        if [[ -n "$online_sessions" ]]; then
            echo "$online_sessions"
        else
            log_info "No online sessions found"
        fi
        
        # Get total count
        echo -e "\nTotal online count:"
        online_count=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM online_sessions WHERE status='online';" 2>/dev/null || echo "0")
        echo "$online_count"
        
        # Check for any sessions (online or offline)
        echo -e "\nTotal sessions (all statuses):"
        total_sessions=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM online_sessions;" 2>/dev/null || echo "0")
        echo "$total_sessions"
        
        if [[ "$total_sessions" -eq 0 ]]; then
            log_warning "No sessions recorded at all - connection tracking may not be working"
        fi
        
    else
        log_error "online_sessions table not found"
    fi
    
    # Check users table if it exists
    echo -e "\nChecking users table:"
    if sqlite3 "$USER_DB" ".schema users" 2>/dev/null >/dev/null; then
        user_count=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "0")
        log_success "Users table exists with $user_count users"
    else
        log_warning "Users table not found"
    fi
    
else
    log_error "Database not found: $USER_DB"
    log_info "Database directory: $(dirname "$USER_DB")"
    if [[ -d "$(dirname "$USER_DB")" ]]; then
        log_info "Directory exists, checking contents:"
        ls -la "$(dirname "$USER_DB")"
    else
        log_error "Directory does not exist: $(dirname "$USER_DB")"
    fi
fi

# 2. Enhanced log file check
echo -e "\n2. Checking log file..."
if [[ -f "$LOG_FILE" ]]; then
    log_success "Log file exists: $LOG_FILE"
    
    # Check file size and permissions
    log_file_size=$(ls -lh "$LOG_FILE" | awk '{print $5}')
    echo "Log file size: $log_file_size"
    echo "Log file permissions: $(ls -l "$LOG_FILE")"
    
    # Check if file is empty
    if [[ -s "$LOG_FILE" ]]; then
        echo -e "\nLast 10 lines of log:"
        tail -10 "$LOG_FILE"
        
        echo -e "\nSearching for connection patterns:"
        connect_count=$(grep -c -i "connect\|session\|client" "$LOG_FILE" 2>/dev/null || echo "0")
        echo "Total connection-related log entries: $connect_count"
        
        if [[ "$connect_count" -gt 0 ]]; then
            echo -e "\nRecent connection events:"
            grep -i "connect\|session\|client" "$LOG_FILE" | tail -5
        fi
        
        # Check for errors
        error_count=$(grep -c -i "error\|fail\|exception" "$LOG_FILE" 2>/dev/null || echo "0")
        echo -e "\nError count in logs: $error_count"
        if [[ "$error_count" -gt 0 ]]; then
            echo "Recent errors:"
            grep -i "error\|fail\|exception" "$LOG_FILE" | tail -3
        fi
        
    else
        log_warning "Log file is empty"
    fi
    
else
    log_error "Log file not found: $LOG_FILE"
    
    # Check if log directory exists
    log_dir=$(dirname "$LOG_FILE")
    if [[ -d "$log_dir" ]]; then
        log_info "Log directory exists: $log_dir"
        echo "Contents:"
        ls -la "$log_dir"
    else
        log_error "Log directory does not exist: $log_dir"
    fi
    
    # Check for alternative log locations
    echo -e "\nSearching for alternative Hysteria logs:"
    find /var/log -name "*hysteria*" -type f 2>/dev/null | head -5
    
    # Check journald logs
    echo -e "\nChecking systemd journal for Hysteria:"
    if systemctl list-units --type=service | grep -q hysteria; then
        echo "Recent Hysteria service logs:"
        journalctl -u hysteria-server --no-pager -n 10 2>/dev/null || log_warning "Could not access journal logs"
    fi
fi

# 3. Enhanced web status file check
echo -e "\n3. Checking web status file..."
if [[ -f "$WEB_STATUS_FILE" ]]; then
    log_success "Web status file exists: $WEB_STATUS_FILE"
    
    content=$(cat "$WEB_STATUS_FILE" 2>/dev/null || echo "error reading file")
    echo "Content: '$content'"
    echo "File permissions: $(ls -l "$WEB_STATUS_FILE")"
    
    # Check if content is numeric
    if [[ "$content" =~ ^[0-9]+$ ]]; then
        log_success "Content is numeric: $content"
    else
        log_warning "Content is not numeric"
    fi
    
    # Check web directory
    web_dir=$(dirname "$WEB_STATUS_FILE")
    if [[ -d "$web_dir" ]]; then
        log_info "Web directory exists: $web_dir"
        echo "Directory contents:"
        ls -la "$web_dir"
    fi
    
else
    log_error "Web status file not found: $WEB_STATUS_FILE"
    
    # Check if web directory exists
    web_dir=$(dirname "$WEB_STATUS_FILE")
    if [[ -d "$web_dir" ]]; then
        log_info "Web directory exists: $web_dir"
        echo "Directory contents:"
        ls -la "$web_dir"
    else
        log_error "Web directory does not exist: $web_dir"
        log_info "You may need to create it: mkdir -p $web_dir"
    fi
fi

# 4. Enhanced monitoring service check
echo -e "\n4. Checking monitoring service..."
if systemctl list-units --type=service | grep -q udp-web-status; then
    if systemctl is-active udp-web-status >/dev/null 2>&1; then
        log_success "UDP web status service is running"
        echo "Service status:"
        systemctl status udp-web-status --no-pager -l
        
        echo -e "\nService logs:"
        journalctl -u udp-web-status --no-pager -n 5 2>/dev/null
    else
        log_error "UDP web status service exists but is not running"
        echo "Service status:"
        systemctl status udp-web-status --no-pager -l
    fi
else
    log_error "UDP web status service not found"
    log_info "Available services with 'udp' in name:"
    systemctl list-units --type=service | grep -i udp || log_info "No UDP-related services found"
fi

# 5. Enhanced Hysteria service check
echo -e "\n5. Checking Hysteria service..."
hysteria_services=$(systemctl list-units --type=service | grep -i hysteria | awk '{print $1}' || echo "")
if [[ -n "$hysteria_services" ]]; then
    echo "Found Hysteria services:"
    echo "$hysteria_services"
    
    for service in $hysteria_services; do
        echo -e "\nChecking $service:"
        if systemctl is-active "$service" >/dev/null 2>&1; then
            log_success "$service is running"
        else
            log_error "$service is not running"
            echo "Try: systemctl start $service"
        fi
        
        echo "Service status:"
        systemctl status "$service" --no-pager -l | head -10
    done
else
    log_error "No Hysteria services found"
    log_info "Available services:"
    systemctl list-units --type=service | grep -E "(hysteria|proxy|vpn)" || log_info "No related services found"
fi

# 6. Enhanced network connections check
echo -e "\n6. Checking network connections..."
if [[ -f "$CONFIG_FILE" ]]; then
    log_success "Config file exists: $CONFIG_FILE"
    
    # Try to parse port with different methods
    if command -v jq >/dev/null 2>&1; then
        HYSTERIA_PORT=$(jq -r '.listen' "$CONFIG_FILE" 2>/dev/null | cut -d: -f2)
    else
        # Fallback without jq
        HYSTERIA_PORT=$(grep -o '"listen"[^,]*' "$CONFIG_FILE" | cut -d: -f3 | tr -d '"' | tr -d ' ' | tr -d '}')
    fi
    
    if [[ -n "$HYSTERIA_PORT" && "$HYSTERIA_PORT" != "null" && "$HYSTERIA_PORT" =~ ^[0-9]+$ ]]; then
        log_success "Hysteria port: $HYSTERIA_PORT"
        
        if command -v netstat >/dev/null 2>&1; then
            echo "Active UDP connections on port $HYSTERIA_PORT:"
            connection_count=$(netstat -un | grep ":$HYSTERIA_PORT " | wc -l)
            echo "Connection count: $connection_count"
            
            if [[ "$connection_count" -gt 0 ]]; then
                echo "Connection details (first 5):"
                netstat -un | grep ":$HYSTERIA_PORT " | head -5
            fi
            
            # Check if port is listening
            echo -e "\nListening status:"
            netstat -ln | grep ":$HYSTERIA_PORT " || log_warning "Port $HYSTERIA_PORT not listening"
        fi
        
        if command -v ss >/dev/null 2>&1; then
            echo -e "\nUsing ss command:"
            ss -un | grep ":$HYSTERIA_PORT" | wc -l | xargs echo "UDP connections:"
        fi
        
    else
        log_error "Could not determine Hysteria port from config"
        echo "Config file content preview:"
        head -20 "$CONFIG_FILE"
    fi
    
else
    log_error "Config file not found: $CONFIG_FILE"
    if [[ -d "$CONFIG_DIR" ]]; then
        log_info "Config directory contents:"
        ls -la "$CONFIG_DIR"
    else
        log_error "Config directory does not exist: $CONFIG_DIR"
    fi
fi

# 7. Enhanced manual test
echo -e "\n7. Manual test - database operations..."
if [[ -f "$USER_DB" ]]; then
    # Test database connectivity
    if sqlite3 "$USER_DB" "SELECT 1;" >/dev/null 2>&1; then
        log_success "Database is accessible"
        
        # Test insert capability
        test_username="debug_test_$(date +%s)"
        if sqlite3 "$USER_DB" "INSERT OR IGNORE INTO online_sessions (username, ip_address, connect_time, status) VALUES ('$test_username', '192.168.1.100', datetime('now'), 'online');" 2>/dev/null; then
            log_success "Database insert test successful"
            
            # Count after insert
            count_after=$(sqlite3 "$USER_DB" "SELECT COUNT(*) FROM online_sessions WHERE status='online';" 2>/dev/null || echo "0")
            echo "Online count after test insert: $count_after"
            
            # Test web status file update
            if echo "$count_after" > "$WEB_STATUS_FILE" 2>/dev/null; then
                log_success "Web status file update successful"
                chmod 644 "$WEB_STATUS_FILE" 2>/dev/null
                
                # Verify content
                actual_content=$(cat "$WEB_STATUS_FILE" 2>/dev/null || echo "error")
                echo "Web status file content: '$actual_content'"
                
                if [[ "$actual_content" == "$count_after" ]]; then
                    log_success "Web status file content matches database count"
                else
                    log_error "Web status file content mismatch"
                fi
            else
                log_error "Failed to update web status file"
            fi
            
            # Clean up test data
            sleep 1
            sqlite3 "$USER_DB" "DELETE FROM online_sessions WHERE username='$test_username';" 2>/dev/null
            log_info "Test data cleaned up"
            
        else
            log_error "Database insert test failed"
        fi
        
    else
        log_error "Database is not accessible or corrupted"
    fi
else
    log_error "Cannot perform manual test - database not found"
fi

# 8. Additional system checks
echo -e "\n8. Additional system checks..."

# Check disk space
echo "Disk space for critical directories:"
df -h /etc /var/log /var/www 2>/dev/null | grep -E "(Filesystem|/etc|/var/log|/var/www)" || log_warning "Could not check disk space"

# Check system load
echo -e "\nSystem load:"
uptime

# Check for any hysteria processes
echo -e "\nHysteria processes:"
ps aux | grep -i hysteria | grep -v grep || log_info "No Hysteria processes found"

# Check recent system logs for hysteria
echo -e "\nRecent system logs mentioning hysteria:"
grep -i hysteria /var/log/syslog 2>/dev/null | tail -3 || log_info "No recent system logs found"

echo -e "\n=== DEBUGGING COMPLETE ==="
echo
echo -e "${BLUE}=== SUMMARY RECOMMENDATIONS ===${NC}"

# Generate recommendations based on findings
if [[ ! -f "$USER_DB" ]]; then
    echo "🔧 DATABASE: Create the database and tables (run main script option 13)"
fi

if [[ ! -f "$LOG_FILE" ]]; then
    echo "🔧 LOGGING: Configure Hysteria logging in config file"
fi

if ! systemctl is-active udp-web-status >/dev/null 2>&1; then
    echo "🔧 MONITORING: Start the monitoring service (main script option 15)"
fi

if ! systemctl list-units --type=service | grep -q hysteria || ! systemctl is-active hysteria-server >/dev/null 2>&1; then
    echo "🔧 SERVICE: Start Hysteria server service"
fi

if [[ ! -f "$WEB_STATUS_FILE" ]]; then
    echo "🔧 WEB STATUS: Create web status file and directory structure"
fi

echo
echo "🌐 TEST WEB ENDPOINT: curl http://localhost:81/udpserver/online"
echo "📊 MONITOR LOGS: tail -f $LOG_FILE"
echo "🔍 CHECK SERVICE: systemctl status hysteria-server"
echo "💾 QUERY DATABASE: sqlite3 $USER_DB 'SELECT * FROM online_sessions;'"
echo
echo "For more help, run the main management script and use the built-in options."
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


# Add this function to your script (insert it before the show_banner function)

check_web_status() {
    echo -e "\n\e[1;34m=== Web Status Check ===\e[0m"
    
    if [[ -f "$WEB_STATUS_ENABLED" ]]; then
        echo -e "\e[1;32m✓ Web status is enabled\e[0m"
        
        # Check if service is running
        if systemctl is-active udp-web-status >/dev/null 2>&1; then
            echo -e "\e[1;32m✓ Web status service is running\e[0m"
        else
            echo -e "\e[1;31m❌ Web status service is not running\e[0m"
            echo -e "\e[1;33mTrying to start service...\e[0m"
            systemctl start udp-web-status
        fi
        
        # Check if nginx is running
        if systemctl is-active nginx >/dev/null 2>&1; then
            echo -e "\e[1;32m✓ Nginx is running\e[0m"
        else
            echo -e "\e[1;31m❌ Nginx is not running\e[0m"
            echo -e "\e[1;33mTrying to start nginx...\e[0m"
            systemctl start nginx
        fi
        
        # Check web status file
        if [[ -f "$WEB_STATUS_FILE" ]]; then
            local current_count=$(cat "$WEB_STATUS_FILE" 2>/dev/null || echo "error")
            echo -e "\e[1;32m✓ Web status file exists\e[0m"
            echo -e "\e[1;36mCurrent online count: $current_count\e[0m"
        else
            echo -e "\e[1;31m❌ Web status file not found\e[0m"
            echo -e "\e[1;33mCreating web status file...\e[0m"
            update_web_status
        fi
        
        # Test the endpoint
        local server_ip=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        echo -e "\n\e[1;34mTesting endpoint:\e[0m"
        echo -e "\e[1;36mURL: http://$server_ip:81/udpserver/online\e[0m"
        
        # Test locally
        local test_result=$(curl -s http://localhost:81/udpserver/online 2>/dev/null || echo "connection_failed")
        if [[ "$test_result" =~ ^[0-9]+$ ]]; then
            echo -e "\e[1;32m✓ Local test successful: $test_result\e[0m"
        else
            echo -e "\e[1;31m❌ Local test failed: $test_result\e[0m"
        fi
        
    else
        echo -e "\e[1;31m❌ Web status is disabled\e[0m"
        echo -e "\e[1;33mUse option 15 to enable web status\e[0m"
    fi
}

# Fix the enable_logging function to ensure log directory and file exist
enable_logging() {
    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Create log file if it doesn't exist
    touch "$LOG_FILE"
    
    # Set proper permissions
    chmod 644 "$LOG_FILE"
    
    # Update config with logging
    if [[ -f "$CONFIG_FILE" ]]; then
        jq '.log.level = "info" | .log.file = "/var/log/hysteria/hysteria.log"' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        echo -e "\e[1;32mLogging enabled in configuration\e[0m"
    else
        echo -e "\e[1;31mConfig file not found: $CONFIG_FILE\e[0m"
    fi
}

# Enhanced start_monitoring function with better log file handling
start_monitoring() {
    echo -e "\e[1;34mStarting connection monitoring (journald mode)...\e[0m"
    stop_monitoring  # Always stop previous tracker
    (track_connections) &
    echo $! > "$TRACKER_PID_FILE"
    echo -e "\e[1;32mConnection monitoring started in background (systemd journal).\e[0m"
    echo -e "\e[1;36mYou can monitor logs with: journalctl -u hysteria-server -f --no-pager\e[0m"
}

# Add this function to check and fix hysteria configuration
check_hysteria_config() {
    echo -e "\n\e[1;34m=== Checking Hysteria Configuration ===\e[0m"
    
    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "\e[1;32m✓ Config file exists\e[0m"
        
        # Check if log section exists
        local has_log_section=$(jq -r '.log' "$CONFIG_FILE" 2>/dev/null)
        if [[ "$has_log_section" == "null" ]]; then
            echo -e "\e[1;33m⚠ Log section missing from config\e[0m"
            echo -e "\e[1;33mAdding log configuration...\e[0m"
            
            # Add log section
            jq '. + {"log": {"level": "info", "file": "/var/log/hysteria/hysteria.log"}}' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            echo -e "\e[1;32m✓ Log configuration added\e[0m"
        else
            echo -e "\e[1;32m✓ Log section exists in config\e[0m"
        fi
        
        # Verify log file path in config
        local log_file_in_config=$(jq -r '.log.file' "$CONFIG_FILE" 2>/dev/null)
        if [[ "$log_file_in_config" == "/var/log/hysteria/hysteria.log" ]]; then
            echo -e "\e[1;32m✓ Log file path is correct in config\e[0m"
        else
            echo -e "\e[1;33m⚠ Log file path incorrect in config: $log_file_in_config\e[0m"
            echo -e "\e[1;33mFixing log file path...\e[0m"
            jq '.log.file = "/var/log/hysteria/hysteria.log"' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            echo -e "\e[1;32m✓ Log file path fixed\e[0m"
        fi
        
    else
        echo -e "\e[1;31m❌ Config file not found: $CONFIG_FILE\e[0m"
        echo -e "\e[1;33mPlease ensure Hysteria is properly installed\e[0m"
    fi
}

# Add this to your menu - insert option 21 before option 20 (Exit)
# In the show_menu function, add:
# echo "21. Check/Fix configuration"

# And in the case statement, add:
# 21) check_hysteria_config ;;

# Also update the exit option numbers from 20 to 21



# Stop connection monitoring
stop_monitoring() {
    if [[ -f "$TRACKER_PID_FILE" ]]; then
        local pid=$(cat "$TRACKER_PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            kill "$pid"
            echo -e "\e[1;32mStopped previous monitoring process (PID $pid).\e[0m"
        fi
        rm -f "$TRACKER_PID_FILE"
    fi
    pkill -f "journalctl -u hysteria-server -f --no-pager" 2>/dev/null
    pkill -f "netstat.*$CONFIG_DIR"
    pkill -f "ss.*$CONFIG_DIR"
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
    echo "18. Debug connection tracking"
    echo "19. Cleanup old sessions"
    echo "20. Uninstall server"
    echo "21. Check/Fix configuration"
    echo -e "22. Exit\e[0m"
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
        18) debug_connection_tracking ;;
        19) cleanup_sessions ;;
        20) uninstall_server; exit 0 ;;
        21) check_hysteria_config ;;
        22) clear; exit 0 ;;
        *) echo -e "\e[1;31mInvalid choice. Please try again.\e[0m" ;;
    esac
done
