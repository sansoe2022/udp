systemctl stop hysteria-online-monitor hysteria-tracker && cat > /usr/local/bin/hysteria-online-monitor.sh << 'EOF' && cat > /usr/local/bin/hysteria-tracker.sh << 'EOF2' && chmod +x /usr/local/bin/hysteria-{online-monitor,tracker}.sh && systemctl start hysteria-tracker && sleep 3 && systemctl start hysteria-online-monitor && echo "Fixed!" && sleep 20 && echo "DB: $(sqlite3 /etc/hysteria/udpusers.db 'SELECT COUNT(*) FROM online_sessions WHERE status="online";') | Web: $(cat /var/www/html/udpserver/online)"
#!/bin/bash
CONFIG_DIR="/etc/hysteria"
USER_DB="$CONFIG_DIR/udpusers.db"
WEB_DIR="/var/www/html/udpserver"
WEB_STATUS_FILE="$WEB_DIR/online"
WEB_APP_FILE="$WEB_DIR/online_app"
echo "Starting Monitor (15s)"
mkdir -p "$WEB_DIR" && chmod 777 "$WEB_DIR"
iteration=0
while true; do
    iteration=$((iteration + 1))
    _onli=$(timeout 10 sqlite3 "$USER_DB" "SELECT COUNT(DISTINCT session_id) FROM online_sessions WHERE status='online';" 2>/dev/null || echo "0")
    [[ ! "$_onli" =~ ^[0-9]+$ ]] && _onli=0
    echo "$_onli" > "$WEB_STATUS_FILE" 2>/dev/null
    echo "{\"onlines\":\"$_onli\",\"limite\":\"2500\"}" > "$WEB_APP_FILE" 2>/dev/null
    chmod 666 "$WEB_STATUS_FILE" "$WEB_APP_FILE" 2>/dev/null
    echo "[$(date '+%H:%M:%S')] #$iteration: $_onli users"
    sleep 15
done
EOF
#!/bin/bash
CONFIG_DIR="/etc/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.json"
USER_DB="$CONFIG_DIR/udpusers.db"
ONLINE_USERS_FILE="$CONFIG_DIR/online_users.log"
echo "Starting Tracker"
sqlite3 "$USER_DB" "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;" >/dev/null 2>&1
HYSTERIA_PORT=$(jq -r '.listen' "$CONFIG_FILE" 2>/dev/null | sed 's/^://' | cut -d: -f1)
[[ -z "$HYSTERIA_PORT" ]] && HYSTERIA_PORT="36712"
timeout 10 sqlite3 "$USER_DB" "UPDATE online_sessions SET status='offline', disconnect_time=datetime('now') WHERE status='online';" 2>/dev/null
(while true; do sleep 20; timestamp=$(date '+%Y-%m-%d %H:%M:%S'); timeout 10 sqlite3 "$USER_DB" "UPDATE online_sessions SET status='offline', disconnect_time='$timestamp' WHERE status='online' AND datetime(connect_time) < datetime('now', '-45 seconds');" 2>/dev/null; done) &
timeout_pid=$!
cleanup() { kill $timeout_pid 2>/dev/null; exit 0; }
trap cleanup SIGTERM SIGINT
journalctl -u hysteria-server -f -n 0 --no-pager 2>/dev/null | while read -r line; do
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    ip=$(echo "$line" | grep -oP '\[src:\K[0-9.]+(?=:)' | head -1)
    [[ -z "$ip" ]] && continue
    port=$(echo "$line" | grep -oP '\[src:[0-9.]+:\K[0-9]+(?=\])' | head -1)
    (flock -w 10 -x 200 || exit 1
    session_id=$(timeout 10 sqlite3 "$USER_DB" "SELECT session_id FROM online_sessions WHERE ip_address='$ip' AND status='online' LIMIT 1;" 2>/dev/null)
    if [[ -z "$session_id" ]]; then
        session_id="${ip}_${port}_$(date +%s%N)"
        username="user_${ip}"
        timeout 10 sqlite3 "$USER_DB" "INSERT INTO online_sessions (session_id, username, ip_address, port, connect_time, status) VALUES ('$session_id', '$username', '$ip', ${port:-0}, '$timestamp', 'online');" 2>/dev/null
        echo "[CONNECT] $username"
    else
        timeout 10 sqlite3 "$USER_DB" "UPDATE online_sessions SET connect_time='$timestamp' WHERE session_id='$session_id';" 2>/dev/null
    fi) 200>/var/lock/udp_sessions.lock
done
kill $timeout_pid 2>/dev/null
EOF2
