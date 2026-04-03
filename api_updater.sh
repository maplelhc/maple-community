#!/data/data/com.termux/files/usr/bin/bash
LOG_FILE="$HOME/backend_tunnel.log"
HTML_FILE="/sdcard/Android/media/maple.html"
API_CONSTANT="API_BASE"
CHECK_INTERVAL=10
touch /tmp/last_backend_url
get_backend_url() {
    awk '/Forwarding HTTP traffic from/ {print $NF}' "$LOG_FILE" | tail -1
}
update_frontend() {
    local new_url=$1
    cp "$HTML_FILE" "$HTML_FILE.bak"
    sed -i "s|^const $API_CONSTANT = .*|const $API_CONSTANT = '$new_url';|" "$HTML_FILE"
    echo "$(date): 已更新 API_BASE 为 $new_url"
}
echo "$(date): 启动自动更新监控脚本"
while true; do
    backend_url=$(get_backend_url)
    if [ -n "$backend_url" ]; then
        last_url=$(cat /tmp/last_backend_url 2>/dev/null)
        if [ "$last_url" != "$backend_url" ]; then
            echo "$backend_url" > /tmp/last_backend_url
            update_frontend "$backend_url"
        fi
    fi
    sleep $CHECK_INTERVAL
done
