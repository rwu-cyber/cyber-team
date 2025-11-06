#!/bin/sh
# Minimal SSH Monitor & Control - POSIX compliant
# Works on: Debian, Ubuntu, RHEL, CentOS, Alpine, etc.
# i might have vibe coded this

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Must run as root"
    exit 1
fi

case "$1" in
    monitor|m)
        echo "=== Active SSH Sessions ==="
        who | grep pts || w | grep pts
        echo ""
        echo "=== Live Auth Monitoring (Ctrl+C to stop) ==="
        # Try multiple log locations
        if [ -f /var/log/auth.log ]; then
            tail -f /var/log/auth.log | grep --line-buffered -i sshd
        elif [ -f /var/log/secure ]; then
            tail -f /var/log/secure | grep --line-buffered -i sshd
        elif command -v journalctl >/dev/null 2>&1; then
            journalctl -u sshd -f
        else
            echo "Error: Cannot find auth logs. Try: journalctl -u sshd -f"
        fi
        ;;
    
    active|a)
        echo "=== SSH Connections ==="
        netstat -tnp 2>/dev/null | grep sshd | grep ESTABLISHED || ss -tnp 2>/dev/null | grep sshd
        echo ""
        echo "=== Logged In Users ==="
        w
        ;;
    
    block|b)
        [ -z "$2" ] && echo "Usage: $0 block <IP>" && exit 1
        iptables -I INPUT -s "$2" -j DROP && echo "Blocked: $2" || echo "Failed to block"
        ;;
    
    unblock|u)
        [ -z "$2" ] && echo "Usage: $0 unblock <IP>" && exit 1
        iptables -D INPUT -s "$2" -j DROP 2>/dev/null && echo "Unblocked: $2" || echo "Not blocked"
        ;;
    
    kill|k)
        [ -z "$2" ] && echo "Usage: $0 kill <IP>" && exit 1
        echo "Killing SSH sessions from $2..."
        ps aux | grep "[s]shd.*$2" | awk '{print $2}' | xargs -r kill -9
        echo "Done"
        ;;
    
    blockall|x)
        [ -z "$2" ] && echo "Usage: $0 blockall <IP>" && exit 1
        ps aux | grep "[s]shd.*$2" | awk '{print $2}' | xargs -r kill -9
        iptables -I INPUT -s "$2" -j DROP
        echo "Killed sessions and blocked: $2"
        ;;
    
    list|l)
        echo "=== Blocked IPs ==="
        iptables -L INPUT -n | grep DROP | awk '{print $4}' | grep -v "0.0.0.0"
        ;;
    
    *)
        echo "SSH Monitor & Control"
        echo ""
        echo "Usage: $0 <command> [IP]"
        echo ""
        echo "Commands:"
        echo "  monitor (m)      - Watch SSH connections live"
        echo "  active (a)       - Show active connections"
        echo "  block (b) <IP>   - Block IP address"
        echo "  unblock (u) <IP> - Unblock IP address"
        echo "  kill (k) <IP>    - Kill sessions from IP"
        echo "  blockall (x) <IP>- Kill sessions AND block IP"
        echo "  list (l)         - List blocked IPs"
        echo ""
        echo "Examples:"
        echo "  $0 m                  # Monitor"
        echo "  $0 x 10.0.0.100       # Block and kill"
        echo "  $0 block 10.0.0.100   # Just block"
        ;;
esac
