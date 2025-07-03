#!/bin/bash

# Universal NETrix - Network Configuration Script - Professional Edition
# Compatible with ALL Linux distributions (systemd/non-systemd)
# Author: Seehrum
# Version: 4.0 - Production Ready

# Root privileges check
[[ $EUID -ne 0 ]] && { echo "Error: Run as root - sudo $0"; exit 1; }

# Essential commands verification
for cmd in dialog iw ip; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Error: Missing required command: $cmd"; exit 1; }
done

# Global configuration
readonly TEMP_FILE=$(mktemp)
readonly WPA_CONFIG="/tmp/wpa_temp.conf"
readonly WPA_CTRL_DIR="/var/run/wpa_supplicant"
readonly RESOLV_CONF="/etc/resolv.conf"
readonly RESOLV_BACKUP="/etc/resolv.conf.backup"
readonly LOG_FILE="/var/log/network-config.log"

# Runtime variables
SELECTED_INTERFACE=""
SELECTED_SSID=""
WIFI_PASSWORD=""

# DNS servers (Primary, Secondary, Fallback)
readonly DNS_SERVERS=("8.8.8.8" "1.1.1.1" "9.9.9.9" "208.67.222.222")

# Cleanup handler
cleanup() {
    rm -f "$TEMP_FILE" "$WPA_CONFIG" 2>/dev/null
    clear
}
trap cleanup EXIT INT TERM

# Enhanced logging for errors
log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $1" >> "$LOG_FILE" 2>/dev/null
}

log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO: $1" >> "$LOG_FILE" 2>/dev/null
}

# Universal service management
manage_service() {
    local action=$1
    local service=$2
    
    if command -v systemctl >/dev/null 2>&1; then
        systemctl $action $service 2>/dev/null
    elif command -v service >/dev/null 2>&1; then
        service $service $action 2>/dev/null
    elif command -v sv >/dev/null 2>&1; then
        sv $action $service 2>/dev/null
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service $service $action 2>/dev/null
    fi
}

# Enhanced DNS configuration with multiple fallbacks
configure_dns() {
    local primary_dns=${1:-"8.8.8.8"}
    local secondary_dns=${2:-"1.1.1.1"}
    
    # Backup current resolv.conf
    [[ -f "$RESOLV_CONF" ]] && cp "$RESOLV_CONF" "$RESOLV_BACKUP" 2>/dev/null
    
    # Create new resolv.conf with multiple DNS servers
    cat > "$RESOLV_CONF" << EOF
nameserver $primary_dns
nameserver $secondary_dns
nameserver 9.9.9.9
nameserver 208.67.222.222
options timeout:2 attempts:3 rotate
EOF
    
    # Set immutable flag to prevent dhcp override
    chattr +i "$RESOLV_CONF" 2>/dev/null || true
    return 0
}

# Complete network process cleanup with enhanced error handling
kill_network_processes() {
    local interface=$1
    
    # Kill DHCP clients silently
    pkill -f "dhclient.*$interface" 2>/dev/null
    pkill -f "udhcpc.*$interface" 2>/dev/null
    pkill -f "dhcpcd.*$interface" 2>/dev/null
    
    # Kill WiFi processes silently
    pkill -f "wpa_supplicant.*$interface" 2>/dev/null
    
    # Clean WPA control interface
    rm -rf "$WPA_CTRL_DIR/$interface" 2>/dev/null
    
    # Flush interface addresses
    ip addr flush dev "$interface" 2>/dev/null
    
    sleep 2
}

# Get network interfaces by type
get_interfaces() {
    local type=$1
    case $type in
        "ethernet")
            ip link show 2>/dev/null | awk '/^[0-9]+: (eth|en|em)/ {gsub(/:/, "", $2); print $2}'
            ;;
        "wireless")
            for dev in $(ls /sys/class/net/ 2>/dev/null); do
                [[ -d "/sys/class/net/$dev/wireless" ]] && echo "$dev"
            done
            ;;
        "all")
            ip link show 2>/dev/null | awk '/^[0-9]+:/ {gsub(/:/, "", $2); if($2 != "lo") print $2}'
            ;;
    esac
}

# Interface selection with enhanced validation
select_interface() {
    local type=$1
    local -a interfaces=($(get_interfaces "$type"))
    
    [[ ${#interfaces[@]} -eq 0 ]] && {
        dialog --msgbox "No $type interfaces found!" 8 40
        return 1
    }
    
    local -a menu_items=()
    for i in "${!interfaces[@]}"; do
        local status="DOWN"
        ip link show "${interfaces[$i]}" 2>/dev/null | grep -q "state UP" && status="UP"
        menu_items+=("$((i+1))" "${interfaces[$i]} [$status]")
    done
    
    dialog --clear --title "Select $type Interface" \
        --menu "Choose network interface:" \
        15 60 8 "${menu_items[@]}" 2>"$TEMP_FILE"
    
    [[ $? -eq 0 ]] && {
        local choice=$(cat "$TEMP_FILE")
        SELECTED_INTERFACE="${interfaces[$((choice-1))]}"
        return 0
    }
    return 1
}

# Main menu
main_menu() {
    while true; do
        dialog --clear --title "Universal Network Configuration Tool" \
            --menu "Select network configuration option:" \
            15 60 8 \
            1 "Configure Ethernet Connection" \
            2 "Configure WiFi Connection" \
            3 "Show Network Status" \
            4 "Test Internet Connectivity" \
            5 "Reset Network Settings" \
            6 "Exit Application" 2>"$TEMP_FILE"

        case $? in
            0)
                case $(cat "$TEMP_FILE") in
                    1) configure_ethernet ;;
                    2) configure_wifi ;;
                    3) show_network_status ;;
                    4) test_connectivity ;;
                    5) reset_network ;;
                    6) exit 0 ;;
                esac
                ;;
            *) exit 0 ;;
        esac
    done
}

# Ethernet configuration
configure_ethernet() {
    select_interface "ethernet" || return
    
    dialog --clear --title "Ethernet Configuration" \
        --menu "Select IP assignment method:" \
        12 50 4 \
        1 "DHCP (Automatic)" \
        2 "Static IP (Manual)" 2>"$TEMP_FILE"
    
    case $(cat "$TEMP_FILE") in
        1) configure_dhcp ;;
        2) configure_static_ip ;;
    esac
}

# DHCP configuration with enhanced error handling
configure_dhcp() {
    dialog --infobox "Configuring DHCP on $SELECTED_INTERFACE..." 5 50
    
    # Clean existing processes
    kill_network_processes "$SELECTED_INTERFACE"
    
    # Reset interface
    ip link set "$SELECTED_INTERFACE" down 2>/dev/null
    sleep 1
    ip link set "$SELECTED_INTERFACE" up 2>/dev/null
    sleep 3
    
    # Start DHCP client
    local dhcp_started=false
    if command -v dhclient >/dev/null 2>&1; then
        dhclient -r "$SELECTED_INTERFACE" >/dev/null 2>&1
        dhclient "$SELECTED_INTERFACE" >/dev/null 2>&1 &
        dhcp_started=true
    elif command -v udhcpc >/dev/null 2>&1; then
        udhcpc -i "$SELECTED_INTERFACE" -b >/dev/null 2>&1 &
        dhcp_started=true
    elif command -v dhcpcd >/dev/null 2>&1; then
        dhcpcd "$SELECTED_INTERFACE" >/dev/null 2>&1 &
        dhcp_started=true
    fi
    
    [[ "$dhcp_started" == false ]] && {
        log_error "No DHCP client found for $SELECTED_INTERFACE"
        dialog --msgbox "No DHCP client found!" 8 40
        return
    }
    
    # Wait for IP assignment
    local ip=""
    for i in {1..15}; do
        ip=$(ip addr show "$SELECTED_INTERFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
        [[ -n "$ip" ]] && break
        sleep 1
    done
    
    if [[ -n "$ip" ]]; then
        configure_dns
        log_info "DHCP configured successfully on $SELECTED_INTERFACE ($ip)"
        dialog --msgbox "DHCP Configuration Successful!\n\nInterface: $SELECTED_INTERFACE\nIP Address: $ip\nDNS: Configured\nStatus: Connected" 10 50
    else
        log_error "DHCP configuration failed on $SELECTED_INTERFACE"
        dialog --msgbox "DHCP Configuration Failed!\n\nCheck ethernet cable connection." 8 50
    fi
}

# Static IP configuration with validation
configure_static_ip() {
    dialog --form "Static IP Configuration" 14 55 4 \
        "IP Address:" 1 1 "192.168.1.100" 1 15 15 15 \
        "Netmask:" 2 1 "255.255.255.0" 2 15 15 15 \
        "Gateway:" 3 1 "192.168.1.1" 3 15 15 15 \
        "DNS Server:" 4 1 "8.8.8.8" 4 15 15 15 2>"$TEMP_FILE"
    
    [[ $? -ne 0 ]] && return
    
    local -a values=($(cat "$TEMP_FILE"))
    local ip_addr="${values[0]}"
    local netmask="${values[1]}"
    local gateway="${values[2]}"
    local dns="${values[3]}"
    
    # Basic IP validation
    if ! [[ $ip_addr =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        dialog --msgbox "Invalid IP address format!" 6 40
        return
    fi
    
    # Apply configuration
    kill_network_processes "$SELECTED_INTERFACE"
    ip addr add "$ip_addr/24" dev "$SELECTED_INTERFACE" 2>/dev/null
    ip link set "$SELECTED_INTERFACE" up 2>/dev/null
    ip route add default via "$gateway" dev "$SELECTED_INTERFACE" 2>/dev/null
    
    # Configure DNS with fallbacks
    configure_dns "$dns" "1.1.1.1"
    
    dialog --msgbox "Static IP Configuration Successful!\n\nInterface: $SELECTED_INTERFACE\nIP: $ip_addr\nGateway: $gateway\nDNS: $dns + fallbacks" 12 50
}

# WiFi scanning with enhanced error handling
scan_wifi() {
    dialog --infobox "Scanning for WiFi networks..." 5 40
    
    kill_network_processes "$SELECTED_INTERFACE"
    ip link set "$SELECTED_INTERFACE" up 2>/dev/null
    sleep 3
    
    local networks=""
    for attempt in {1..3}; do
        networks=$(iw dev "$SELECTED_INTERFACE" scan 2>/dev/null | grep -E "^BSS|SSID:|signal:" | head -60)
        [[ -n "$networks" ]] && break
        sleep 2
    done
    
    [[ -z "$networks" ]] && {
        dialog --msgbox "No WiFi networks detected!" 8 40
        return 1
    }
    
    local -a ssids=()
    local -a signals=()
    local current_signal=""
    
    while IFS= read -r line; do
        if [[ $line =~ signal:[[:space:]]*([+-]?[0-9.]+) ]]; then
            current_signal="${BASH_REMATCH[1]}"
        elif [[ $line =~ SSID:[[:space:]]*(.+) ]]; then
            local ssid="${BASH_REMATCH[1]}"
            if [[ -n "$ssid" && "$ssid" != "(hidden)" ]]; then
                ssids+=("$ssid")
                signals+=("$current_signal")
            fi
        fi
    done <<< "$networks"
    
    [[ ${#ssids[@]} -eq 0 ]] && {
        dialog --msgbox "No visible WiFi networks found!" 8 40
        return 1
    }
    
    local -a menu_items=()
    for i in "${!ssids[@]}"; do
        local signal="${signals[$i]:-"-999"}"
        local quality="Poor"
        [[ ${signal%.*} -gt -70 ]] && quality="Good"
        [[ ${signal%.*} -gt -50 ]] && quality="Excellent"
        menu_items+=("$((i+1))" "${ssids[$i]} (${signal}dBm - $quality)")
    done
    
    dialog --clear --title "Available WiFi Networks" \
        --menu "Select network to connect:" \
        15 65 8 "${menu_items[@]}" 2>"$TEMP_FILE"
    
    [[ $? -eq 0 ]] && {
        local choice=$(cat "$TEMP_FILE")
        SELECTED_SSID="${ssids[$((choice-1))]}"
        return 0
    }
    return 1
}

# WiFi configuration
configure_wifi() {
    select_interface "wireless" || return
    scan_wifi || return
    
    dialog --passwordbox "Enter WiFi password for network:\n'$SELECTED_SSID'" 9 50 2>"$TEMP_FILE"
    [[ $? -ne 0 ]] && return
    
    WIFI_PASSWORD=$(cat "$TEMP_FILE")
    connect_wifi
}

# WiFi connection with professional error handling
connect_wifi() {
    dialog --infobox "Connecting to WiFi network: $SELECTED_SSID..." 5 55
    
    kill_network_processes "$SELECTED_INTERFACE"
    mkdir -p "$WPA_CTRL_DIR" 2>/dev/null
    
    cat > "$WPA_CONFIG" << EOF
ctrl_interface=$WPA_CTRL_DIR
update_config=1
country=US

network={
    ssid="$SELECTED_SSID"
    psk="$WIFI_PASSWORD"
    key_mgmt=WPA-PSK
    scan_ssid=1
}
EOF
    
    # Start WPA supplicant with enhanced error suppression
    if command -v wpa_supplicant >/dev/null 2>&1; then
        wpa_supplicant -B -i "$SELECTED_INTERFACE" -c "$WPA_CONFIG" -D nl80211 -f /dev/null >/dev/null 2>&1 || \
        wpa_supplicant -B -i "$SELECTED_INTERFACE" -c "$WPA_CONFIG" -D wext -f /dev/null >/dev/null 2>&1
        sleep 4
    fi
    
    # Get IP via DHCP
    if command -v dhclient >/dev/null 2>&1; then
        dhclient "$SELECTED_INTERFACE" >/dev/null 2>&1 &
    elif command -v udhcpc >/dev/null 2>&1; then
        udhcpc -i "$SELECTED_INTERFACE" -b >/dev/null 2>&1 &
    fi
    
    # Wait for IP
    local ip=""
    for i in {1..20}; do
        ip=$(ip addr show "$SELECTED_INTERFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
        [[ -n "$ip" ]] && break
        sleep 1
    done
    
    if [[ -n "$ip" ]]; then
        configure_dns
        log_info "WiFi connected successfully to $SELECTED_SSID ($ip)"
        dialog --msgbox "WiFi Connection Successful!\n\nNetwork: $SELECTED_SSID\nInterface: $SELECTED_INTERFACE\nIP Address: $ip\nDNS: Configured with fallbacks" 12 50
    else
        log_error "WiFi connection failed to $SELECTED_SSID on $SELECTED_INTERFACE"
        dialog --msgbox "WiFi Connection Failed!\n\nCheck password and signal strength." 8 50
    fi
}

# Network status display
show_network_status() {
    local status="=== NETWORK STATUS REPORT ===\n\n"
    local -a interfaces=($(get_interfaces "all"))
    
    for iface in "${interfaces[@]}"; do
        local ip=$(ip addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
        local state=$(ip link show "$iface" 2>/dev/null | grep -o "state [A-Z]*" | cut -d' ' -f2)
        
        status+="Interface: $iface\n"
        status+="Status: $state\n"
        status+="IP Address: ${ip:-"Not assigned"}\n"
        
        if [[ -d "/sys/class/net/$iface/wireless" ]]; then
            local ssid=$(iw dev "$iface" link 2>/dev/null | grep -oP 'SSID: \K.*' | head -1)
            [[ -n "$ssid" ]] && status+="WiFi Network: $ssid\n"
        fi
        status+="\n"
    done
    
    local gateway=$(ip route 2>/dev/null | grep default | head -1 | grep -oP 'via \K[\d.]+')
    [[ -n "$gateway" ]] && status+="Gateway: $gateway\n"
    
    local dns=$(grep nameserver /etc/resolv.conf 2>/dev/null | head -1 | awk '{print $2}')
    [[ -n "$dns" ]] && status+="Primary DNS: $dns\n"
    
    dialog --msgbox "$status" 20 55
}

# Internet connectivity test with speed measurement
test_connectivity() {
    dialog --infobox "Testing internet connectivity and speed..." 5 50
    
    local results="=== CONNECTIVITY TEST ===\n\n"
    
    # Test gateway
    local gateway=$(ip route 2>/dev/null | grep default | head -1 | grep -oP 'via \K[\d.]+')
    if [[ -n "$gateway" ]] && ping -c 2 -W 3 "$gateway" >/dev/null 2>&1; then
        results+="✓ Gateway: PASSED ($gateway)\n"
    else
        results+="✗ Gateway: FAILED\n"
        log_error "Gateway test failed ($gateway)"
    fi
    
    # Test internet
    if ping -c 2 -W 5 8.8.8.8 >/dev/null 2>&1; then
        results+="✓ Internet: PASSED\n"
    else
        results+="✗ Internet: FAILED\n"
        log_error "Internet connectivity test failed"
    fi
    
    # Test DNS
    if nslookup google.com >/dev/null 2>&1; then
        results+="✓ DNS Resolution: PASSED\n"
    else
        results+="✗ DNS Resolution: FAILED\n"
        log_error "DNS resolution test failed"
    fi
    
    # Speed test using basic download method
    results+="\n=== SPEED TEST ===\n"
    local speed="N/A"
    
    # Test download speed using wget or curl with timeout
    if command -v wget >/dev/null 2>&1; then
        local start_time=$(date +%s)
        if timeout 10 wget -q -O /dev/null "http://speedtest.tele2.net/1MB.zip" 2>/dev/null; then
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            [[ $duration -gt 0 ]] && speed=$(( (1024 * 8) / duration )) && speed="${speed} Kbps"
        fi
    elif command -v curl >/dev/null 2>&1; then
        local start_time=$(date +%s)
        if timeout 10 curl -s -o /dev/null "http://speedtest.tele2.net/1MB.zip" 2>/dev/null; then
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            [[ $duration -gt 0 ]] && speed=$(( (1024 * 8) / duration )) && speed="${speed} Kbps"
        fi
    fi
    
    # Alternative speed test using ping latency
    if [[ "$speed" == "N/A" ]]; then
        local ping_time=$(ping -c 4 8.8.8.8 2>/dev/null | grep "avg" | cut -d'/' -f5 | cut -d'.' -f1)
        if [[ -n "$ping_time" && $ping_time -lt 50 ]]; then
            speed="Fast (${ping_time}ms latency)"
        elif [[ -n "$ping_time" && $ping_time -lt 100 ]]; then
            speed="Good (${ping_time}ms latency)"
        elif [[ -n "$ping_time" ]]; then
            speed="Slow (${ping_time}ms latency)"
        fi
    fi
    
    results+="Download Speed: $speed\n"
    log_info "Connectivity test completed - Speed: $speed"
    
    dialog --msgbox "$results" 16 50
}

# Network reset
reset_network() {
    dialog --yesno "Reset all network configurations?" 8 40
    [[ $? -ne 0 ]] && return
    
    dialog --infobox "Resetting network..." 5 30
    
    local -a interfaces=($(get_interfaces "all"))
    for iface in "${interfaces[@]}"; do
        kill_network_processes "$iface"
        ip link set "$iface" down 2>/dev/null
    done
    
    ip route flush table main 2>/dev/null
    rm -rf "$WPA_CTRL_DIR" 2>/dev/null
    
    # Restore DNS backup
    chattr -i "$RESOLV_CONF" 2>/dev/null
    [[ -f "$RESOLV_BACKUP" ]] && mv "$RESOLV_BACKUP" "$RESOLV_CONF"
    
    manage_service restart networking
    
    dialog --msgbox "Network reset completed!" 6 40
}

# Main execution
log_info "Universal Network Configuration Tool started"
main_menu
