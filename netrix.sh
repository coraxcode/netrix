#!/bin/bash

# Universal NETrix v5.2 - Professional Network Configuration Script
# Compatible with ALL Linux distributions (systemd/non-systemd)
# Optimized for base system compatibility and universal usage
# Author: Seehrum

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
DETECTED_DISTRO=""
PREFERRED_DHCP=""
WIFI_COUNTRY=""

# Cleanup handler
cleanup() {
    rm -f "$TEMP_FILE" "$WPA_CONFIG" 2>/dev/null
    clear
}
trap cleanup EXIT INT TERM

# Enhanced logging
log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE" 2>/dev/null
}

# Professional distribution detection
detect_distribution() {
    local distro="unknown"
    if [[ -f /etc/void-release ]]; then
        distro="void"
    elif [[ -f /etc/alpine-release ]]; then
        distro="alpine"
    elif [[ -f /etc/arch-release ]]; then
        distro="arch"
    elif [[ -f /etc/debian_version ]]; then
        distro="debian"
    elif [[ -f /etc/redhat-release ]]; then
        distro="redhat"
    elif [[ -f /etc/openwrt_release ]]; then
        distro="openwrt"
    fi
    DETECTED_DISTRO="$distro"
    log_info "Detected distribution: $distro"
}

# Get preferred DHCP client by distribution
get_preferred_dhcp_client() {
    case "$DETECTED_DISTRO" in
        "void"|"arch") echo "dhcpcd" ;;
        "alpine"|"openwrt") echo "udhcpc" ;;
        "debian"|"redhat") 
            command -v dhclient >/dev/null 2>&1 && echo "dhclient" || echo "dhcpcd" ;;
        *) 
            command -v dhclient >/dev/null 2>&1 && echo "dhclient" || echo "dhcpcd" ;;
    esac
}

# Detect WiFi country code
detect_wifi_country() {
    local country="US"
    if command -v curl >/dev/null 2>&1; then
        country=$(timeout 5 curl -s "http://ipinfo.io/country" 2>/dev/null | head -1 | tr -d '\n\r' | grep -E '^[A-Z]{2}$' || echo "US")
    elif [[ -f /etc/timezone ]]; then
        local tz=$(cat /etc/timezone 2>/dev/null)
        case "$tz" in
            Europe/*) country="DE" ;;
            America/*) country="US" ;;
            Asia/*) country="JP" ;;
            Australia/*) country="AU" ;;
        esac
    fi
    [[ ${#country} -eq 2 ]] && [[ "$country" =~ ^[A-Z]{2}$ ]] && WIFI_COUNTRY="$country" || WIFI_COUNTRY="US"
}

# Check CapsLock status - Bug Fix #2
check_capslock_status() {
    local capslock_status="OFF"
    if command -v xset >/dev/null 2>&1; then
        xset q 2>/dev/null | grep -q "Caps Lock:.*on" && capslock_status="ON"
    elif [[ -f /sys/class/leds/input*::capslock/brightness ]]; then
        local brightness=$(cat /sys/class/leds/input*::capslock/brightness 2>/dev/null | head -1)
        [[ "$brightness" == "1" ]] && capslock_status="ON"
    fi
    
    if [[ "$capslock_status" == "ON" ]]; then
        dialog --title "CapsLock Warning" --msgbox "WARNING: CapsLock is currently ON!\n\nThis may cause issues with WiFi password entry.\nPlease disable CapsLock and try again." 9 50
        return 1
    fi
    return 0
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

# Intelligent DNS configuration
configure_dns() {
    local primary_dns=${1:-"8.8.8.8"}
    local secondary_dns=${2:-"1.1.1.1"}
    
    if systemctl is-active systemd-resolved >/dev/null 2>&1; then
        command -v resolvectl >/dev/null 2>&1 && resolvectl dns "$SELECTED_INTERFACE" "$primary_dns" "$secondary_dns" 2>/dev/null && return 0
    fi
    
    [[ -f "$RESOLV_CONF" ]] && cp "$RESOLV_CONF" "$RESOLV_BACKUP" 2>/dev/null
    command -v chattr >/dev/null 2>&1 && chattr -i "$RESOLV_CONF" 2>/dev/null
    
    cat > "$RESOLV_CONF" << EOF
nameserver $primary_dns
nameserver $secondary_dns
nameserver 9.9.9.9
options timeout:2 attempts:3
EOF
    
    command -v chattr >/dev/null 2>&1 && chattr +i "$RESOLV_CONF" 2>/dev/null
    log_info "DNS configured: $primary_dns, $secondary_dns"
}

# Enhanced network process cleanup with full interface reset
kill_network_processes() {
    local interface=$1
    
    # Kill all network processes
    pkill -f "dhclient.*$interface" 2>/dev/null
    pkill -f "dhcpcd.*$interface" 2>/dev/null
    pkill -f "udhcpc.*$interface" 2>/dev/null
    pkill -f "wpa_supplicant.*$interface" 2>/dev/null
    
    # Clean up control directories
    rm -rf "$WPA_CTRL_DIR/$interface" 2>/dev/null
    
    # Complete interface reset - Bug Fix #1
    ip addr flush dev "$interface" 2>/dev/null
    ip route del default dev "$interface" 2>/dev/null
    ip link set "$interface" down 2>/dev/null
    sleep 2
    ip link set "$interface" up 2>/dev/null
    sleep 2
    
    log_info "Network processes killed and interface $interface reset"
}

# Get network interfaces by type
get_interfaces() {
    local type=$1
    case $type in
        "ethernet")
            ip link show 2>/dev/null | awk '/^[0-9]+: (eth|en|em|enp|eno|ens)/ {gsub(/:/, "", $2); print $2}'
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

# Interface selection
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
        dialog --clear --title "Universal NETrix v5.2 [$DETECTED_DISTRO]" \
            --menu "Professional Network Configuration:" \
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

# Enhanced DHCP configuration
configure_dhcp() {
    dialog --infobox "Configuring DHCP on $SELECTED_INTERFACE using $PREFERRED_DHCP..." 5 60
    
    kill_network_processes "$SELECTED_INTERFACE"
    
    # Start DHCP client based on distribution preference
    case "$PREFERRED_DHCP" in
        "dhclient")
            command -v dhclient >/dev/null 2>&1 && dhclient "$SELECTED_INTERFACE" >/dev/null 2>&1 &
            ;;
        "dhcpcd")
            command -v dhcpcd >/dev/null 2>&1 && dhcpcd "$SELECTED_INTERFACE" >/dev/null 2>&1 &
            ;;
        "udhcpc")
            command -v udhcpc >/dev/null 2>&1 && udhcpc -i "$SELECTED_INTERFACE" -b >/dev/null 2>&1 &
            ;;
    esac
    
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
        dialog --msgbox "DHCP Configuration Successful!\n\nInterface: $SELECTED_INTERFACE\nIP Address: $ip\nDHCP Client: $PREFERRED_DHCP" 10 50
    else
        dialog --msgbox "DHCP Configuration Failed!\nCheck ethernet cable connection." 8 50
    fi
}

# Static IP configuration
configure_static_ip() {
    dialog --form "Static IP Configuration" 14 55 4 \
        "IP Address:" 1 1 "192.168.1.100" 1 15 15 15 \
        "Netmask:" 2 1 "255.255.255.0" 2 15 15 15 \
        "Gateway:" 3 1 "192.168.1.1" 3 15 15 15 \
        "DNS Server:" 4 1 "8.8.8.8" 4 15 15 15 2>"$TEMP_FILE"
    
    [[ $? -ne 0 ]] && return
    
    local -a values=($(cat "$TEMP_FILE"))
    local ip_addr="${values[0]}"
    local gateway="${values[2]}"
    local dns="${values[3]}"
    
    # IP validation
    if ! [[ $ip_addr =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        dialog --msgbox "Invalid IP address format!" 6 40
        return
    fi
    
    kill_network_processes "$SELECTED_INTERFACE"
    ip addr add "$ip_addr/24" dev "$SELECTED_INTERFACE" 2>/dev/null
    ip link set "$SELECTED_INTERFACE" up 2>/dev/null
    ip route add default via "$gateway" dev "$SELECTED_INTERFACE" 2>/dev/null
    
    configure_dns "$dns" "1.1.1.1"
    dialog --msgbox "Static IP Configuration Successful!\n\nInterface: $SELECTED_INTERFACE\nIP: $ip_addr\nGateway: $gateway" 10 50
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

# WiFi configuration with CapsLock check and network reset - Bug Fix #1 & #2
configure_wifi() {
    # Reset all network connections first to avoid conflicts - Bug Fix #1
    dialog --infobox "Resetting network connections to avoid conflicts..." 5 55
    local -a all_interfaces=($(get_interfaces "all"))
    for iface in "${all_interfaces[@]}"; do
        kill_network_processes "$iface"
    done
    sleep 2
    
    select_interface "wireless" || return
    
    # Check CapsLock status before password entry - Bug Fix #2
    check_capslock_status || return
    
    scan_wifi || return
    
    dialog --title "WiFi Password" --insecure --passwordbox "Enter WiFi password for network:\n'$SELECTED_SSID'" 9 50 2>"$TEMP_FILE"
    [[ $? -ne 0 ]] && return
    
    WIFI_PASSWORD=$(cat "$TEMP_FILE")
    connect_wifi
}

# Enhanced WiFi connection
connect_wifi() {
    dialog --infobox "Connecting to WiFi network: $SELECTED_SSID..." 5 55
    
    mkdir -p "$WPA_CTRL_DIR" 2>/dev/null
    
    cat > "$WPA_CONFIG" << EOF
ctrl_interface=$WPA_CTRL_DIR
update_config=1
country=$WIFI_COUNTRY

network={
    ssid="$SELECTED_SSID"
    psk="$WIFI_PASSWORD"
    key_mgmt=WPA-PSK
    scan_ssid=1
}
EOF
    
    # Start WPA supplicant
    if command -v wpa_supplicant >/dev/null 2>&1; then
        wpa_supplicant -B -i "$SELECTED_INTERFACE" -c "$WPA_CONFIG" -D nl80211 >/dev/null 2>&1 || \
        wpa_supplicant -B -i "$SELECTED_INTERFACE" -c "$WPA_CONFIG" -D wext >/dev/null 2>&1
        sleep 4
    fi
    
    # Get IP via DHCP
    case "$PREFERRED_DHCP" in
        "dhclient") command -v dhclient >/dev/null 2>&1 && dhclient "$SELECTED_INTERFACE" >/dev/null 2>&1 & ;;
        "dhcpcd") command -v dhcpcd >/dev/null 2>&1 && dhcpcd "$SELECTED_INTERFACE" >/dev/null 2>&1 & ;;
        "udhcpc") command -v udhcpc >/dev/null 2>&1 && udhcpc -i "$SELECTED_INTERFACE" -b >/dev/null 2>&1 & ;;
    esac
    
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
        dialog --msgbox "WiFi Connection Successful!\n\nNetwork: $SELECTED_SSID\nInterface: $SELECTED_INTERFACE\nIP Address: $ip\nCountry: $WIFI_COUNTRY" 12 55
    else
        dialog --msgbox "WiFi Connection Failed!\nCheck password and signal strength." 8 50
    fi
}

# Network status display
show_network_status() {
    local status="=== NETWORK STATUS REPORT ===\n"
    status+="Distribution: $DETECTED_DISTRO\n"
    status+="DHCP Client: $PREFERRED_DHCP\n"
    status+="WiFi Country: $WIFI_COUNTRY\n\n"
    
    local -a interfaces=($(get_interfaces "all"))
    for iface in "${interfaces[@]}"; do
        local ip=$(ip addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
        local state=$(ip link show "$iface" 2>/dev/null | grep -o "state [A-Z]*" | cut -d' ' -f2)
        
        status+="Interface: $iface [$state]\n"
        status+="IP Address: ${ip:-"Not assigned"}\n"
        
        if [[ -d "/sys/class/net/$iface/wireless" ]]; then
            local ssid=$(iw dev "$iface" link 2>/dev/null | grep -oP 'SSID: \K.*' | head -1)
            [[ -n "$ssid" ]] && status+="WiFi Network: $ssid\n"
        fi
        status+="\n"
    done
    
    local gateway=$(ip route 2>/dev/null | grep default | head -1 | grep -oP 'via \K[\d.]+')
    [[ -n "$gateway" ]] && status+="Gateway: $gateway\n"
    
    dialog --msgbox "$status" 20 60
}

# Enhanced connectivity test
test_connectivity() {
    dialog --infobox "Testing internet connectivity..." 5 40
    
    local results="=== CONNECTIVITY TEST ===\n\n"
    
    local gateway=$(ip route 2>/dev/null | grep default | head -1 | grep -oP 'via \K[\d.]+')
    if [[ -n "$gateway" ]] && timeout 5 ping -c 2 -W 3 "$gateway" >/dev/null 2>&1; then
        results+="✓ Gateway: PASSED ($gateway)\n"
    else
        results+="✗ Gateway: FAILED\n"
    fi
    
    if timeout 8 ping -c 2 -W 5 8.8.8.8 >/dev/null 2>&1; then
        results+="✓ Internet: PASSED\n"
    else
        results+="✗ Internet: FAILED\n"
    fi
    
    # DNS resolution test
    local dns_ok=false
    if command -v nslookup >/dev/null 2>&1; then
        timeout 5 nslookup google.com >/dev/null 2>&1 && dns_ok=true
    elif command -v dig >/dev/null 2>&1; then
        timeout 5 dig google.com >/dev/null 2>&1 && dns_ok=true
    fi
    
    if [[ "$dns_ok" == true ]]; then
        results+="✓ DNS Resolution: PASSED\n"
    else
        results+="✗ DNS Resolution: FAILED\n"
    fi
    
    dialog --msgbox "$results" 12 50
}

# Network reset with enhanced cleanup
reset_network() {
    dialog --yesno "Reset all network configurations?" 8 40
    [[ $? -ne 0 ]] && return
    
    dialog --infobox "Resetting network..." 5 30
    
    local -a interfaces=($(get_interfaces "all"))
    for iface in "${interfaces[@]}"; do
        kill_network_processes "$iface"
    done
    
    ip route flush table main 2>/dev/null
    rm -rf "$WPA_CTRL_DIR" 2>/dev/null
    
    # Restore DNS backup
    if ! systemctl is-active systemd-resolved >/dev/null 2>&1; then
        command -v chattr >/dev/null 2>&1 && chattr -i "$RESOLV_CONF" 2>/dev/null
        [[ -f "$RESOLV_BACKUP" ]] && mv "$RESOLV_BACKUP" "$RESOLV_CONF"
    fi
    
    dialog --msgbox "Network reset completed!" 6 40
}

# Initialize system detection
detect_distribution
PREFERRED_DHCP=$(get_preferred_dhcp_client)
detect_wifi_country

# Main execution
log_info "Universal NETrix v5.2 started - Distribution: $DETECTED_DISTRO, DHCP: $PREFERRED_DHCP, Country: $WIFI_COUNTRY"
main_menu
