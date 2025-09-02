#!/bin/bash
# You are NOT allowed to change the files' names!
config="config.txt"
rulesV4="rulesV4"
rulesV6="rulesV6"

function firewall() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-config"  ]; then
        # create the rules based on the domains and IPs in config.txt
        while IFS= read -r line; do
            echo $line
            if [[ -z "$line" || "$line" == \#* ]]; then
                continue
            fi

            # IPv4 and IPv6 addresses
            ip4s=$(dig +short "$line")   
            ip6s=$(dig +short "$line" AAAA)  # IPv6
            echo $line $ip4s $ip6s
            # block all ips
            for ip in $ip4s; do
                sudo iptables -A INPUT -s "$ip" -j REJECT
                sudo iptables -A OUTPUT -d "$ip" -j REJECT
            done

            for ip in $ip6s; do
                sudo ip6tables -A INPUT -s "$ip" -j REJECT
                sudo ip6tables -A OUTPUT -d "$ip" -j REJECT
            done
        done < "$config"

        true
        
    elif [ "$1" = "-save"  ]; then
        #  rules to rulesV4 and rulesV6
        sudo iptables-save > "$rulesV4"
        sudo ip6tables-save > "$rulesV6"
        true
        
    elif [ "$1" = "-load"  ]; then
        # load from file 
        sudo iptables-restore < "$rulesV4"
        sudo ip6tables-restore < "$rulesV6"
        true

        
    elif [ "$1" = "-reset"  ]; then
        # clear rules 
        sudo iptables -F  
        sudo ip6tables -F  
        sudo iptables -P INPUT ACCEPT  
        sudo ip6tables -P INPUT ACCEPT  
        sudo iptables -P OUTPUT ACCEPT  
        sudo ip6tables -P OUTPUT ACCEPT  
        true

        
    elif [ "$1" = "-list"  ]; then
        # list rules
        echo "IPv4 Rules:"
        sudo iptables -L
        echo "IPv6 Rules:"
        sudo ip6tables -L
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple firewall mechanism. It rejects connections from specific domain names or IP addresses using iptables/ip6tables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -config\t  Configure adblock rules based on the domain names and IPs of '$config' file.\n"
        printf "  -save\t\t  Save rules to '$rulesV4' and '$rulesV6'  files.\n"
        printf "  -load\t\t  Load rules from '$rulesV4' and '$rulesV6' files.\n"
        printf "  -list\t\t  List current rules for IPv4 and IPv6.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

firewall $1
exit 0