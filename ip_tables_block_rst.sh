iptables-save > iptables.tmp
iptables -A OUTPUT -p tcp --tcp-flags RST RST -dport 45000 -j DROP
