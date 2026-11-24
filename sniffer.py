from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime 
import sqlite3

common_ports = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH", 
    23: "TELNET", 
    21: "FTP", 
    53: "DNS", 
    445: "SMB"
}


# Creating dictionary, Stores amount of time IP is seen
ip_counts = {}

port_sets = {}

# This function runs everytime a packet is seen 
# Check for IP, Grabs Source and Destination IP 
# Alerts if source IP has sent multiple packets 
# Prints port of packet
# Prints what it saw 
def handle_packet(packet): 
    if packet.haslayer(IP) and packet.haslayer(TCP): 
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dport = packet[TCP].dport

        #count the time src IP has been seen
        if src_ip in ip_counts: 
            ip_counts[src_ip] += 1 
        else: 
            ip_counts[src_ip] = 1

        # Alert from IP flooding
        if ip_counts[src_ip] > 10: 
            alert_type = "IP FLOOD"
            timestamp = str(datetime.now())
            connect = sqlite3.connect("alerts.db")
            cursor = connect.cursor()
            cursor.execute(''' 
                INSERT INTO alerts (timestamp, src_ip, dst_ip, port, alert_type)
                VALUES (?,?,?,?,?)''', (timestamp, src_ip, dst_ip, dport, alert_type))
            connect.commit()
            connect.close()

        if src_ip not in port_sets: 
            port_sets[src_ip] = set()
        port_sets[src_ip].add(dport)

        if len(port_sets[src_ip]) > 10: 
            alert_type = "Port Scan"
            timestamp = str(datetime.now())
            connect = sqlite3.connect("alerts.db")
            cursor = connect.cursor()
            cursor.execute(''' 
                INSERT INTO alerts (timestamp, src_ip, dst_ip, port, alert_type)
                VALUES (?,?,?,?,?)''', (timestamp, src_ip, dst_ip, dport, alert_type))
            connect.commit()
            connect.close()

        service = common_ports.get(dport, "Unknown")
        print(f"{datetime.now()} --> Source IP: {src_ip} --> Destination IP: {dst_ip} on port {dport} ({service})")

    # UDP PACKET HANDLING
    elif packet.haslayer(IP) and packet.haslayer(UDP): 
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dport = packet[UDP].dport

        print(f"[UDP] {datetime.now()} --> From {src_ip} to {dst_ip} on port {dport}")

        # Alert system for uncommon UDP port 
        if dport not in common_ports: 
            alert_type = "Uncommon UDP Port"
            timestamp = str(datetime.now())
            connect = sqlite3.connect("alerts.db")
            cursor = connect.cursor()
            cursor.execute(''' 
                INSERT INTO alerts (timestamp, src_ip, dst_ip, port, alert_type)
                VALUES (?,?,?,?,?)''', (timestamp, src_ip, dst_ip, dport, alert_type))
            
            connect.commit()
            connect.close()

    
    elif packet.haslayer(IP) and packet.haslayer(ICMP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        print(f"[ICMP] {datetime.now()} --> ICMP Echo from {src_ip} to {dst_ip}")

        # ICMP flood detection 

        ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
        if ip_counts[src_ip] > 10: 
            alert_type = "ICMP Flood"
            timestamp = str(datetime.now())
            connection = sqlite3.connect("alerts.db")
            cursor = connection.cursor()
            cursor.execute (""" 
                INSERT INTO alerts (timestamp, src_ip, dst_ip, port, alert_type)
                VALUES (?,?,?,?,?)""", (timestamp, src_ip, dst_ip, 0, alert_type))
            connection.commit()
            connection.close()
            

# Sniffs through network 
# Want only IP Packets, calls packet handling function
# Don't want to save them just process
try: 
    sniff(
        filter="ip",
        prn=handle_packet,
        store=0
    )
except KeyboardInterrupt: 
    print("\n[!] Sniffing stopped by user.")