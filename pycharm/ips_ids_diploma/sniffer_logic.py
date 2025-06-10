import datetime
from scapy.all import IP, DNSQR, UDP, TCP
from config import PROTO_MAP


def process_packet_for_threats(packet, bad_ips_info_dict, bad_domains_info_dict):
    detected_alerts = []
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    packet_summary_str = packet.summary()
    src_ip_str, dst_ip_str, src_port, dst_port, proto_name = "N/A", "N/A", "N/A", "N/A", "N/A"

    if IP in packet:
        src_ip_str = packet[IP].src
        dst_ip_str = packet[IP].dst
        proto_num = packet[IP].proto
        proto_name = PROTO_MAP.get(proto_num, str(proto_num))

        if packet.haslayer(TCP):
            src_port, dst_port = packet[TCP].sport, packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port, dst_port = packet[UDP].sport, packet[UDP].dport

        packet_info_base = {
            "timestamp": timestamp, "src_ip": src_ip_str, "src_port": src_port,
            "dst_ip": dst_ip_str, "dst_port": dst_port, "protocol": proto_name
        }
        if dst_ip_str in bad_ips_info_dict:
            ip_meta = bad_ips_info_dict[dst_ip_str]
            detected_alerts.append(
                {"packet_info": packet_info_base, "indicator_type": "IP", "indicator_value": dst_ip_str,
                 "alert_metadata": ip_meta, "packet_summary_str": packet_summary_str})

        if src_ip_str in bad_ips_info_dict:
            ip_meta = bad_ips_info_dict[src_ip_str]
            detected_alerts.append(
                {"packet_info": packet_info_base, "indicator_type": "IP", "indicator_value": src_ip_str,
                 "alert_metadata": ip_meta, "packet_summary_str": packet_summary_str})

    if DNSQR in packet and packet.haslayer(UDP) and packet[UDP].dport == 53:
        dns_src_ip = src_ip_str
        dns_dst_ip = dst_ip_str
        dns_src_port = src_port if packet.haslayer(UDP) else "N/A"

        packet_info_dns = {
            "timestamp": timestamp, "src_ip": dns_src_ip, "src_port": dns_src_port,
            "dst_ip": dns_dst_ip, "dst_port": 53, "protocol": "UDP (DNS)"
        }
        try:
            queried_domain = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            if queried_domain:
                for bad_domain_entry, domain_meta in bad_domains_info_dict.items():
                    if queried_domain == bad_domain_entry or queried_domain.endswith("." + bad_domain_entry):
                        detected_alerts.append({"packet_info": packet_info_dns, "indicator_type": "DOMAIN",
                                                "indicator_value": queried_domain, "alert_metadata": domain_meta,
                                                "packet_summary_str": packet_summary_str})
                        break
        except Exception:
            pass

    return detected_alerts
