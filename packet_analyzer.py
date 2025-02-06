from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import Counter, defaultdict
import pandas as pd
from typing import Dict, List, Tuple

def analyze_pcap(filepath: str) -> Dict:
    """
    Analyze a PCAP file and return various statistics about the network traffic.
    
    Args:
        filepath (str): Path to the PCAP file
        
    Returns:
        dict: Dictionary containing various analysis results
    """
    # Read the pcap file
    packets = rdpcap(filepath)
    
    # Initialize counters and storage
    protocol_counter = Counter()
    ip_sources = Counter()
    ip_destinations = Counter()
    ports_used = defaultdict(Counter)
    packet_lengths = []
    tcp_flags = Counter()
    conversations = defaultdict(int)
    
    # Analyze each packet
    for packet in packets:
        # Get packet length
        packet_lengths.append(len(packet))
        
        # Check if packet has IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Count IPs
            ip_sources[src_ip] += 1
            ip_destinations[dst_ip] += 1
            
            # Track conversations
            conv_key = tuple(sorted([src_ip, dst_ip]))
            conversations[conv_key] += 1
            
            # Analyze protocols
            if TCP in packet:
                protocol_counter['TCP'] += 1
                ports_used['TCP'][packet[TCP].dport] += 1
                # Analyze TCP flags
                flag_names = []
                if packet[TCP].flags.F: flag_names.append('FIN')
                if packet[TCP].flags.S: flag_names.append('SYN')
                if packet[TCP].flags.R: flag_names.append('RST')
                if packet[TCP].flags.P: flag_names.append('PSH')
                if packet[TCP].flags.A: flag_names.append('ACK')
                if flag_names:
                    tcp_flags['+'.join(flag_names)] += 1
                    
            elif UDP in packet:
                protocol_counter['UDP'] += 1
                ports_used['UDP'][packet[UDP].dport] += 1
                
            elif ICMP in packet:
                protocol_counter['ICMP'] += 1
            
            else:
                protocol_counter['Other'] += 1
    
    # Process results
    results = {
        'total_packets': len(packets),
        'protocols': dict(protocol_counter),
        'top_source_ips': dict(ip_sources.most_common(10)),
        'top_dest_ips': dict(ip_destinations.most_common(10)),
        'top_tcp_ports': dict(ports_used['TCP'].most_common(10)),
        'top_udp_ports': dict(ports_used['UDP'].most_common(10)),
        'tcp_flags': dict(tcp_flags),
        'packet_stats': {
            'min_length': min(packet_lengths),
            'max_length': max(packet_lengths),
            'avg_length': sum(packet_lengths) / len(packet_lengths)
        },
        'top_conversations': {
            f"{ip1} <-> {ip2}": count 
            for (ip1, ip2), count in sorted(
                conversations.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]
        }
    }
    
    # Calculate additional statistics
    if protocol_counter['TCP'] > 0:
        results['tcp_stats'] = analyze_tcp_connections(packets)
    
    return results

def analyze_tcp_connections(packets: List) -> Dict:
    """
    Analyze TCP connections in detail.
    
    Args:
        packets (List): List of packets from scapy
        
    Returns:
        dict: Dictionary containing TCP analysis results
    """
    syn_count = 0
    established_count = 0
    reset_count = 0
    
    # Track connection states
    connections = defaultdict(lambda: {'state': 'NEW', 'syn': False, 'synack': False})
    
    for packet in packets:
        if TCP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            # Create unique connection identifier
            conn_id = tuple(sorted([(src, sport), (dst, dport)]))
            
            # Track TCP handshake
            if packet[TCP].flags.S and not packet[TCP].flags.A:  # SYN
                syn_count += 1
                connections[conn_id]['syn'] = True
            
            elif packet[TCP].flags.S and packet[TCP].flags.A:  # SYN-ACK
                if connections[conn_id]['syn']:
                    connections[conn_id]['synack'] = True
            
            elif packet[TCP].flags.A:  # ACK
                if connections[conn_id]['syn'] and connections[conn_id]['synack']:
                    if connections[conn_id]['state'] == 'NEW':
                        established_count += 1
                        connections[conn_id]['state'] = 'ESTABLISHED'
            
            if packet[TCP].flags.R:  # RST
                reset_count += 1
                connections[conn_id]['state'] = 'CLOSED'
    
    return {
        'total_syn': syn_count,
        'established_connections': established_count,
        'reset_connections': reset_count,
        'completion_rate': (established_count / syn_count * 100) if syn_count > 0 else 0
    }
