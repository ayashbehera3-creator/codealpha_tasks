#!/usr/bin/env python3
"""
Network Packet Capture and Analysis Tool
======================================
A comprehensive tool for capturing, analyzing, and understanding network packets.
Supports both live capture (requires root/admin privileges) and PCAP file analysis.

Requirements:
    pip install scapy colorama

Usage:
    sudo python3 packet_analyzer.py              # Live capture (all interfaces)
    sudo python3 packet_analyzer.py -i eth0      # Live capture (specific interface)
    python3 packet_analyzer.py -r capture.pcap   # Read from PCAP file
    python3 packet_analyzer.py -c 100            # Capture 100 packets then stop
    python3 packet_analyzer.py -f "tcp port 80"  # Capture with BPF filter
"""

import sys
import argparse
import signal
import time
from datetime import datetime
from collections import Counter, defaultdict
from typing import Optional, Dict, List, Any

# Try to import scapy - provide helpful error if not installed
try:
    from scapy.all import (
        sniff, Raw, IP, TCP, UDP, ICMP, ARP, Ether,
        wrpcap, rdpcap, get_if_list, conf, hexdump
    )
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("ERROR: Scapy is not installed. Please run: pip install scapy")
    print("Note: On Linux, you may also need: sudo apt-get install tcpdump")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR_AVAILABLE = True
except ImportError:
    COLOR_AVAILABLE = False
    # Dummy color classes
    class _DummyColor:
        def __getattr__(self, name):
            return ''
    Fore = _DummyColor()
    Style = _DummyColor()


class PacketAnalyzer:
    """
    A comprehensive network packet analyzer that captures and dissects
    network traffic to understand protocol structures and data flow.
    """
    
    # Protocol color mapping for visual distinction
    PROTOCOL_COLORS = {
        'TCP': Fore.CYAN,
        'UDP': Fore.GREEN,
        'ICMP': Fore.YELLOW,
        'ARP': Fore.MAGENTA,
        'DNS': Fore.BLUE,
        'HTTP': Fore.WHITE,
        'OTHER': Fore.RED,
    }
    
    def __init__(self, interface: Optional[str] = None, 
                 packet_count: Optional[int] = None,
                 bpf_filter: Optional[str] = None):
        self.interface = interface
        self.packet_count = packet_count
        self.bpf_filter = bpf_filter
        self.packets_captured = 0
        self.stats = {
            'protocols': Counter(),
            'src_ips': Counter(),
            'dst_ips': Counter(),
            'src_ports': Counter(),
            'dst_ports': Counter(),
            'total_bytes': 0,
        }
        self.packet_history: List[Dict[str, Any]] = []
        self.running = True
        
        # Setup graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully."""
        print(f"\n{Fore.YELLOW}⚠ Stopping capture...{Style.RESET_ALL}")
        self.running = False
    
    def _get_protocol_color(self, protocol: str) -> str:
        """Get color for a protocol type."""
        return self.PROTOCOL_COLORS.get(protocol, self.PROTOCOL_COLORS['OTHER'])
    
    def _format_timestamp(self, pkt_time: float) -> str:
        """Format packet timestamp nicely."""
        return datetime.fromtimestamp(pkt_time).strftime('%H:%M:%S.%f')[:-3]
    
    def _safe_decode(self, data: bytes, max_len: int = 200) -> str:
        """Safely decode bytes to string, showing both hex and ascii."""
        if not data:
            return "[No payload]"
        
        # Show printable characters, replace others with dots
        ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:max_len])
        
        # If it looks like text, return it
        if any(c.isprintable() and c.isalpha() for c in ascii_repr[:50]):
            if len(data) > max_len:
                return ascii_repr + f" ... [{len(data)} bytes total]"
            return ascii_repr
        
        # Otherwise return hex representation
        hex_str = data[:max_len].hex(' ')
        if len(data) > max_len:
            hex_str += f" ... [{len(data)} bytes total]"
        return hex_str
    
    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """
        Analyze a single packet and extract structured information.
        This is the core analysis engine that understands packet structure.
        """
        info = {
            'timestamp': packet.time,
            'size': len(packet),
            'layers': [],
            'protocol': 'OTHER',
            'summary': '',
            'details': {},
        }
        
        # Track total bytes
        self.stats['total_bytes'] += len(packet)
        
        # === ETHERNET LAYER (Layer 2) ===
        if packet.haslayer(Ether):
            eth = packet[Ether]
            info['layers'].append('Ethernet')
            info['details']['ethernet'] = {
                'src_mac': eth.src,
                'dst_mac': eth.dst,
                'type': hex(eth.type),
            }
        
        # === ARP (Address Resolution Protocol) ===
        if packet.haslayer(ARP):
            arp = packet[ARP]
            info['protocol'] = 'ARP'
            info['layers'].append('ARP')
            info['details']['arp'] = {
                'operation': 'Request' if arp.op == 1 else 'Reply' if arp.op == 2 else f'OP{arp.op}',
                'sender_mac': arp.hwsrc,
                'sender_ip': arp.psrc,
                'target_mac': arp.hwdst,
                'target_ip': arp.pdst,
            }
            info['summary'] = f"ARP {info['details']['arp']['operation']}: {arp.psrc} -> {arp.pdst}"
            self.stats['protocols']['ARP'] += 1
            return info
        
        # === IP LAYER (Layer 3) ===
        if packet.haslayer(IP):
            ip = packet[IP]
            info['layers'].append('IP')
            info['details']['ip'] = {
                'version': ip.version,
                'header_length': ip.ihl * 4,  # in bytes
                'ttl': ip.ttl,
                'protocol_num': ip.proto,
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'flags': str(ip.flags),
                'fragment_offset': ip.frag,
                'checksum': hex(ip.chksum),
            }
            
            # Track IPs
            self.stats['src_ips'][ip.src] += 1
            self.stats['dst_ips'][ip.dst] += 1
            
            # === ICMP (Internet Control Message Protocol) ===
            if packet.haslayer(ICMP):
                icmp = packet[ICMP]
                info['protocol'] = 'ICMP'
                info['layers'].append('ICMP')
                info['details']['icmp'] = {
                    'type': icmp.type,
                    'code': icmp.code,
                    'type_name': self._get_icmp_type_name(icmp.type),
                    'checksum': hex(icmp.chksum),
                }
                info['summary'] = f"ICMP {info['details']['icmp']['type_name']} ({icmp.type}/{icmp.code}) {ip.src} -> {ip.dst}"
                self.stats['protocols']['ICMP'] += 1
            
            # === TCP (Transmission Control Protocol) ===
            elif packet.haslayer(TCP):
                tcp = packet[TCP]
                info['protocol'] = 'TCP'
                info['layers'].append('TCP')
                info['details']['tcp'] = {
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'seq_num': tcp.seq,
                    'ack_num': tcp.ack,
                    'flags': self._parse_tcp_flags(tcp),
                    'window_size': tcp.window,
                    'urgent_pointer': tcp.urgptr,
                    'checksum': hex(tcp.chksum),
                    'data_offset': tcp.dataofs * 4,
                }
                
                # Track ports
                self.stats['src_ports'][tcp.sport] += 1
                self.stats['dst_ports'][tcp.dport] += 1
                
                # Determine service
                service = self._get_service_name(tcp.dport, tcp.sport)
                
                # === HTTP over TCP ===
                if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                    info['protocol'] = 'HTTP'
                    info['layers'].append('HTTP')
                    http_info = self._parse_http(packet)
                    info['details']['http'] = http_info
                    info['summary'] = f"HTTP {http_info.get('method', '')} {http_info.get('host', '')} {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
                    self.stats['protocols']['HTTP'] += 1
                else:
                    flag_str = '|'.join(info['details']['tcp']['flags']) if info['details']['tcp']['flags'] else 'NONE'
                    info['summary'] = f"TCP [{flag_str}] {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} ({service})"
                    self.stats['protocols']['TCP'] += 1
                
                # Extract payload
                payload = bytes(tcp.payload)
                if payload:
                    info['payload'] = payload
                    info['payload_text'] = self._safe_decode(payload)
            
            # === UDP (User Datagram Protocol) ===
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                info['protocol'] = 'UDP'
                info['layers'].append('UDP')
                info['details']['udp'] = {
                    'src_port': udp.sport,
                    'dst_port': udp.dport,
                    'length': udp.len,
                    'checksum': hex(udp.chksum),
                }
                
                self.stats['src_ports'][udp.sport] += 1
                self.stats['dst_ports'][udp.dport] += 1
                service = self._get_service_name(udp.dport, udp.sport)
                
                # === DNS over UDP ===
                if packet.haslayer(DNS):
                    info['protocol'] = 'DNS'
                    info['layers'].append('DNS')
                    dns_info = self._parse_dns(packet)
                    info['details']['dns'] = dns_info
                    info['summary'] = f"DNS {dns_info.get('query_name', '')} {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"
                    self.stats['protocols']['DNS'] += 1
                else:
                    info['summary'] = f"UDP {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} ({service})"
                    self.stats['protocols']['UDP'] += 1
                
                # Extract payload
                payload = bytes(udp.payload)
                if payload and not packet.haslayer(DNS):
                    info['payload'] = payload
                    info['payload_text'] = self._safe_decode(payload)
            
            # Other IP protocols
            else:
                info['summary'] = f"IP Protocol {ip.proto} {ip.src} -> {ip.dst}"
        
        else:
            # Non-IP packet
            info['summary'] = f"Non-IP Packet: {packet.summary()}"
        
        return info
    
    def _parse_tcp_flags(self, tcp) -> List[str]:
        """Parse TCP flags into human-readable list."""
        flags = []
        if tcp.syn: flags.append('SYN')
        if tcp.ack: flags.append('ACK')
        if tcp.fin: flags.append('FIN')
        if tcp.rst: flags.append('RST')
        if tcp.psh: flags.append('PSH')
        if tcp.urg: flags.append('URG')
        if tcp.ece: flags.append('ECE')
        if tcp.cwr: flags.append('CWR')
        return flags
    
    def _get_icmp_type_name(self, icmp_type: int) -> str:
        """Get human-readable ICMP type name."""
        icmp_types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            5: 'Redirect',
            8: 'Echo Request',
            11: 'Time Exceeded',
            12: 'Parameter Problem',
            13: 'Timestamp Request',
            14: 'Timestamp Reply',
        }
        return icmp_types.get(icmp_type, f'Unknown({icmp_type})')
    
    def _get_service_name(self, port1: int, port2: int) -> str:
        """Guess service name from port number."""
        common_ports = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 161: 'SNMP',
            162: 'SNMP-Trap', 443: 'HTTPS', 445: 'SMB',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
        }
        # Check well-known ports first
        for port in [port1, port2]:
            if port in common_ports:
                return common_ports[port]
        # Check if ephemeral port
        if port1 > 49152 or port2 > 49152:
            return 'Ephemeral'
        return 'Unknown'
    
    def _parse_http(self, packet) -> Dict[str, Any]:
        """Parse HTTP request/response details."""
        http_info = {}
        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            http_info['type'] = 'Request'
            http_info['method'] = http.Method.decode() if isinstance(http.Method, bytes) else str(http.Method)
            http_info['path'] = http.Path.decode() if isinstance(http.Path, bytes) else str(http.Path)
            http_info['host'] = http.Host.decode() if hasattr(http, 'Host') and http.Host else ''
            http_info['user_agent'] = http.User_Agent.decode() if hasattr(http, 'User_Agent') and http.User_Agent else ''
        elif packet.haslayer(HTTPResponse):
            http = packet[HTTPResponse]
            http_info['type'] = 'Response'
            http_info['status_code'] = http.Status_Code.decode() if isinstance(http.Status_Code, bytes) else str(http.Status_Code)
            http_info['reason'] = http.Reason_Phrase.decode() if isinstance(http.Reason_Phrase, bytes) else str(http.Reason_Phrase)
        return http_info
    
    def _parse_dns(self, packet) -> Dict[str, Any]:
        """Parse DNS query/response details."""
        dns = packet[DNS]
        dns_info = {
            'id': dns.id,
            'qr': 'Response' if dns.qr else 'Query',
            'opcode': dns.opcode,
            'rcode': dns.rcode,
            'qdcount': dns.qdcount,
            'ancount': dns.ancount,
        }
        
        # Extract query name
        if dns.qdcount and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname
            if isinstance(qname, bytes):
                try:
                    dns_info['query_name'] = qname.decode()
                except:
                    dns_info['query_name'] = str(qname)
            else:
                dns_info['query_name'] = str(qname)
        else:
            dns_info['query_name'] = ''
        
        return dns_info
    
    def display_packet(self, info: Dict[str, Any], packet_num: int):
        """
        Display a packet's information in a structured, readable format.
        This shows how data flows through the network layer by layer.
        """
        color = self._get_protocol_color(info['protocol'])
        ts = self._format_timestamp(info['timestamp'])
        
        # Header line
        print(f"\n{'='*80}")
        print(f"{color}[{packet_num}] {info['protocol']} Packet | {ts} | {info['size']} bytes{Style.RESET_ALL}")
        print(f"{'='*80}")
        
        # Summary
        print(f"{Fore.WHITE}📋 SUMMARY: {info['summary']}{Style.RESET_ALL}")
        print(f"{'─'*80}")
        
        # Layer stack
        print(f"{Fore.YELLOW}🔧 PROTOCOL STACK: {' → '.join(info['layers'])}{Style.RESET_ALL}")
        
        # Detailed layer information
        for layer_name, layer_data in info['details'].items():
            print(f"\n{Fore.CYAN}▶ {layer_name.upper()} LAYER:{Style.RESET_ALL}")
            for key, value in layer_data.items():
                print(f"   • {key:20s}: {value}")
        
        # Payload
        if 'payload_text' in info:
            print(f"\n{Fore.GREEN}▶ PAYLOAD ({len(info['payload'])} bytes):{Style.RESET_ALL}")
            # Show payload with indentation
            payload_lines = info['payload_text'].split('\n')
            for line in payload_lines[:10]:  # Limit to 10 lines
                print(f"   {line}")
            if len(payload_lines) > 10:
                print(f"   ... [{len(payload_lines) - 10} more lines]")
        
        print(f"{'='*80}")
    
    def display_statistics(self):
        """Display capture statistics summary."""
        print(f"\n{'#'*80}")
        print(f"{Fore.CYAN}📊 CAPTURE STATISTICS{Style.RESET_ALL}")
        print(f"{'#'*80}")
        
        print(f"\n{Fore.YELLOW}Total Packets:{Style.RESET_ALL} {self.packets_captured}")
        print(f"{Fore.YELLOW}Total Bytes:{Style.RESET_ALL} {self.stats['total_bytes']:,} ({self.stats['total_bytes']/1024/1024:.2f} MB)")
        
        # Protocol distribution
        print(f"\n{Fore.GREEN}Protocol Distribution:{Style.RESET_ALL}")
        for proto, count in self.stats['protocols'].most_common():
            pct = (count / self.packets_captured * 100) if self.packets_captured > 0 else 0
            bar = '█' * int(pct / 2)
            print(f"  {proto:10s}: {count:6d} ({pct:5.1f}%) {bar}")
        
        # Top source IPs
        print(f"\n{Fore.GREEN}Top Source IPs:{Style.RESET_ALL}")
        for ip, count in self.stats['src_ips'].most_common(5):
            print(f"  {ip:15s}: {count:6d} packets")
        
        # Top destination ports
        print(f"\n{Fore.GREEN}Top Destination Ports:{Style.RESET_ALL}")
        for port, count in self.stats['dst_ports'].most_common(5):
            service = self._get_service_name(port, 0)
            print(f"  Port {port:5d} ({service:12s}): {count:6d} packets")
        
        print(f"\n{'#'*80}")
    
    def packet_callback(self, packet):
        """Callback function for each captured packet."""
        if not self.running:
            return
        
        self.packets_captured += 1
        info = self.analyze_packet(packet)
        
        if info:
            self.packet_history.append(info)
            self.display_packet(info, self.packets_captured)
            
            # Stop if we've reached the packet count limit
            if self.packet_count and self.packets_captured >= self.packet_count:
                self.running = False
                raise KeyboardInterrupt  # Gracefully stop sniffing
    
    def start_capture(self):
        """Start live packet capture."""
        print(f"{Fore.CYAN}🔴 Starting Network Packet Capture{Style.RESET_ALL}")
        print(f"{'─'*60}")
        print(f"Interface: {self.interface or 'default'}")
        print(f"Filter: {self.bpf_filter or 'none'}")
        print(f"Count: {self.packet_count or 'unlimited'}")
        print(f"{'─'*60}")
        print(f"{Fore.YELLOW}Press Ctrl+C to stop capturing{Style.RESET_ALL}\n")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                filter=self.bpf_filter,
                store=0,  # Don't store in memory (we handle it ourselves)
                stop_filter=lambda x: not self.running,
            )
        except PermissionError:
            print(f"\n{Fore.RED}❌ ERROR: Permission denied!{Style.RESET_ALL}")
            print("Packet capture requires root/administrator privileges.")
            print("Please run with: sudo python3 packet_analyzer.py")
            sys.exit(1)
        except Exception as e:
            print(f"\n{Fore.RED}❌ Capture error: {e}{Style.RESET_ALL}")
        
        # Display final statistics
        self.display_statistics()
    
    def analyze_pcap(self, filename: str):
        """Analyze packets from a PCAP file."""
        print(f"{Fore.CYAN}📁 Reading PCAP file: {filename}{Style.RESET_ALL}")
        
        try:
            packets = rdpcap(filename)
            print(f"Loaded {len(packets)} packets from file.\n")
            
            for i, packet in enumerate(packets, 1):
                if self.packet_count and i > self.packet_count:
                    break
                
                self.packets_captured += 1
                info = self.analyze_packet(packet)
                
                if info:
                    self.packet_history.append(info)
                    self.display_packet(info, i)
            
            self.display_statistics()
            
        except FileNotFoundError:
            print(f"{Fore.RED}❌ File not found: {filename}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}❌ Error reading PCAP: {e}{Style.RESET_ALL}")
            sys.exit(1)
    
    def save_to_pcap(self, filename: str = "capture.pcap"):
        """Save captured packets to a PCAP file."""
        if not self.packet_history:
            print(f"{Fore.YELLOW}No packets to save.{Style.RESET_ALL}")
            return
        
        try:
            # We need to reconstruct scapy packets from our history
            # For simplicity, we'll use a different approach - store raw packets during capture
            print(f"{Fore.YELLOW}Note: Use -w flag with tcpdump or modify to store raw packets for PCAP export.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error saving: {e}{Style.RESET_ALL}")


def list_interfaces():
    """List available network interfaces."""
    print(f"{Fore.CYAN}Available Network Interfaces:{Style.RESET_ALL}")
    try:
        from scapy.all import get_if_list
        for iface in get_if_list():
            print(f"  • {iface}")
    except:
        print("  Could not retrieve interface list. Try running with sudo.")


def main():
    parser = argparse.ArgumentParser(
        description='Network Packet Capture and Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 packet_analyzer.py                    # Capture all traffic
  sudo python3 packet_analyzer.py -i eth0 -c 50      # Capture 50 packets on eth0
  sudo python3 packet_analyzer.py -f "tcp port 80"   # Capture only HTTP traffic
  python3 packet_analyzer.py -r capture.pcap         # Analyze PCAP file
  python3 packet_analyzer.py --list                  # Show interfaces
        """
    )
    
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-f', '--filter', help='BPF filter (e.g., "tcp port 80")')
    parser.add_argument('-r', '--read', help='Read packets from PCAP file instead of live capture')
    parser.add_argument('--list', action='store_true', help='List available interfaces and exit')
    
    args = parser.parse_args()
    
    if args.list:
        list_interfaces()
        return
    
    # Create analyzer
    analyzer = PacketAnalyzer(
        interface=args.interface,
        packet_count=args.count,
        bpf_filter=args.filter
    )
    
    if args.read:
        # Analyze from file
        analyzer.analyze_pcap(args.read)
    else:
        # Live capture
        analyzer.start_capture()


if __name__ == '__main__':
    main()