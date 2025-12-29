"""
Paket analiz işlemleri
"""

from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.dns import DNS
import socket
from collections import Counter, defaultdict
from datetime import datetime


class PacketAnalyzer:

    def __init__(self):
        self.port_to_service = self._load_service_ports()

    def _load_service_ports(self):
        common_ports = {
            20: 'FTP-Data',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            67: 'DHCP-Server',
            68: 'DHCP-Client',
            69: 'TFTP',
            80: 'HTTP',
            110: 'POP3',
            123: 'NTP',
            143: 'IMAP',
            161: 'SNMP',
            162: 'SNMP-Trap',
            443: 'HTTPS',
            465: 'SMTPS',
            587: 'SMTP',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        return common_ports

    def analyze_packet(self, packet):
        packet_info = {
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'src_ip': 'N/A',
            'dst_ip': 'N/A',
            'src_port': 'N/A',
            'dst_port': 'N/A',
            'protocol': 'Unknown',
            'length': len(packet),
            'info': '',
            'raw': packet
        }

        try:
            # IP katmanı
            if packet.haslayer('IP'):
                packet_info['src_ip'] = packet['IP'].src
                packet_info['dst_ip'] = packet['IP'].dst
            elif packet.haslayer('IPv6'):
                packet_info['src_ip'] = packet['IPv6'].src
                packet_info['dst_ip'] = packet['IPv6'].dst
                packet_info['protocol'] = 'IPv6'

            # TCP katmanı
            if packet.haslayer('TCP'):
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet['TCP'].sport
                packet_info['dst_port'] = packet['TCP'].dport
                packet_info['info'] = self._analyze_tcp(packet)

            # UDP katmanı
            elif packet.haslayer('UDP'):
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet['UDP'].sport
                packet_info['dst_port'] = packet['UDP'].dport
                packet_info['info'] = self._analyze_udp(packet)

            # ICMP katmanı
            elif packet.haslayer('ICMP'):
                packet_info['protocol'] = 'ICMP'
                packet_info['info'] = self._analyze_icmp(packet)

            # ARP katmanı
            elif packet.haslayer('ARP'):
                packet_info['protocol'] = 'ARP'
                packet_info['info'] = self._analyze_arp(packet)

            if packet_info['dst_port'] != 'N/A' and isinstance(packet_info['dst_port'], int):
                service = self.port_to_service.get(packet_info['dst_port'])
                if service:
                    if packet_info['info']:
                        packet_info['info'] = f"{service} - {packet_info['info']}"
                    else:
                        packet_info['info'] = service

            if packet_info['protocol'] == 'Unknown':
                if isinstance(packet_info['dst_port'], int):
                    if packet_info['dst_port'] in [80, 8080, 8443]:
                        packet_info['protocol'] = 'HTTP/HTTPS'
                    elif packet_info['dst_port'] in [53, 5353]:
                        packet_info['protocol'] = 'DNS'
                    elif packet_info['dst_port'] in [67, 68]:
                        packet_info['protocol'] = 'DHCP'

        except Exception as e:
            packet_info['info'] = f"Analiz hatası: {str(e)}"

        return packet_info

    def _analyze_tcp(self, packet):
        try:
            tcp_layer = packet['TCP']
            info_parts = []

            # TCP flag'leri
            flags = []
            if tcp_layer.flags & 0x02:  # SYN
                flags.append('SYN')
            if tcp_layer.flags & 0x10:  # ACK
                flags.append('ACK')
            if tcp_layer.flags & 0x01:  # FIN
                flags.append('FIN')
            if tcp_layer.flags & 0x08:  # PSH
                flags.append('PSH')
            if tcp_layer.flags & 0x04:  # RST
                flags.append('RST')
            if tcp_layer.flags & 0x20:  # URG
                flags.append('URG')

            if flags:
                info_parts.append(f"Flags: {', '.join(flags)}")

            info_parts.append(f"Win: {tcp_layer.window}")

            info_parts.append(f"Seq: {tcp_layer.seq}")

            if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                http_info = self._analyze_http(packet)
                if http_info:
                    return f"HTTP: {http_info}"

            if tcp_layer.dport == 443 or tcp_layer.sport == 443:
                return "HTTPS"

            service_info = self._get_service_info(tcp_layer.dport)
            if service_info:
                return service_info

            return f"TCP {tcp_layer.sport} → {tcp_layer.dport}"

        except Exception as e:
            return f"TCP Error: {str(e)}"

    def _analyze_udp(self, packet):
        try:
            udp_layer = packet['UDP']

            # DNS
            if udp_layer.dport == 53 or udp_layer.sport == 53:
                dns_info = self._analyze_dns(packet)
                if dns_info:
                    return f"DNS: {dns_info}"
                return 'DNS'

            # DHCP
            elif udp_layer.dport == 67 or udp_layer.sport == 67:
                return 'DHCP Server'
            elif udp_layer.dport == 68 or udp_layer.sport == 68:
                return 'DHCP Client'

            service_info = self._get_service_info(udp_layer.dport)
            if service_info:
                return service_info

            return f"UDP {udp_layer.sport} → {udp_layer.dport}"

        except Exception as e:
            return f"UDP Error: {str(e)}"

    def _analyze_icmp(self, packet):
        try:
            icmp_layer = packet['ICMP']

            icmp_types = {
                0: 'Echo Reply',
                3: 'Destination Unreachable',
                5: 'Redirect',
                8: 'Echo Request',
                11: 'Time Exceeded',
                13: 'Timestamp Request',
                14: 'Timestamp Reply',
                17: 'Address Mask Request',
                18: 'Address Mask Reply'
            }

            icmp_type = icmp_layer.type
            type_name = icmp_types.get(icmp_type, f'Type {icmp_type}')

            return f"ICMP {type_name}"

        except Exception as e:
            return f"ICMP Error: {str(e)}"

    def _analyze_arp(self, packet):
        try:
            arp_layer = packet['ARP']

            arp_opcodes = {
                1: 'ARP Request',
                2: 'ARP Reply',
                3: 'RARP Request',
                4: 'RARP Reply'
            }

            opcode = arp_layer.op
            opcode_name = arp_opcodes.get(opcode, f'Opcode {opcode}')

            return f"ARP {opcode_name}: {arp_layer.psrc} -> {arp_layer.pdst}"

        except Exception as e:
            return f"ARP Error: {str(e)}"

    def _analyze_http(self, packet):
        try:
            if packet.haslayer('Raw'):
                raw_data = packet['Raw'].load
                try:
                    decoded_data = raw_data.decode('utf-8', errors='ignore')
                except (UnicodeDecodeError, AttributeError):
                    decoded_data = str(raw_data)

                if decoded_data.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
                    lines = decoded_data.split('\r\n')
                    if lines:
                        request_line = lines[0]
                        if 'HTTP/' in request_line:
                            return request_line.split(' HTTP/')[0]
                        return request_line[:80]  # İlk 80 karakter

                elif decoded_data.startswith('HTTP/'):
                    lines = decoded_data.split('\r\n')
                    if lines:
                        status_line = lines[0]
                        return status_line[:80]

                elif 'HTTP/' in decoded_data:
                    for line in decoded_data.split('\r\n'):
                        if line.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'HTTP/')):
                            return line[:80]

        except Exception as e:
            pass

        return "HTTP Data"

    def _analyze_dns(self, packet):
        try:
            if packet.haslayer('DNS'):
                dns_layer = packet['DNS']

                if dns_layer.qr == 0:  # Query
                    if hasattr(dns_layer, 'qd') and dns_layer.qd:
                        qname = dns_layer.qd.qname
                        if isinstance(qname, bytes):
                            try:
                                decoded_qname = qname.decode('utf-8', errors='ignore')
                                decoded_qname = decoded_qname.rstrip('.')
                                return f"Query: {decoded_qname}"
                            except:
                                return "DNS Query"
                else:
                    answer_count = dns_layer.ancount if hasattr(dns_layer, 'ancount') else 0
                    return f"Response ({answer_count} answers)"

        except Exception:
            pass

        return "DNS"

    def _get_service_info(self, port):
        if isinstance(port, int):
            service = self.port_to_service.get(port)
            if service:
                return service
        return None

    def get_protocol_stats(self, packets):
        protocol_counter = Counter()

        for packet_info in packets:
            protocol = packet_info.get('protocol', 'Unknown')
            protocol_counter[protocol] += 1

        return protocol_counter

    def get_ip_stats(self, packets):
        stats = {
            'src_ips': Counter(),
            'dst_ips': Counter(),
            'conversations': Counter()
        }

        for packet_info in packets:
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')

            if src_ip != 'N/A':
                stats['src_ips'][src_ip] += 1
            if dst_ip != 'N/A':
                stats['dst_ips'][dst_ip] += 1

            if src_ip != 'N/A' and dst_ip != 'N/A':
                conversation = f"{src_ip} ↔ {dst_ip}"
                stats['conversations'][conversation] += 1

        return stats