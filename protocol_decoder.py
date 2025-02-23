import scapy.all as scapy
from scapy.layers import http

import base64
from datetime import datetime
import json

class ProtocolDecoder:
    """
    The ProtocolDecoder class is responsible for decoding various layers of a network packet.
    It extracts information from layers 2, 3, 4, and 7 (application layer), including payload data
    and raw packet information. In addition, it identifies protocols present in the packet.

    The class provides helper methods to decode individual layers such as Ethernet or WiFi (Layer 2),
    IP/ARP (Layer 3), TCP/UDP/ICMP (Layer 4), and common application protocols (Layer 7, e.g., HTTP, DNS, TLS).
    It also includes utility functions for extracting timestamps and raw packet data.
    
    Attributes:
        app_protocols (dict): Mapping of common TCP/UDP port numbers to their corresponding application protocols.
    """

    def __init__(self):
        """
        Initialize a new ProtocolDecoder instance and register known application layer protocols.
        """
        # Register known application layer protocols based on common port numbers.
        self.app_protocols = {
            80: 'HTTP',
            443: 'HTTPS',
            53: 'DNS',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            445: 'SMB',
            3306: 'MySQL',
            1433: 'MSSQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }

    def decode_packet(self, packet):
        """
        Main packet decoding method.

        This method extracts and decodes information from different layers of the packet.
        It constructs a dictionary containing:
          - Timestamp information,
          - Layer 2 (Data Link Layer) details,
          - Layer 3 (Network Layer) details,
          - Layer 4 (Transport Layer) details,
          - Layer 7 (Application Layer) details,
          - Payload decoding,
          - A list of identified protocols,
          - Raw packet data summary.

        Parameters:
            packet: The network packet to decode.

        Returns:
            dict: A dictionary containing decoded information from all layers.
        """
        decoded_info = {
            'timestamp': self.get_timestamp(packet),
            'layer2': self.decode_layer2(packet),
            'layer3': self.decode_layer3(packet),
            'layer4': self.decode_layer4(packet),
            'layer7': self.decode_layer7(packet),
            'payload': self.decode_payload(packet),
            'protocols': self.identify_protocols(packet),
            'raw_data': self.get_raw_data(packet)
        }
        return decoded_info

    def get_timestamp(self, packet):
        """
        Extract and format the packet's timestamp.

        Converts the packet's epoch time into a dictionary containing both the raw epoch
        and a formatted timestamp string.

        Parameters:
            packet: The network packet containing the timestamp.

        Returns:
            dict: A dictionary with 'epoch' and 'formatted' timestamp keys.
        """
        return {
            'epoch': packet.time,
            'formatted': datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f')
        }

    def decode_layer2(self, packet):
        """
        Decode Layer 2 (Data Link Layer) information from the packet.

        If the packet contains an Ethernet layer, extract the source and destination MAC addresses,
        and the EtherType. If it contains a Dot11 layer, extract the relevant WiFi addresses.

        Parameters:
            packet: The network packet.

        Returns:
            dict: A dictionary containing Layer 2 information.
        """
        l2_info = {}
        
        if packet.haslayer('Ether'):
            l2_info['type'] = 'Ethernet'
            l2_info['src_mac'] = packet.src
            l2_info['dst_mac'] = packet.dst
            l2_info['ethertype'] = hex(packet.type)
            
        elif packet.haslayer('Dot11'):
            l2_info['type'] = 'WiFi'
            l2_info['src_mac'] = packet.addr2
            l2_info['dst_mac'] = packet.addr1
            l2_info['bssid'] = packet.addr3
            
        return l2_info

    def decode_layer3(self, packet):
        """
        Decode Layer 3 (Network Layer) information from the packet.

        Extracts details from IPv4, IPv6, or ARP layers such as source/destination IP,
        TTL, flags, and other header fields.

        Parameters:
            packet: The network packet.

        Returns:
            dict: A dictionary containing Layer 3 information.
        """
        l3_info = {}
        
        if packet.haslayer('IP'):
            l3_info['type'] = 'IPv4'
            l3_info['src_ip'] = packet[scapy.IP].src
            l3_info['dst_ip'] = packet[scapy.IP].dst
            l3_info['ttl'] = packet[scapy.IP].ttl
            l3_info['id'] = packet[scapy.IP].id
            l3_info['flags'] = self.decode_ip_flags(packet[scapy.IP].flags)
            l3_info['tos'] = packet[scapy.IP].tos
            l3_info['length'] = packet[scapy.IP].len
            
        elif packet.haslayer('IPv6'):
            l3_info['type'] = 'IPv6'
            l3_info['src_ip'] = packet[scapy.IPv6].src
            l3_info['dst_ip'] = packet[scapy.IPv6].dst
            l3_info['traffic_class'] = packet[scapy.IPv6].tc
            l3_info['flow_label'] = packet[scapy.IPv6].fl
            l3_info['hop_limit'] = packet[scapy.IPv6].hlim
            
        elif packet.haslayer('ARP'):
            l3_info['type'] = 'ARP'
            l3_info['op'] = 'Request' if packet[scapy.ARP].op == 1 else 'Reply'
            l3_info['src_ip'] = packet[scapy.ARP].psrc
            l3_info['dst_ip'] = packet[scapy.ARP].pdst
            l3_info['src_mac'] = packet[scapy.ARP].hwsrc
            l3_info['dst_mac'] = packet[scapy.ARP].hwdst
            
        return l3_info

    def decode_layer4(self, packet):
        """
        Decode Layer 4 (Transport Layer) information from the packet.

        Extracts details from TCP, UDP, or ICMP layers, such as source/destination ports,
        sequence numbers, flags, window size, and options for TCP, and appropriate fields for UDP and ICMP.

        Parameters:
            packet: The network packet.

        Returns:
            dict: A dictionary containing Layer 4 information.
        """
        l4_info = {}
        
        if packet.haslayer('TCP'):
            l4_info['type'] = 'TCP'
            l4_info['src_port'] = packet[scapy.TCP].sport
            l4_info['dst_port'] = packet[scapy.TCP].dport
            l4_info['seq'] = packet[scapy.TCP].seq
            l4_info['ack'] = packet[scapy.TCP].ack
            l4_info['flags'] = self.decode_tcp_flags(packet[scapy.TCP].flags)
            l4_info['window'] = packet[scapy.TCP].window
            l4_info['urgent_ptr'] = packet[scapy.TCP].urgptr
            l4_info['options'] = self.decode_tcp_options(packet[scapy.TCP].options)
            
        elif packet.haslayer('UDP'):
            l4_info['type'] = 'UDP'
            l4_info['src_port'] = packet[scapy.UDP].sport
            l4_info['dst_port'] = packet[scapy.UDP].dport
            l4_info['length'] = packet[scapy.UDP].len
            
        elif packet.haslayer('ICMP'):
            l4_info['type'] = 'ICMP'
            l4_info['type_id'] = packet[scapy.ICMP].type
            l4_info['code'] = packet[scapy.ICMP].code
            l4_info['type_name'] = self.get_icmp_type_name(packet[scapy.ICMP].type)
            
        return l4_info

    def decode_layer7(self, packet):
        """
        Decode Layer 7 (Application Layer) protocols from the packet.

        This method attempts to decode application layer protocols:
          - For HTTP, it calls decode_http.
          - For DNS, it calls decode_dns.
          - For TLS/SSL, it calls decode_tls.
          - If neither is found but the packet has TCP or UDP layers, it checks common port numbers
            against a registered list of application protocols.

        Parameters:
            packet: The network packet.

        Returns:
            dict: A dictionary containing Layer 7 protocol details.
        """
        l7_info = {}
        
        # HTTP Detection and Decoding
        if packet.haslayer('HTTP'):
            l7_info['protocol'] = 'HTTP'
            l7_info['http'] = self.decode_http(packet)
            
        # DNS Detection and Decoding
        elif packet.haslayer('DNS'):
            l7_info['protocol'] = 'DNS'
            l7_info['dns'] = self.decode_dns(packet)
            
        # TLS/SSL Detection
        elif packet.haslayer('TLS'):
            l7_info['protocol'] = 'TLS'
            l7_info['tls'] = self.decode_tls(packet)
            
        # Detect other protocols based on ports
        elif packet.haslayer('TCP') or packet.haslayer('UDP'):
            port = min(packet[scapy.TCP].sport if packet.haslayer('TCP') else packet[scapy.UDP].sport,
                      packet[scapy.TCP].dport if packet.haslayer('TCP') else packet[scapy.UDP].dport)
            if port in self.app_protocols:
                l7_info['protocol'] = self.app_protocols[port]
                l7_info['port'] = port
                
        return l7_info

    def decode_http(self, packet):
        """
        Decode HTTP protocol details from the packet.

        Determines whether the packet contains an HTTP request or response and extracts the corresponding
        fields, such as method, path, HTTP version, status code, reason phrase, and headers.

        Parameters:
            packet: The network packet containing HTTP data.

        Returns:
            dict: A dictionary containing HTTP details.
        """
        http_info = {}
        
        if packet.haslayer('HTTP'):
            # HTTP Request
            if packet.haslayer('HTTPRequest'):
                http_info['type'] = 'Request'
                http_info['method'] = packet[http.HTTPRequest].Method.decode()
                http_info['path'] = packet[http.HTTPRequest].Path.decode()
                http_info['version'] = packet[http.HTTPRequest].Http_Version.decode()
                http_info['headers'] = self.decode_http_headers(packet[http.HTTPRequest].fields)
                
            # HTTP Response
            elif packet.haslayer('HTTPResponse'):
                http_info['type'] = 'Response'
                http_info['status_code'] = packet[http.HTTPResponse].Status_Code
                http_info['reason'] = packet[http.HTTPResponse].Reason_Phrase.decode()
                http_info['version'] = packet[http.HTTPResponse].Http_Version.decode()
                http_info['headers'] = self.decode_http_headers(packet[http.HTTPResponse].fields)
                
        return http_info

    def decode_dns(self, packet):
        """
        Decode DNS protocol details from the packet.

        Extracts basic DNS header information, and if available, decodes the queries and answers,
        including record types and data.

        Parameters:
            packet: The network packet containing DNS data.

        Returns:
            dict: A dictionary containing DNS details.
        """
        dns_info = {}
        
        if packet.haslayer('DNS'):
            dns = packet['DNS']
            dns_info['id'] = dns.id
            dns_info['qr'] = 'Response' if dns.qr else 'Query'
            dns_info['opcode'] = dns.opcode
            dns_info['rcode'] = dns.rcode
            
            # Queries
            if dns.qd:
                dns_info['queries'] = [{
                    'name': query.qname.decode(),
                    'type': self.get_dns_type(query.qtype)
                } for query in dns.qd]
                
            # Answers
            if dns.an:
                dns_info['answers'] = [{
                    'name': rr.rrname.decode(),
                    'type': self.get_dns_type(rr.type),
                    'data': self.get_dns_rdata(rr)
                } for rr in dns.an]
                
        return dns_info

    def decode_tls(self, packet):
        """
        Decode TLS protocol details from the packet.

        Extracts TLS type and version, and further details if the packet contains
        a ClientHello or ServerHello message.

        Parameters:
            packet: The network packet containing TLS data.

        Returns:
            dict: A dictionary containing TLS details.
        """
        tls_info = {}
        
        if packet.haslayer('TLS'):
            tls = packet['TLS']
            tls_info['type'] = self.get_tls_type(tls.type)
            tls_info['version'] = self.get_tls_version(tls.version)
            
            # Handle different TLS message types
            if tls.haslayer('TLSClientHello'):
                tls_info['message_type'] = 'Client Hello'
                tls_info['cipher_suites'] = self.decode_cipher_suites(tls['TLSClientHello'].cipher_suites)
                
            elif tls.haslayer('TLSServerHello'):
                tls_info['message_type'] = 'Server Hello'
                tls_info['cipher_suite'] = self.get_cipher_suite_name(tls['TLSServerHello'].cipher_suite)
                
        return tls_info

    def decode_payload(self, packet):
        """
        Decode packet payload with multiple encoding attempts.

        Extracts the payload from TCP, UDP, or the packet's default payload layer and
        attempts various decodings including UTF-8, ASCII, Base64, and JSON.

        Parameters:
            packet: The network packet containing the payload.

        Returns:
            dict: A dictionary containing the raw payload (in hex and length) and any successfully decoded data.
        """
        payload_info = {}
        
        if packet.haslayer('TCP'):
            payload = bytes(packet)
        elif packet.haslayer('UDP'):
            payload = bytes(packet)
        else:
            payload = bytes(packet.payload)
            
        if payload:
            payload_info['raw'] = {
                'hex': payload.hex(),
                'length': len(payload)
            }
            
            # Try various decodings
            try:
                payload_info['utf8'] = payload.decode('utf-8', errors='ignore')
            except:
                pass
                
            try:
                payload_info['ascii'] = payload.decode('ascii', errors='ignore')
            except:
                pass
                
            # Try base64 decoding
            try:
                decoded = base64.b64decode(payload + b'=' * (-len(payload) % 4))
                payload_info['base64'] = {
                    'decoded_hex': decoded.hex(),
                    'decoded_utf8': decoded.decode('utf-8', errors='ignore')
                }
            except:
                pass
                
            # Try JSON decoding
            try:
                json_data = json.loads(payload)
                payload_info['json'] = json_data
            except:
                pass
                
        return payload_info

    def identify_protocols(self, packet):
        """
        Identify all protocols present in the packet.

        Checks various layers (Layer 2, 3, 4, and Application Layer) and returns a list of protocol names
        based on detected layers and, if applicable, registered application protocols.

        Parameters:
            packet: The network packet.

        Returns:
            list: A list of protocol names (e.g., 'Ethernet', 'IPv4', 'TCP', 'HTTP').
        """
        protocols = []
        
        # Layer 2
        if packet.haslayer('Ether'):
            protocols.append('Ethernet')
        elif packet.haslayer('Dot11'):
            protocols.append('802.11')
            
        # Layer 3
        if packet.haslayer('IP'):
            protocols.append('IPv4')
        elif packet.haslayer('IPv6'):
            protocols.append('IPv6')
        elif packet.haslayer('ARP'):
            protocols.append('ARP')
            
        # Layer 4
        if packet.haslayer('TCP'):
            protocols.append('TCP')
        elif packet.haslayer('UDP'):
            protocols.append('UDP')
        elif packet.haslayer('ICMP'):
            protocols.append('ICMP')
            
        # Application Layer
        if packet.haslayer('HTTP'):
            protocols.append('HTTP')
        elif packet.haslayer('DNS'):
            protocols.append('DNS')
        elif packet.haslayer('TLS'):
            protocols.append('TLS')
            
        return protocols

    # Helper methods

    def get_raw_data(self, packet):
        """
        Retrieve raw packet data.

        Returns a dictionary containing the hexadecimal representation of the packet,
        its total length, and a summary string.

        Parameters:
            packet: The network packet.

        Returns:
            dict: A dictionary with keys 'raw_hex', 'length', and 'summary'.
        """
        return {
            'raw_hex': bytes(packet).hex(),
            'length': len(packet),
            'summary': packet.summary()
        }

    def decode_tcp_flags(self, flags):
        """
        Decode TCP flags from the packet.

        Maps TCP flag abbreviations to their full names.

        Parameters:
            flags: The TCP flags from the packet.

        Returns:
            list: A list of decoded flag names.
        """
        flag_map = {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR'
        }
        return [flag_map[f] for f in str(flags)]

    def decode_ip_flags(self, flags):
        """
        Decode IP flags from the packet.

        Maps IP flag abbreviations to their descriptive names.

        Parameters:
            flags: The IP flags from the packet.

        Returns:
            list: A list of decoded IP flag descriptions.
        """
        flag_map = {
            'DF': "Don't Fragment",
            'MF': 'More Fragments'
        }
        return [flag_map[f] for f in str(flags).split('+') if f in flag_map]

    def get_icmp_type_name(self, type_id):
        """
        Get the human-readable name for an ICMP type.

        Parameters:
            type_id (int): The ICMP type identifier.

        Returns:
            str: The corresponding ICMP type name, or a string indicating an unknown type.
        """
        icmp_types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            5: 'Redirect',
            8: 'Echo Request',
            11: 'Time Exceeded'
        }
        return icmp_types.get(type_id, f'Unknown ({type_id})')

    def decode_http_headers(self, fields):
        """
        Decode HTTP headers from a dictionary of fields.

        Transforms header field names from the Scapy format (e.g., 'Http_Content_Type')
        to a more standard format (e.g., 'Content-Type').

        Parameters:
            fields (dict): The fields from an HTTP layer.

        Returns:
            dict: A dictionary of HTTP headers with standardized names.
        """
        headers = {}
        for field in fields:
            if field.startswith('Http_'):
                header_name = field.replace('Http_', '').replace('_', '-')
                headers[header_name] = fields[field]
        return headers

    def get_tls_version(self, version):
        """
        Get a human-readable TLS version name from a version number.

        Parameters:
            version (int): The TLS version number.

        Returns:
            str: The corresponding TLS version name, or a string indicating an unknown version.
        """
        versions = {
            0x0300: 'SSL 3.0',
            0x0301: 'TLS 1.0',
            0x0302: 'TLS 1.1',
            0x0303: 'TLS 1.2',
            0x0304: 'TLS 1.3'
        }
        return versions.get(version, f'Unknown (0x{version:04x})')

    def get_tls_type(self, type_id):
        """
        Get the TLS content type name based on its identifier.

        Parameters:
            type_id (int): The TLS type identifier.

        Returns:
            str: The TLS content type name, or a string indicating an unknown type.
        """
        types = {
            20: 'Change Cipher Spec',
            21: 'Alert',
            22: 'Handshake',
            23: 'Application Data'
        }
        return types.get(type_id, f'Unknown ({type_id})')

    def decode_tcp_options(self, options):
        """
        Decode TCP options from the packet.

        Iterates over the options provided in the TCP header and decodes them.
        If an option tuple has two elements, it uses the second as the value; otherwise,
        the value is set to None.

        Parameters:
            options: The list of TCP options.

        Returns:
            dict: A dictionary mapping option names to their values.
        """
        decoded_options = {}
        for option in options:
            if len(option) == 2:
                decoded_options[option[0]] = option[1]
            else:
                decoded_options[option[0]] = None
        return decoded_options

    def get_dns_type(self, qtype):
        """
        Get the human-readable DNS query type name.

        Parameters:
            qtype (int): The DNS query type identifier.

        Returns:
            str: The corresponding DNS query type name, or a string indicating an unknown type.
        """
        dns_types = {
            1: 'A',
            2: 'NS',
            5: 'CNAME',
            6: 'SOA',
            12: 'PTR',
            15: 'MX',
            16: 'TXT',
            28: 'AAAA'
        }
        return dns_types.get(qtype, f'Unknown ({qtype})')

    def get_dns_rdata(self, rr):
        """
        Get formatted DNS record data.

        For specific record types (A, AAAA, CNAME, MX), extract and decode the rdata appropriately.
        If the record type is not specifically handled, returns the string representation of the record.

        Parameters:
            rr: A DNS resource record.

        Returns:
            str or None: The formatted record data, or None if not available.
        """
        if rr.type == 1:  # A record
            return rr.rdata if hasattr(rr, 'rdata') else None
        elif rr.type == 28:  # AAAA record
            return rr.rdata if hasattr(rr, 'rdata') else None
        elif rr.type == 5:  # CNAME record
            return rr.rdata.decode() if hasattr(rr, 'rdata') else None
        elif rr.type == 15:  # MX record
            return f"{rr.preference} {rr.exchange.decode()}" if hasattr(rr, 'exchange') else None
        return str(rr) if hasattr(rr, '__str__') else "Unknown"

