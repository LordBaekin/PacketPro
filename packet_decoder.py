import scapy.all as scapy
from scapy.all import sniff
from scapy.layers import http, dns, tls

import base64
import binascii
import re
import math
import string
from datetime import datetime
import json
import threading
import os
import zlib
import pandas as pd
import struct
from queue import Queue
import time
import socket
from typing import Dict, List, Tuple, Any
import cProfile
import pstats
import io
import traceback
import pyperclip
from protocol_decoder import ProtocolDecoder
from encoding_detector import EncodingDetector

class PacketDecoder:
    def __init__(self):
        self.protocol_decoder = ProtocolDecoder()
        self.encoding_detector = EncodingDetector()
    def decode_packet(self, packet):
        """Complete packet decoding and analysis"""
        # Get basic protocol decoding
        decoded = self.protocol_decoder.decode_packet(packet)
        
        # Add payload analysis
        if packet.haslayer('Raw'):
            payload = bytes(packet[scapy.Raw].load)
            decoded['payload_analysis'] = self.analyze_payload(payload)
        return decoded

    def analyze_payload(self, payload):
        """Comprehensive payload analysis"""
        analysis = {
            'length': len(payload),
            'hex': payload.hex(),
            'entropy': self.encoding_detector.calculate_entropy(payload)
        }
        
        # Try to decode as text
        try:
            analysis['utf8'] = payload.decode('utf-8')
        except:
            try:
                analysis['ascii'] = payload.decode('ascii', errors='replace')
            except:
                pass
        # Detect encodings
        encodings = self.encoding_detector.detect_encoding(payload)
        if encodings:
            analysis['detected_encodings'] = []
            for encoding, decoded, confidence in encodings:
                encoding_info = {
                    'type': encoding,
                    'confidence': confidence
                }
                if decoded:
                    try:
                        if isinstance(decoded, bytes):
                            encoding_info['decoded'] = {
                                'hex': decoded.hex(),
                                'utf8': decoded.decode('utf-8', errors='ignore')
                            }
                        else:
                            encoding_info['decoded'] = str(decoded)
                    except:
                        encoding_info['decoded'] = {
                            'hex': decoded.hex() if isinstance(decoded, bytes) else None
                        }
                analysis['detected_encodings'].append(encoding_info)
        # Try to identify file signatures
        file_type = self.identify_file_signature(payload)
        if file_type:
            analysis['file_type'] = file_type
        return analysis

    def identify_file_signature(self, data):
        """Identify file type based on magic numbers"""
        signatures = {
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x89PNG\r\n\x1A\n': 'PNG',
            b'GIF87a': 'GIF',
            b'GIF89a': 'GIF',
            b'%PDF': 'PDF',
            b'PK\x03\x04': 'ZIP',
            b'PK\x05\x06': 'ZIP',
            b'PK\x07\x08': 'ZIP',
            b'\x1F\x8B\x08': 'GZIP',
            b'\x42\x5A\x68': 'BZIP2',
            b'\x75\x73\x74\x61\x72': 'TAR',
            b'\x52\x61\x72\x21\x1A\x07': 'RAR',
            b'\x7F\x45\x4C\x46': 'ELF',
            b'\x4D\x5A': 'EXE',
            b'\x25\x21\x50\x53': 'PS'
        }
        
        for signature, filetype in signatures.items():
            if data.startswith(signature):
                return filetype
        return None