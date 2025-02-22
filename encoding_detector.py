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

class EncodingDetector:
    def __init__(self):
        self.patterns = {
            'base64': re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'),
            'hex': re.compile(r'^[0-9a-fA-F]+$'),
            'binary': re.compile(r'^[01]+$'),
            'jwt': re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'),
            'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
            'ip': re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'),
            'zlib': re.compile(rb'^\x78[\x01\x9c\xda\x5e]')
        }
        try:
            import zlib as zlib_module
            self.zlib = zlib_module
            self.zlib_available = True
        except ImportError:
            self.zlib_available = False
            print("Warning: zlib module not available")
    def calculate_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    def detect_encoding(self, data):
        results = []
        try:
            str_data = data.decode('utf-8', errors='ignore')
        except:
            str_data = ""
        entropy = self.calculate_entropy(data)
        # Check for zlib compression first
        if self.zlib_available:
            try:
                if len(data) >= 2 and data.startswith(b'\x78'):
                    decompressed = self.zlib.decompress(data)
                    results.append(('Zlib', decompressed, 0.95))
                    try:
                        decoded_str = decompressed.decode('utf-8', errors='ignore')
                        if self.is_printable(decompressed):
                            results.append(('Zlib->Text', decoded_str, 0.90))
                    except:
                        pass
            except:
                pass
        # Base64 detection
        if self.patterns['base64'].match(str_data):
            try:
                decoded = base64.b64decode(data + b'=' * (-len(data) % 4))
                if self.is_printable(decoded):
                    results.append(('Base64', decoded, 0.9))
                # Check if base64 decoded data is zlib compressed
                if self.zlib_available:
                    try:
                        if decoded.startswith(b'\x78'):
                            decompressed = self.zlib.decompress(decoded)
                            results.append(('Base64->Zlib', decompressed, 0.85))
                    except:
                        pass
            except:
                pass
        # Hex detection
        if self.patterns['hex'].match(str_data):
            try:
                decoded = bytes.fromhex(str_data)
                if self.is_printable(decoded):
                    results.append(('Hex', decoded, 0.8))
                # Check if hex decoded data is zlib compressed
                if self.zlib_available:
                    try:
                        if decoded.startswith(b'\x78'):
                            decompressed = self.zlib.decompress(decoded)
                            results.append(('Hex->Zlib', decompressed, 0.75))
                    except:
                        pass
            except:
                pass
        # JWT detection
        if self.patterns['jwt'].match(str_data):
            results.append(('JWT', None, 0.95))
        # Compressed/Encrypted detection
        if entropy > 7.5:
            results.append(('Compressed', None, 0.7))
        if 7.8 <= entropy <= 8.0:
            results.append(('Encrypted', None, 0.8))
        return results if results else []
    def is_printable(self, data):
        try:
            text = data.decode('utf-8')
            return all(char in string.printable for char in text)
        except:
            return False