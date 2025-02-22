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
    """
    The EncodingDetector class analyzes raw byte data to detect potential encoding schemes,
    compression, or encryption. It computes the Shannon entropy of the data, uses compiled
    regular expressions to identify common encoding patterns (such as Base64, hexadecimal, binary,
    JWT, UUID, and IP formats), and checks for zlib-compressed data. Additionally, it provides a 
    helper method to determine if a given byte sequence represents printable text.

    Attributes:
        patterns (dict): A dictionary mapping encoding names to their compiled regular expression patterns.
        zlib (module): A reference to the zlib module, if available.
        zlib_available (bool): Flag indicating whether the zlib module is available.
    """

    def __init__(self):
        """
        Initialize a new EncodingDetector instance.

        Compiles regular expression patterns for detecting various encodings and attempts to import
        the zlib module. Sets the zlib_available flag accordingly.
        """
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
        """
        Calculate the Shannon entropy of the given data.

        Entropy is a measure of randomness. This method iterates over all possible byte values
        (0-255), calculates the probability of each byte in the data, and computes the total entropy.
        
        Parameters:
            data (bytes): The raw data for which to compute the entropy.
            
        Returns:
            float: The Shannon entropy of the data. Returns 0 if data is empty.
        """
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    def detect_encoding(self, data):
        """
        Detect potential encodings or compressions in the given data.

        The method attempts to identify various encoding schemes by checking the data against precompiled
        regular expressions and by analyzing the data's entropy. It first decodes the data as a UTF-8 string,
        then checks for zlib compression, Base64 encoding, hexadecimal encoding, and JWT format. It also adds
        tags for data that may be compressed or encrypted based on its entropy.

        Parameters:
            data (bytes): The raw data to be analyzed.
            
        Returns:
            list: A list of tuples in the format (encoding_type, decoded_data, confidence) if any
                  encoding/compression is detected; otherwise, an empty list.
        """
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
        # Compressed/Encrypted detection based on entropy
        if entropy > 7.5:
            results.append(('Compressed', None, 0.7))
        if 7.8 <= entropy <= 8.0:
            results.append(('Encrypted', None, 0.8))
        return results if results else []

    def is_printable(self, data):
        """
        Determine if the given byte data represents printable text.

        Attempts to decode the data as UTF-8 and then checks if every character in the resulting string
        is in Python's set of printable characters.

        Parameters:
            data (bytes): The data to test for printability.
            
        Returns:
            bool: True if the data decodes to a string that consists solely of printable characters; False otherwise.
        """
        try:
            text = data.decode('utf-8')
            return all(char in string.printable for char in text)
        except:
            return False
