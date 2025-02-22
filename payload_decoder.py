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

class PayloadDecoder:
    def __init__(self):
        self.known_signatures = {
            b'\x1f\x8b\x08': 'GZIP',
            b'\x42\x5a\x68': 'BZIP2',
            b'\x50\x4b\x03\x04': 'ZIP',
            b'\x00\x00\x00\x14\x66\x74\x79\x70': 'MP4',
            b'\x47\x49\x46\x38': 'GIF',
            b'\x89\x50\x4e\x47': 'PNG',
            b'\xff\xd8\xff': 'JPEG',
            b'\x25\x50\x44\x46': 'PDF',
            b'\x7f\x45\x4c\x46': 'ELF',
            b'\x4d\x5a': 'EXE',
            b'\x23\x21': 'SHELL SCRIPT',
            b'\x43\x57\x53': 'SWF',
            b'\x46\x4c\x56': 'FLV',
            b'\x52\x49\x46\x46': 'RIFF',
        }
        
        self.data_patterns = {
            'float32_le': struct.Struct('<f'),
            'float32_be': struct.Struct('>f'),
            'float64_le': struct.Struct('<d'),
            'float64_be': struct.Struct('>d'),
            'int32_le': struct.Struct('<i'),
            'int32_be': struct.Struct('>i'),
            'uint32_le': struct.Struct('<I'),
            'uint32_be': struct.Struct('>I'),
            'int16_le': struct.Struct('<h'),
            'int16_be': struct.Struct('>h'),
            'uint16_le': struct.Struct('<H'),
            'uint16_be': struct.Struct('>H'),
        }

    def analyze_payload(self, data: bytes) -> dict:
        """Comprehensive payload analysis"""
        result = {
            'length': len(data),
            'hex_dump': self.create_hex_dump(data),
            'file_type': self.detect_file_type(data),
            'data_analysis': self.analyze_data_patterns(data),
            'text_analysis': self.analyze_text(data),
            'entropy': self.calculate_entropy(data),
            'encoding_analysis': self.analyze_encodings(data),
            'structure_analysis': self.analyze_structure(data)
        }
        return result

    def create_hex_dump(self, data: bytes) -> list:
        """Create formatted hex dump with metadata"""
        hex_dump = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_line = {
                'offset': i,
                'hex': ' '.join(f'{b:02X}' for b in chunk),
                'ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk),
                'decoded': self.try_decode_chunk(chunk)
            }
            hex_dump.append(hex_line)
        return hex_dump

    def try_decode_chunk(self, chunk: bytes) -> dict:
        """Try to decode each chunk in various ways"""
        decoded = {}
        
        # Try different numeric interpretations
        for name, pattern in self.data_patterns.items():
            if len(chunk) >= pattern.size:
                try:
                    value = pattern.unpack(chunk[:pattern.size])[0]
                    if isinstance(value, float):
                        if -1e10 < value < 1e10:  # Reasonable range check
                            decoded[name] = value
                    else:
                        decoded[name] = value
                except:
                    pass
        # Try text decodings
        encodings = ['utf-8', 'ascii', 'utf-16', 'utf-32']
        for encoding in encodings:
            try:
                text = chunk.decode(encoding)
                if any(32 <= ord(c) <= 126 for c in text):  # Contains printable chars
                    decoded[encoding] = text
            except:
                pass
        return decoded

    def detect_file_type(self, data: bytes) -> str:
        """Detect file type based on signatures and content analysis"""
        # Check for known file signatures
        for signature, filetype in self.known_signatures.items():
            if data.startswith(signature):
                return filetype
        # Additional content-based detection
        if data.startswith(b'<?xml'):
            return 'XML'
        elif data.startswith(b'{') and data.strip().endswith(b'}'):
            try:
                json.loads(data)
                return 'JSON'
            except:
                pass
        elif all(b in range(256) for b in data[:4]) and len(set(data[:4])) > 2:
            return 'BINARY'
            
        return 'UNKNOWN'

    def analyze_data_patterns(self, data: bytes) -> dict:
        """Analyze for common data patterns"""
        patterns = {
            'numbers': self.find_number_sequences(data),
            'strings': self.find_string_sequences(data),
            'repeating': self.find_repeating_patterns(data),
            'structured': self.detect_structured_data(data)
        }
        return patterns

    def find_number_sequences(self, data: bytes) -> list:
        """Find sequences of numbers in different formats"""
        sequences = []
        # Check for different numeric patterns
        for i in range(0, len(data) - 4):
            chunk = data[i:i+4]
            for name, pattern in self.data_patterns.items():
                try:
                    if len(chunk) >= pattern.size:
                        value = pattern.unpack(chunk[:pattern.size])[0]
                        if isinstance(value, float):
                            if -1e10 < value < 1e10:  # Reasonable range
                                sequences.append({
                                    'offset': i,
                                    'type': name,
                                    'value': value
                                })
                        elif isinstance(value, int):
                            sequences.append({
                                'offset': i,
                                'type': name,
                                'value': value
                            })
                except:
                    continue
        return sequences

    def find_string_sequences(self, data: bytes) -> list:
        """Find viable string sequences"""
        strings = []
        current_string = []
        current_offset = None
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # Printable ASCII
                if current_string == []:
                    current_offset = i
                current_string.append(chr(byte))
            else:
                if len(current_string) >= 4:  # Min string length
                    strings.append({
                        'offset': current_offset,
                        'string': ''.join(current_string),
                        'length': len(current_string)
                    })
                current_string = []
                current_offset = None
        # Don't forget last string
        if len(current_string) >= 4:
            strings.append({
                'offset': current_offset,
                'string': ''.join(current_string),
                'length': len(current_string)
            })
        return strings

    def find_repeating_patterns(self, data: bytes) -> list:
        """Find repeating byte patterns"""
        patterns = []
        min_pattern_len = 2
        max_pattern_len = 8
        for pattern_len in range(min_pattern_len, max_pattern_len + 1):
            for i in range(len(data) - pattern_len * 2):
                pattern = data[i:i+pattern_len]
                # Look for at least 3 repetitions
                repeats = 1
                pos = i + pattern_len
                while pos < len(data) - pattern_len and data[pos:pos+pattern_len] == pattern:
                    repeats += 1
                    pos += pattern_len
                
                if repeats >= 3:
                    patterns.append({
                        'offset': i,
                        'pattern': pattern.hex(),
                        'length': pattern_len,
                        'repeats': repeats
                    })
                    i = pos  # Skip past this pattern
        return patterns

    def detect_structured_data(self, data: bytes) -> dict:
        """Detect potential structured data formats"""
        structure = {
            'potential_headers': [],
            'field_separators': [],
            'record_sizes': []
        }
        # Look for common field separators
        separators = [b',', b'|', b'\t', b';']
        for sep in separators:
            count = data.count(sep)
            if count > 1:
                structure['field_separators'].append({
                    'separator': sep.hex(),
                    'count': count
                })
        # Look for potential record sizes
        if len(data) >= 8:
            for size in range(4, 17):  # Common record sizes
                if len(data) % size == 0:
                    # Verify some consistency in the structure
                    consistency = 0
                    for i in range(0, len(data) - size, size):
                        if data[i] == data[i + size]:
                            consistency += 1
                    if consistency >= 2:
                        structure['record_sizes'].append({
                            'size': size,
                            'count': len(data) // size,
                            'consistency': consistency
                        })
        return structure

    def analyze_text(self, data: bytes) -> dict:
        """Analyze text representations"""
        text_analysis = {}
        
        # Try different encodings
        encodings = ['utf-8', 'ascii', 'utf-16', 'utf-32', 'iso-8859-1']
        for encoding in encodings:
            try:
                decoded = data.decode(encoding)
                if any(32 <= ord(c) <= 126 for c in decoded):  # Contains printable chars
                    text_analysis[encoding] = {
                        'text': decoded,
                        'printable_ratio': sum(32 <= ord(c) <= 126 for c in decoded) / len(decoded)
                    }
            except:
                continue
        return text_analysis

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of the data"""
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy
    def analyze_encodings(self, data: bytes) -> dict:
        """Analyze possible encodings"""
        encodings = {}
        
        # Try base64
        try:
            decoded = base64.b64decode(data + b'=' * (-len(data) % 4))
            encodings['base64'] = {
                'decoded': decoded.hex(),
                'text': self.try_decode_chunk(decoded)
            }
        except:
            pass
        # Try hex
        try:
            hex_str = data.hex()
            if all(c in '0123456789abcdefABCDEF' for c in hex_str):
                encodings['hex'] = {
                    'text': hex_str,
                    'decoded': bytes.fromhex(hex_str).hex()
                }
        except:
            pass
        # Try URL encoding
        try:
            from urllib.parse import unquote
            decoded = unquote(data.decode())
            if '%' in decoded:
                encodings['url'] = {
                    'decoded': decoded
                }
        except:
            pass
        return encodings

    def analyze_structure(self, data: bytes) -> dict:
        """Analyze data structure patterns"""
        structure = {
            'patterns': {},
            'alignment': {},
            'boundaries': []
        }
        # Check byte alignment patterns
        alignments = [2, 4, 8]
        for align in alignments:
            aligned_positions = []
            for i in range(0, len(data) - align, align):
                chunk = data[i:i+align]
                if all(x == chunk[0] for x in chunk):
                    aligned_positions.append(i)
            if aligned_positions:
                structure['alignment'][align] = aligned_positions
        # Look for boundary markers
        common_boundaries = [b'\x00\x00', b'\xff\xff', b'\r\n', b'\n\n']
        for boundary in common_boundaries:
            positions = []
            pos = -1
            while True:
                pos = data.find(boundary, pos + 1)
                if pos == -1:
                    break
                positions.append(pos)
            if positions:
                structure['boundaries'].append({
                    'marker': boundary.hex(),
                    'positions': positions
                })
        return structure