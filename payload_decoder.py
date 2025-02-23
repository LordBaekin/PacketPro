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
    """
    The PayloadDecoder class performs comprehensive analysis of a packet's payload.
    It generates a hex dump with metadata, detects file types using magic numbers,
    analyzes common data patterns (e.g., numbers, strings, repeating patterns, structured data),
    and performs text and encoding analysis.
    
    The analysis includes:
      - Creating a formatted hex dump.
      - Attempting to decode numeric and text representations from data chunks.
      - Identifying file types based on known signatures.
      - Detecting and analyzing numeric sequences and string sequences.
      - Finding repeating patterns and potential structured data.
      - Analyzing text representations using various encodings.
      - Calculating the Shannon entropy of the data.
      - Analyzing possible encodings (e.g., Base64, hex, URL).
      - Analyzing overall data structure patterns.
    
    Attributes:
        known_signatures (dict): Mapping of known file signature bytes to file type names.
        data_patterns (dict): Mapping of pattern names to struct.Struct objects for numeric decoding.
    """

    def __init__(self):
        """
        Initialize a new PayloadDecoder instance with predefined known signatures
        and data patterns for numeric decoding.
        """
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
        """
        Perform comprehensive analysis of the provided payload data.

        The analysis includes generating a hex dump, detecting file type,
        analyzing numeric and string data patterns, analyzing text representations,
        computing entropy, performing encoding analysis, and analyzing overall data structure.

        Parameters:
            data (bytes): The raw payload data from a packet.
        
        Returns:
            dict: A dictionary containing the results of the payload analysis.
                  Keys include 'length', 'hex_dump', 'file_type', 'data_analysis',
                  'text_analysis', 'entropy', 'encoding_analysis', 'structure_analysis',
                  'numeric_values', and 'string_sequences'.
        """
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
    
        # --- NEW SECTION: Inject Numeric and String Sequences ---
        # From data_analysis, get the numeric sequences (under 'numbers') and convert to a dictionary.
        numeric_values = {}
        for seq in result['data_analysis'].get('numbers', []):
            # Composite key: e.g., "float32_le@57"
            key = f"{seq['type']}@{seq['offset']}"
            numeric_values[key] = seq['value']
        result['numeric_values'] = numeric_values

        # Also, pass along the string sequences.
        result['string_sequences'] = result['data_analysis'].get('strings', [])
        # --- End NEW SECTION ---
    
        return result



    def create_hex_dump(self, data: bytes) -> list:
        """
        Returns a list of dictionaries representing a formatted hex dump of the given data,
        styled similarly to Wireshark. Each dictionary contains:
          - 'offset': The starting byte offset for the line.
          - 'hex': A string of 16 hex bytes (split into two groups of 8 with extra space in between).
          - 'ascii': The corresponding ASCII representation (non-printable characters replaced by '.').
          - 'decoded': Any decoded interpretations from try_decode_chunk.
        """
        bytes_per_line = 16
        group_size = 8
        dump = []
    
        for offset in range(0, len(data), bytes_per_line):
            chunk = data[offset:offset+bytes_per_line]
            hex_bytes = [f"{b:02X}" for b in chunk]
            first_group = " ".join(hex_bytes[:group_size])
            second_group = " ".join(hex_bytes[group_size:])
        
            # Pad the groups if the chunk is shorter than 16 bytes.
            if len(chunk) < bytes_per_line:
                if len(chunk) <= group_size:
                    first_group = first_group.ljust(group_size * 3 - 1)
                    second_group = ""
                else:
                    second_group = second_group.ljust((bytes_per_line - group_size) * 3 - 1)
        
            hex_section = f"{first_group}  {second_group}".strip()
            ascii_section = "".join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        
            dump.append({
                'offset': offset,
                'hex': hex_section,
                'ascii': ascii_section,
                'decoded': self.try_decode_chunk(chunk)
            })
    
        return dump




    def try_decode_chunk(self, chunk: bytes) -> dict:
        """
        Attempt to decode a chunk of data using various numeric and text interpretations.

        This method tries to decode the given chunk using multiple struct patterns defined in data_patterns,
        and also attempts to decode the chunk as text using several encodings. Numeric values that fall within a
        reasonable range are included, and printable text is added as well.

        Parameters:
            chunk (bytes): A segment of data to decode.
            
        Returns:
            dict: A dictionary containing decoded values with keys indicating the interpretation (e.g., 'float32_le',
                  'utf-8', etc.).
        """
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
                if any(32 <= ord(c) <= 126 for c in text):  # Contains printable characters
                    decoded[encoding] = text
            except:
                pass
        return decoded

    def detect_file_type(self, data: bytes) -> str:
        """
        Detect the file type of the data based on known file signature (magic numbers)
        and additional content-based heuristics.

        Checks if the data starts with any known signature, and if not, checks for XML or JSON structure,
        or considers it binary if applicable.

        Parameters:
            data (bytes): The raw data to analyze.
            
        Returns:
            str: The identified file type (e.g., 'JPEG', 'PNG', etc.) or 'UNKNOWN' if no match is found.
        """
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
        """
        Analyze common data patterns present in the data.

        The analysis includes:
          - Extracting sequences of numbers (numeric patterns).
          - Extracting sequences of printable strings.
          - Finding repeating byte patterns.
          - Detecting potential structured data formats.

        Parameters:
            data (bytes): The raw data to analyze.
            
        Returns:
            dict: A dictionary containing sub-results for 'numbers', 'strings', 'repeating', and 'structured' patterns.
        """
        patterns = {
            'numbers': self.find_number_sequences(data),
            'strings': self.find_string_sequences(data),
            'repeating': self.find_repeating_patterns(data),
            'structured': self.detect_structured_data(data)
        }
        return patterns

    def find_number_sequences(self, data: bytes) -> list:
        """
        Find sequences of numeric values in the data using various numeric formats.

        Iterates over the data and attempts to unpack numbers using the numeric patterns in data_patterns.
        Valid numbers (within a reasonable range for floats, or any integers) are collected along with their offset
        and the format used.

        Parameters:
            data (bytes): The raw data to analyze.
            
        Returns:
            list: A list of dictionaries, each containing an 'offset', 'type', and 'value' for a numeric sequence.
        """
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
        """
        Find sequences of printable characters in the data.

        Iterates byte by byte to collect sequences of printable ASCII characters.
        A sequence must be at least 4 characters long to be considered valid.

        Parameters:
            data (bytes): The raw data to analyze.
            
        Returns:
            list: A list of dictionaries, each containing the starting 'offset', the extracted 'string',
                  and its 'length'.
        """
        strings = []
        current_string = []
        current_offset = None
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # Printable ASCII
                if current_string == []:
                    current_offset = i
                current_string.append(chr(byte))
            else:
                if len(current_string) >= 4:  # Minimum string length requirement
                    strings.append({
                        'offset': current_offset,
                        'string': ''.join(current_string),
                        'length': len(current_string)
                    })
                current_string = []
                current_offset = None
        # Capture any string remaining at the end of the data
        if len(current_string) >= 4:
            strings.append({
                'offset': current_offset,
                'string': ''.join(current_string),
                'length': len(current_string)
            })
        return strings

    def find_repeating_patterns(self, data: bytes) -> list:
        """
        Identify repeating byte patterns within the data.

        Searches for patterns with lengths between 2 and 8 bytes that repeat at least 3 times consecutively.
        If such a pattern is found, it records the starting offset, the hexadecimal representation of the pattern,
        the length of the pattern, and the number of repetitions.

        Parameters:
            data (bytes): The raw data to analyze.
            
        Returns:
            list: A list of dictionaries, each representing a repeating pattern found.
        """
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
        """
        Detect potential structured data formats within the data.

        Looks for common field separators and potential record sizes in the data to determine
        if the data exhibits a structured format.

        Parameters:
            data (bytes): The raw data to analyze.
            
        Returns:
            dict: A dictionary containing potential headers, field separators, and record size information.
        """
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
        """
        Analyze text representations within the data using various encodings.

        Attempts to decode the data using common text encodings such as UTF-8, ASCII, UTF-16,
        UTF-32, and ISO-8859-1. For each successful decoding that results in printable characters,
        it calculates the printable ratio (the fraction of characters that are printable).

        Parameters:
            data (bytes): The raw data to analyze.
            
        Returns:
            dict: A dictionary mapping each encoding to a dictionary with the decoded text and its printable ratio.
        """
        text_analysis = {}
        
        # Try different encodings
        encodings = ['utf-8', 'ascii', 'utf-16', 'utf-32', 'iso-8859-1']
        for encoding in encodings:
            try:
                decoded = data.decode(encoding)
                if any(32 <= ord(c) <= 126 for c in decoded):  # Contains printable characters
                    text_analysis[encoding] = {
                        'text': decoded,
                        'printable_ratio': sum(32 <= ord(c) <= 126 for c in decoded) / len(decoded)
                    }
            except:
                continue
        return text_analysis

    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate the Shannon entropy of the given data.

        Entropy is a measure of randomness in the data. This method computes the entropy
        by iterating through each byte value, calculating its probability, and summing the weighted
        negative logarithm of the probabilities.

        Parameters:
            data (bytes): The raw data for which to calculate entropy.
            
        Returns:
            float: The Shannon entropy of the data.
        """
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    def analyze_encodings(self, data: bytes) -> dict:
        """
        Analyze possible encodings present in the data.

        Attempts to decode the data as Base64, hexadecimal, and URL-encoded text.
        For each encoding attempt, it captures the decoded output and its hexadecimal representation if applicable.

        Parameters:
            data (bytes): The raw data to analyze.
            
        Returns:
            dict: A dictionary mapping encoding names (e.g., 'base64', 'hex', 'url') to their decoded results.
        """
        encodings = {}
        
        # Try base64 decoding
        try:
            decoded = base64.b64decode(data + b'=' * (-len(data) % 4))
            encodings['base64'] = {
                'decoded': decoded.hex(),
                'text': self.try_decode_chunk(decoded)
            }
        except:
            pass
        # Try hex decoding
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
        """
        Analyze structural patterns within the data.

        This method checks for patterns such as byte alignment, boundary markers, and consistent record sizes.
        It identifies potential field separators and records if the data appears to be structured.

        Parameters:
            data (bytes): The raw data to analyze.
            
        Returns:
            dict: A dictionary containing detected structural patterns, including 'patterns', 'alignment', and 'boundaries'.
        """
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

    def analyze_text(self, data: bytes) -> dict:
        """
        Analyze text representations in the data using various encodings.

        Attempts to decode the data using several common encodings (e.g., UTF-8, ASCII, UTF-16, UTF-32, ISO-8859-1)
        and calculates the printable ratio for each successful decoding.

        Parameters:
            data (bytes): The raw data to analyze.
            
        Returns:
            dict: A dictionary mapping each encoding to a sub-dictionary containing the decoded text and the printable ratio.
        """
        text_analysis = {}
        
        # Try different encodings
        encodings = ['utf-8', 'ascii', 'utf-16', 'utf-32', 'iso-8859-1']
        for encoding in encodings:
            try:
                decoded = data.decode(encoding)
                if any(32 <= ord(c) <= 126 for c in decoded):  # Contains printable characters
                    text_analysis[encoding] = {
                        'text': decoded,
                        'printable_ratio': sum(32 <= ord(c) <= 126 for c in decoded) / len(decoded)
                    }
            except:
                continue
        return text_analysis

    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate the Shannon entropy of the data.

        Measures the randomness or unpredictability of the data by summing the negative probabilities
        of each byte value multiplied by the logarithm of that probability.

        Parameters:
            data (bytes): The raw data.
            
        Returns:
            float: The calculated entropy.
        """
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    def analyze_encodings(self, data: bytes) -> dict:
        """
        Analyze possible encodings in the data.

        Attempts to decode the data using Base64, hexadecimal, and URL encoding. For each attempt,
        captures the decoded output and its hexadecimal representation if applicable.

        Parameters:
            data (bytes): The raw data.
            
        Returns:
            dict: A dictionary mapping encoding types (e.g., 'base64', 'hex', 'url') to their decoded results.
        """
        encodings = {}
        
        # Try base64 decoding
        try:
            decoded = base64.b64decode(data + b'=' * (-len(data) % 4))
            encodings['base64'] = {
                'decoded': decoded.hex(),
                'text': self.try_decode_chunk(decoded)
            }
        except:
            pass
        # Try hex decoding
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
        """
        Analyze structural patterns within the data.

        Checks for alignment patterns, boundary markers, and consistent record sizes.
        This can help determine if the data is structured (e.g., CSV, fixed record binary).

        Parameters:
            data (bytes): The raw data.
            
        Returns:
            dict: A dictionary containing structural analysis results including 'patterns', 'alignment', and 'boundaries'.
        """
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

    def analyze_text(self, data: bytes) -> dict:
        """
        Analyze text representations in the data using various encodings.

        Attempts to decode the data using common text encodings and calculates the ratio of printable characters.
        This can help determine the presence of human-readable text.

        Parameters:
            data (bytes): The raw data.
            
        Returns:
            dict: A dictionary mapping each attempted encoding to its decoded text and printable ratio.
        """
        text_analysis = {}
        
        # Try different encodings
        encodings = ['utf-8', 'ascii', 'utf-16', 'utf-32', 'iso-8859-1']
        for encoding in encodings:
            try:
                decoded = data.decode(encoding)
                if any(32 <= ord(c) <= 126 for c in decoded):  # Contains printable characters
                    text_analysis[encoding] = {
                        'text': decoded,
                        'printable_ratio': sum(32 <= ord(c) <= 126 for c in decoded) / len(decoded)
                    }
            except:
                continue
        return text_analysis

    def try_decode_chunk(self, chunk: bytes) -> dict:
        """
        Attempt to decode a chunk of data using various numeric and text interpretations.

        Tries to decode the chunk using different numeric formats defined in data_patterns, and attempts text decodings
        using several encodings. Returns a dictionary with the decoded values.
        
        Parameters:
            chunk (bytes): A segment of data to decode.
            
        Returns:
            dict: A dictionary containing decoded interpretations of the chunk.
        """
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
                if any(32 <= ord(c) <= 126 for c in text):  # Contains printable characters
                    decoded[encoding] = text
            except:
                pass
        return decoded

    def detect_file_type(self, data: bytes) -> str:
        """
        Detect the file type of the data based on known file signatures and content analysis.

        Checks if the data starts with any known magic numbers (file signatures). If not, it checks for XML or JSON
        structure, or considers it binary if a variety of byte values are present.

        Parameters:
            data (bytes): The raw data.
            
        Returns:
            str: The identified file type (e.g., 'JPEG', 'PNG', etc.) or 'UNKNOWN' if no match is found.
        """
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

    def format_hex_ascii_dump(self, data: bytes) -> str:
        hex_dump = self.create_hex_dump(data)
        lines = []
        header = "Offset  Hexadecimal                                              ASCII"
        lines.append(header)
        lines.append("-" * len(header))
        for line in hex_dump:
            offset = f"{line['offset']:04X}"
            hex_str = line['hex'].ljust(48)
            ascii_str = line['ascii']
            lines.append(f"{offset}  {hex_str}  {ascii_str}")
        return "\n".join(lines)
