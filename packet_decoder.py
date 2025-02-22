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
    """
    The PacketDecoder class performs comprehensive decoding and analysis of network packets.
    It leverages a ProtocolDecoder to extract protocol-specific details and an EncodingDetector
    to assess and detect various text encodings present in packet payloads.
    
    The class provides methods to decode an entire packet as well as to perform in-depth
    analysis on the packet payload, including calculating entropy, attempting multiple text decodings,
    detecting common encoding schemes, and identifying file signatures based on magic numbers.
    
    Attributes:
        protocol_decoder (ProtocolDecoder): Instance used to decode protocol layers of a packet.
        encoding_detector (EncodingDetector): Instance used to detect and analyze payload encodings.
    """

    def __init__(self):
        """
        Initialize a new PacketDecoder instance by creating instances of ProtocolDecoder and EncodingDetector.
        """
        self.protocol_decoder = ProtocolDecoder()
        self.encoding_detector = EncodingDetector()

    def decode_packet(self, packet):
        """
        Perform complete decoding and analysis of a network packet.

        This method first uses the protocol_decoder to extract basic protocol information.
        If the packet contains a 'Raw' layer, it extracts the payload and performs comprehensive
        payload analysis using the analyze_payload method. The resulting decoded information,
        including protocol and payload details, is returned as a dictionary.
        
        Parameters:
            packet: The network packet to be decoded.
            
        Returns:
            dict: A dictionary containing decoded information from various layers of the packet.
        """
        # Get basic protocol decoding
        decoded = self.protocol_decoder.decode_packet(packet)
        
        # Add payload analysis if Raw layer exists
        if packet.haslayer('Raw'):
            payload = bytes(packet[scapy.Raw].load)
            decoded['payload_analysis'] = self.analyze_payload(payload)
        return decoded

    def analyze_payload(self, payload):
        """
        Perform comprehensive analysis of a packet payload.

        This method creates a dictionary containing:
          - The length and hexadecimal representation of the payload.
          - The Shannon entropy of the payload.
          - Attempts to decode the payload as UTF-8 and ASCII text.
          - Detection of common encodings (e.g., Base64, Hex) via the encoding_detector.
          - Identification of file signatures based on known magic numbers.
          
        Detected encodings are added along with a confidence score and, if available, both hexadecimal
        and UTF-8 representations of the decoded data.
        
        Parameters:
            payload (bytes): The raw payload data from a network packet.
            
        Returns:
            dict: A dictionary containing detailed analysis of the payload.
        """
        analysis = {
            'length': len(payload),
            'hex': payload.hex(),
            'entropy': self.encoding_detector.calculate_entropy(payload)
        }
        
        # Try to decode as text using UTF-8, falling back to ASCII if necessary.
        try:
            analysis['utf8'] = payload.decode('utf-8')
        except:
            try:
                analysis['ascii'] = payload.decode('ascii', errors='replace')
            except:
                pass
        
        # Detect encodings using the EncodingDetector.
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
        
        # Attempt to identify file signatures based on magic numbers.
        file_type = self.identify_file_signature(payload)
        if file_type:
            analysis['file_type'] = file_type
        
        return analysis

    def identify_file_signature(self, data):
        """
        Identify the file type of the given data based on its magic number (file signature).

        The method checks the start of the data against a dictionary of known signatures.
        If a match is found, the corresponding file type is returned.
        
        Parameters:
            data (bytes): The data to analyze for file signatures.
            
        Returns:
            str or None: The identified file type if a signature matches, otherwise None.
        """
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
