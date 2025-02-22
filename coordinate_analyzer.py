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

class CoordinateAnalyzer:
    def __init__(self):
        self.formats = {
            'float32': '<fff',  # Little-endian, 3 floats
           
        }
        self.csv_data = None
    def load_csv(self, filename):
        try:
            self.csv_data = pd.read_csv(filename)
            return True
        except Exception as e:
            raise Exception(f"Failed to load CSV: {str(e)}")
    def find_coordinates(self, payload, timestamp):
        results = []
        for format_name, format_str in self.formats.items():
            size = struct.calcsize(format_str)
            for i in range(0, len(payload) - size + 1):
                try:
                    x, y, z = struct.unpack(format_str, payload[i:i+size])
                    if self.is_valid_coordinate(x, y, z):
                        results.append({
                            'offset': i,
                            'format': format_name,
                            'x': x, 'y': y, 'z': z,
                            'timestamp': timestamp
                        })
                except:
                    continue
        return results
    def is_valid_coordinate(self, x, y, z):
        return all([
            isinstance(x, (int, float)),
            isinstance(y, (int, float)),
            isinstance(z, (int, float)),
            abs(x) < 1e6,
            abs(y) < 1e6,
            abs(z) < 1e6
        ])