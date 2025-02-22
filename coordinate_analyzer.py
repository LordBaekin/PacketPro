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
    """
    The CoordinateAnalyzer class is responsible for loading coordinate data from a CSV file
    and for analyzing a payload to extract potential coordinate values using different binary formats.
    
    It currently supports one format ('float32') for extracting three floating-point numbers (x, y, z)
    from a payload. The class also provides validation to ensure that the extracted coordinates are within
    a reasonable range.
    
    Attributes:
        formats (dict): A dictionary mapping format names to struct format strings.
        csv_data (pandas.DataFrame or None): DataFrame containing loaded CSV data, or None if not loaded.
    """

    def __init__(self):
        """
        Initialize a new CoordinateAnalyzer instance with a predefined format.
        
        The default supported format is 'float32', which expects three little-endian floats.
        """
        self.formats = {
            'float32': '<fff',  # Little-endian, 3 floats
        }
        self.csv_data = None

    def load_csv(self, filename):
        """
        Load coordinate data from a CSV file.
        
        This method attempts to read the CSV file using pandas and stores the result
        in the csv_data attribute.
        
        Parameters:
            filename (str): The path to the CSV file to load.
        
        Returns:
            bool: True if the CSV is loaded successfully.
        
        Raises:
            Exception: If there is an error loading the CSV file.
        """
        try:
            self.csv_data = pd.read_csv(filename)
            return True
        except Exception as e:
            raise Exception(f"Failed to load CSV: {str(e)}")

    def find_coordinates(self, payload, timestamp):
        """
        Analyze the given payload to extract potential coordinate data.
        
        For each supported format, this method iterates over the payload, attempts to unpack
        coordinate values (x, y, z) using the struct format, and validates the extracted coordinates.
        If valid, a dictionary containing the coordinate data, the offset, format used, and timestamp
        is appended to the results list.
        
        Parameters:
            payload (bytes): The raw payload data to analyze.
            timestamp (float): The timestamp associated with the payload.
        
        Returns:
            list: A list of dictionaries, each representing a valid coordinate extraction.
        """
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
        """
        Validate extracted coordinate values.
        
        This method checks that x, y, and z are numbers (int or float) and that their absolute values
        are less than 1e6. This helps filter out any values that are clearly out of the expected range.
        
        Parameters:
            x (float or int): The x-coordinate.
            y (float or int): The y-coordinate.
            z (float or int): The z-coordinate.
        
        Returns:
            bool: True if all coordinates are valid; False otherwise.
        """
        return all([
            isinstance(x, (int, float)),
            isinstance(y, (int, float)),
            isinstance(z, (int, float)),
            abs(x) < 1e6,
            abs(y) < 1e6,
            abs(z) < 1e6
        ])
