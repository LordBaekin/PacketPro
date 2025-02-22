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

class LivePacketScanner:
    """
    The LivePacketScanner class provides functionality to capture network packets live
    using Scapy. It runs the packet capture in a separate daemon thread, supports starting
    and stopping the capture process, and allows retrieval of available network interfaces.
    
    Attributes:
        packet_callback (callable): Function to be called with each captured packet.
        interface (str or None): The network interface on which to capture packets.
        is_running (threading.Event): Event flag indicating whether packet capture is active.
        capture_thread (threading.Thread or None): Thread in which packet capture is running.
    """

    def __init__(self, packet_callback, interface=None):
        """
        Initialize a new LivePacketScanner instance.

        Parameters:
            packet_callback (callable): Function to call with each captured packet.
            interface (str, optional): The network interface to capture on. Defaults to None.
        """
        self.packet_callback = packet_callback
        self.interface = interface
        self.is_running = threading.Event()
        self.capture_thread = None

    def start_capture(self):
        """
        Start the live packet capture.

        If a capture thread is already running, this method does nothing. Otherwise,
        it sets the is_running event, creates a new daemon thread that runs the packet
        capture loop, and starts the thread.
        """
        if self.capture_thread and self.capture_thread.is_alive():
            return

        self.is_running.set()
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_capture(self):
        """
        Stop the live packet capture.

        This method clears the is_running event, causing the capture loop to exit.
        """
        self.is_running.clear()

    def _capture_packets(self):
        """
        Internal method that captures packets in a loop.

        This method defines a packet_handler function that is called for each captured packet.
        If the is_running event is set, it calls the packet_callback with the packet.
        The packet capture is performed using Scapy's sniff function, with storage disabled,
        and the loop stops when is_running is cleared.
        """
        def packet_handler(packet):
            if self.is_running.is_set():
                try:
                    self.packet_callback(packet)
                except Exception as e:
                    print(f"Packet callback error: {e}")

        try:
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=False,
                stop_filter=lambda _: not self.is_running.is_set()
            )
        except Exception as e:
            print(f"Capture error: {e}")

    def get_available_interfaces(self):
        """
        Retrieve a dictionary of available network interfaces.

        On Windows, uses Scapy's get_windows_if_list to obtain interfaces and their descriptions.
        On other systems, uses scapy.get_if_list. Returns a dictionary mapping interface names to display names.

        Returns:
            dict: Dictionary with interface names as keys and display names as values.
                  Returns an empty dictionary if an error occurs.
        """
        try:
            interfaces = {}
            if os.name == "nt":  # Windows
                from scapy.arch.windows import get_windows_if_list
                for iface in get_windows_if_list():
                    display_name = iface.get('description', iface.get('name', ''))
                    if display_name:
                        interfaces[iface['name']] = display_name
            else:  # Linux/Unix/MacOS
                for iface in scapy.get_if_list():
                    interfaces[iface] = iface
            return interfaces
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return {}
