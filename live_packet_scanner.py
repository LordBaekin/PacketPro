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
   def __init__(self, packet_callback, interface=None):  
      self.packet_callback = packet_callback  
      self.interface = interface  
      self.is_running = threading.Event()  
      self.capture_thread = None  
   
   def start_capture(self):  
      if self.capture_thread and self.capture_thread.is_alive():  
        return  
   
      self.is_running.set()  
      self.capture_thread = threading.Thread(target=self._capture_packets)  
      self.capture_thread.daemon = True  
      self.capture_thread.start()  
   
   def stop_capture(self):  
      self.is_running.clear()  
   
   def _capture_packets(self):  
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