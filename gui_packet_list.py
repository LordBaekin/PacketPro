# gui_packet_list.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import re
import scapy.all as scapy
from datetime import datetime

class PacketListMixin:
    def add_packet_to_list(self, packet, decoded_packet=None):
        """
        Adds a single packet to the packet list display.

        This method decodes the packet (if not already provided) to extract timestamp, source, destination,
        protocol, and length information. It then inserts this information into the packet_tree widget.
        
        Parameters:
            packet: The packet object captured or loaded.
            decoded_packet (optional): The pre-decoded packet information. If not provided, it will be decoded.
        """
        try:
            if decoded_packet is None:
                decoded_packet = self.packet_decoder.decode_packet(packet)
            time_val = decoded_packet['timestamp']['formatted']
            if 'layer3' in decoded_packet:
                src = decoded_packet['layer3'].get('src_ip', 'Unknown')
                dst = decoded_packet['layer3'].get('dst_ip', 'Unknown')
            else:
                src = "Unknown"
                dst = "Unknown"
            if decoded_packet.get('layer7', {}).get('protocol'):
                proto = decoded_packet['layer7']['protocol']
            elif decoded_packet.get('layer4', {}).get('type'):
                proto = decoded_packet['layer4']['type']
            else:
                proto = decoded_packet.get('layer3', {}).get('type', 'Unknown')
            length = decoded_packet['raw_data']['length']
            self.packet_tree.insert('', 'end', values=(len(self.packets), time_val, src, dst, proto, length))
            self.packet_tree.yview_moveto(1)
        except Exception as e:
            print(f"Error adding packet to list: {e}")

    def update_packet_list(self):
        """
        Updates the entire packet list display with the current packets.

        This method clears the packet_tree widget and re-inserts each packet's information by decoding
        the packet to extract timestamp, source, destination, protocol, and length data. It also sets the status
        label to show the total number of packets.
        """
        try:
            self.packet_tree.delete(*self.packet_tree.get_children())
            for i, packet in enumerate(self.packets, 1):
                try:
                    decoded = self.packet_decoder.decode_packet(packet)
                    time_val = decoded['timestamp']['formatted']
                    src = decoded.get('layer3', {}).get('src_ip', 'Unknown')
                    dst = decoded.get('layer3', {}).get('dst_ip', 'Unknown')
                    if decoded.get('layer7', {}).get('protocol'):
                        proto = decoded['layer7']['protocol']
                    elif decoded.get('layer4', {}).get('type'):
                        proto = decoded['layer4']['type']
                    else:
                        proto = decoded.get('layer3', {}).get('type', 'Unknown')
                    length = decoded['raw_data']['length']
                    self.packet_tree.insert('', 'end', values=(i, time_val, src, dst, proto, length))
                except Exception as e:
                    print(f"Error processing packet {i}: {e}")
                    self.packet_tree.insert('', 'end', values=(i, "Error", "Error", "Error", "Unknown", "Error"))
            self.status_var.set(f"Showing {len(self.packets)} packets")
        except Exception as e:
            print(f"Error updating packet list: {e}")
            self.status_var.set("Error updating packet list")

    def update_packet_list_with_decoded(self, decoded_packets):
        """
        Updates the packet list using a list of pre-decoded packet data.

        This method clears the packet_tree widget and iterates over the list of packets along with their corresponding
        decoded data. For each packet, it displays the timestamp, source, destination, protocol, and length. If the decoded
        data is not available, it attempts to extract information from the packet directly.
        
        Parameters:
            decoded_packets (list): A list of decoded packet dictionaries corresponding to self.packets.
        """
        self.packet_tree.delete(*self.packet_tree.get_children())
        for i, (packet, decoded) in enumerate(zip(self.packets, decoded_packets), 1):
            try:
                if decoded:
                    time_val = decoded['timestamp']['formatted']
                    src = decoded.get('layer3', {}).get('src_ip', 'Unknown')
                    dst = decoded.get('layer3', {}).get('dst_ip', 'Unknown')
                    proto = decoded.get('layer7', {}).get('protocol', decoded.get('layer4', {}).get('type', 'Unknown'))
                    length = decoded['raw_data']['length']
                else:
                    time_val = datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S.%f')
                    src = packet[scapy.IP].src if scapy.IP in packet else "Unknown"
                    dst = packet[scapy.IP].dst if scapy.IP in packet else "Unknown"
                    proto = "TCP" if scapy.TCP in packet else "UDP" if scapy.UDP in packet else "Unknown"
                    length = len(packet)
                self.packet_tree.insert('', 'end', values=(i, time_val, src, dst, proto, length))
            except Exception as e:
                print(f"Error updating packet list: {e}")

    def on_packet_select(self, event):
        """
        Event handler for when a packet is selected in the packet list.

        This method retrieves the selected packet based on the user's selection in the packet_tree widget, decodes it,
        and then updates the packet details pane, payload analysis pane, and protocol analysis tabs accordingly.
        
        Parameters:
            event: The event object generated by the selection.
        """
        selection = self.packet_tree.selection()
        if not selection:
            return
        item = self.packet_tree.selection()[0]
        packet_num = int(self.packet_tree.item(item)['values'][0]) - 1
        packet = self.packets[packet_num]
        decoded_packet = self.packet_decoder.decode_packet(packet)
        self.update_packet_details(decoded_packet)
        self.update_payload_analysis(decoded_packet)
        self.update_protocol_tabs(decoded_packet)

    def update_packet_details(self, decoded_packet):
        """
        Updates the packet details pane with information from the decoded packet.

        The details pane is cleared and then populated with the timestamp followed by detailed information for each layer
        (layer2, layer3, layer4, and layer7) if available.
        
        Parameters:
            decoded_packet (dict): The dictionary containing decoded information for the selected packet.
        """
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "Timestamp:\n")
        self.format_dict_output(self.details_text, decoded_packet['timestamp'], indent=2)
        self.details_text.insert(tk.END, "\n")
        for layer in ['layer2', 'layer3', 'layer4', 'layer7']:
            if layer in decoded_packet:
                self.details_text.insert(tk.END, f"{layer.upper()}:\n")
                self.format_dict_output(self.details_text, decoded_packet[layer], indent=2)
                self.details_text.insert(tk.END, "\n")

    def update_protocol_tabs(self, decoded_packet):
        """
        Updates the protocol-specific analysis tabs based on the decoded packet.

        This method clears and repopulates the protocol overview, HTTP, DNS, and TLS/SSL tabs with relevant data.
        For each tab, it checks for the presence of specific analysis data and displays it accordingly.
        
        Parameters:
            decoded_packet (dict): The dictionary containing decoded protocol analysis data for the selected packet.
        """
        self.protocol_text.delete(1.0, tk.END)
        self.protocol_text.insert(tk.END, "Detected Protocols:\n")
        for proto in decoded_packet['protocols']:
            self.protocol_text.insert(tk.END, f"- {proto}\n")
        self.http_text.delete(1.0, tk.END)
        if 'http_analysis' in decoded_packet:
            self.format_dict_output(self.http_text, decoded_packet['http_analysis'])
        else:
            self.http_text.insert(tk.END, "No HTTP data detected")
        self.dns_text.delete(1.0, tk.END)
        if 'dns_analysis' in decoded_packet:
            self.format_dict_output(self.dns_text, decoded_packet['dns_analysis'])
        else:
            self.dns_text.insert(tk.END, "No DNS data detected")
        self.tls_text.delete(1.0, tk.END)
        if 'tls_analysis' in decoded_packet:
            self.format_dict_output(self.tls_text, decoded_packet['tls_analysis'])
        else:
            self.tls_text.insert(tk.END, "No TLS/SSL data detected")
