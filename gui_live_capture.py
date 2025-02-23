# gui_live_capture.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import scapy.all as scapy


class LiveCaptureMixin:
    def setup_live_capture_controls(self):
        """
        Sets up the live capture controls in the GUI.

        This method creates and configures a label frame titled "Live Capture" that includes:
          - A combobox to select a network interface (populated using the available interfaces).
          - A start/stop capture button that toggles live packet capturing.
          - A label to display the current packet count.
        """
        capture_frame = ttk.LabelFrame(self.root, text="Live Capture")
        capture_frame.pack(fill='x', padx=15, pady=2)
        self.interface_var = tk.StringVar()
        self.interface_map = self.scanner.get_available_interfaces()
        self.interface_name_to_guid = {v: k for k, v in self.interface_map.items()}
        interface_names = list(self.interface_map.values())
        if interface_names:
            self.interface_var.set(interface_names[0])
        ttk.Label(capture_frame, text="Interface:").pack(side='left', padx=2)
        interface_menu = ttk.Combobox(capture_frame, textvariable=self.interface_var, values=interface_names)
        interface_menu.pack(side='left', padx=2)
        self.capture_button = ttk.Button(capture_frame, text="Start Capture", command=self.toggle_capture)
        self.capture_button.pack(side='left', padx=2)
        self.packet_count_var = tk.StringVar(value="Packets: 0")
        ttk.Label(capture_frame, textvariable=self.packet_count_var).pack(side='left', padx=2)

    def toggle_capture(self):
        """
        Toggles the live packet capture on or off.

        When starting capture, it verifies that a valid network interface is selected, sets the interface for the scanner,
        and starts capturing packets. It updates the capture button text and status message accordingly.
        When stopping capture, it stops the live capture, resets the button text, and updates the status message.
        """
        if not self.is_scanning:
            selected_name = self.interface_var.get()
            if selected_name in self.interface_name_to_guid:
                self.scanner.interface = self.interface_name_to_guid[selected_name]
                self.scanner.start_capture()
                self.is_scanning = True
                self.capture_button.configure(text="Stop Capture")
                self.status_var.set(f"Live capture started on {selected_name}.")
            else:
                messagebox.showerror("Error", "Please select a valid network interface")
                return
        else:
            self.scanner.stop_capture()
            self.is_scanning = False
            self.capture_button.configure(text="Start Capture")
            self.status_var.set("Live capture stopped")

    def process_live_packet(self, packet):
        """
        Processes each live captured packet.
        """
        self.packets.append(packet)
        self.original_packets.append(packet)
        decoded_packet = self.packet_decoder.decode_packet(packet)
        if 'payload' in decoded_packet and decoded_packet['payload'].get('raw'):
            raw_data = bytes.fromhex(decoded_packet['payload']['raw']['hex'])
            location = self.location_tracker.analyze_packet_for_location(raw_data, packet.time)
            if location:
                self.root.after(0, self.update_location_display, location)

            # Re-analyze the payload using PayloadDecoder to get numeric and string sequences.
            payload_analysis = self.payload_decoder.analyze_payload(raw_data)
            decoded_packet['payload_analysis'] = payload_analysis

            # Generate a formatted hex dump using PayloadDecoder.
            payload_hex_dump = self.payload_decoder.create_hex_dump(raw_data)
            if isinstance(payload_hex_dump, list):
                payload_hex_dump_str = "\n".join(
                    f"{line['offset']:04X}  {line['hex']:<48}  {line['ascii']}" for line in payload_hex_dump)
            else:
                payload_hex_dump_str = payload_hex_dump

            # Add the packet to the conversation tracker.
            self.conversation_tracker.add_packet(decoded_packet, payload_hex_dump_str, decoded_packet['timestamp']['epoch'])

        self.root.after(0, self.add_packet_to_list, packet, decoded_packet)
        count = len(self.packets)
        self.root.after(0, self.packet_count_var.set, f"Packets: {count}")

