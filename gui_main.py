# gui_main.py
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import re
import threading
import json
from datetime import datetime
import pandas as pd
import scapy.all as scapy
from coordinate_analyzer import CoordinateAnalyzer
from location_tracker import LocationTracker
from encoding_detector import EncodingDetector
from packet_decoder import PacketDecoder
from gui_live_capture import LiveCaptureMixin
from gui_packet_list import PacketListMixin
from gui_payload_analysis import PayloadAnalysisMixin
from conversation_tracker import ConversationTracker
from payload_decoder import PayloadDecoder

class PacketAnalyzerGUI(LiveCaptureMixin, PacketListMixin, PayloadAnalysisMixin):
    def __init__(self, root):
        """
        Initializes the Packet Analyzer GUI.

        This method sets up the main window properties, initializes essential analyzers and trackers,
        sets up packet storage lists, and configures the live packet scanner. It then proceeds to create the GUI,
        add protocol filters and export options, and initialize live capture, protocol analysis, conversation tracking and location tracking.
      
        Parameters:
            root: The root Tkinter window.
        """
        self.root = root
        self.root.title("Advanced Network Packet Analyzer")
        self.root.geometry("1200x800")
        self.detector = EncodingDetector()
        self.packet_decoder = PacketDecoder()
        self.coordinate_analyzer = CoordinateAnalyzer()
        self.location_tracker = LocationTracker()
        self.payload_decoder = PayloadDecoder()

        self.conversation_tracker = ConversationTracker()
        self.packets = []
        self.original_packets = []
        self.current_packet_index = 0
        try:
            from live_packet_scanner import LivePacketScanner
            self.scanner = LivePacketScanner(self.process_live_packet)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize live scanner: {e}")
        self.is_scanning = False
        self.search_results = []
        self.current_match_index = -1
        self.case_sensitive = tk.BooleanVar(value=False)
        self.regex = tk.BooleanVar(value=False)
        self.hex_search = tk.BooleanVar(value=False)
        self.search_var = tk.StringVar()

        self.create_gui()
        self.add_protocol_filters()
        self.add_export_options()
        self.setup_live_capture_controls()
        self.setup_protocol_analysis_frame()
        self.setup_location_tracking_frame()
        

    def create_gui(self):
        """
        Creates and lays out the main GUI components.

        This method sets up the overall GUI layout including:
          - The top menu with file options (Open PCAP, Save Analysis, Export to JSON, and Exit).
          - A toolbar with buttons for opening, saving, exporting, filtering, resetting, loading CSV,
            and coordinate analysis.
          - A paned window that divides the interface into a left panel (packet list) and a right panel
            (notebook with packet details, payload analysis, and protocol analysis tabs).
          - A search bar with options for case sensitivity, regex, and hexadecimal searches, along with
            find and copy functionalities.
          - A status bar for displaying messages.
          - Event bindings for packet selection and search shortcuts.
        """
        main_container = ttk.Frame(self.root)
        main_container.pack(fill='both', expand=True, padx=10, pady=5)
        top_menu = tk.Menu(self.root)
        self.root.config(menu=top_menu)
        file_menu = tk.Menu(top_menu, tearoff=0)
        top_menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open PCAP", command=self.open_pcap)
        file_menu.add_command(label="Save Analysis", command=self.save_analysis)
        file_menu.add_command(label="Export to JSON", command=self.export_to_json)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        toolbar = tk.Frame(main_container)
        toolbar.pack(fill='x', padx=5, pady=5)
        tk.Button(toolbar, text="Open", command=self.open_pcap).pack(side='left', padx=2)
        tk.Button(toolbar, text="Save", command=self.save_analysis).pack(side='left', padx=2)
        tk.Button(toolbar, text="Export", command=self.export_to_json).pack(side='left', padx=2)
        tk.Button(toolbar, text="Filter", command=self.apply_filter).pack(side='left', padx=2)
        tk.Button(toolbar, text="Reset", command=self.reset_filters).pack(side='left', padx=2)
        tk.Button(toolbar, text="Load CSV", command=self.load_coordinate_csv).pack(side='left', padx=2)
        tk.Button(toolbar, text="Find Coordinates", command=self.analyze_coordinates).pack(side='left', padx=2)
        # In the toolbar area in create_gui() of PacketAnalyzerGUI
        follow_conv_button = ttk.Button(toolbar, text="Follow Conversation", command=self.follow_selected_conversation)
        follow_conv_button.pack(side='left', padx=2)
        paned_window = ttk.PanedWindow(main_container, orient='horizontal')
        paned_window.pack(fill='both', expand=True, pady=5)
        left_frame = ttk.Frame(paned_window)
        self.packet_tree = ttk.Treeview(left_frame, columns=('No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length'))
        self.packet_tree.heading('No.', text='No.')
        self.packet_tree.heading('Time', text='Time')
        self.packet_tree.heading('Source', text='Source')
        self.packet_tree.heading('Destination', text='Destination')
        self.packet_tree.heading('Protocol', text='Protocol')
        self.packet_tree.heading('Length', text='Length')
        self.packet_tree.column('No.', width=50)
        self.packet_tree.column('Time', width=100)
        self.packet_tree.column('Source', width=120)
        self.packet_tree.column('Destination', width=120)
        self.packet_tree.column('Protocol', width=70)
        self.packet_tree.column('Length', width=60)
        scrollbar = ttk.Scrollbar(left_frame, orient='vertical', command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)
        self.packet_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        paned_window.add(left_frame, weight=1)
        right_frame = ttk.Frame(paned_window)
        self.right_notebook = ttk.Notebook(right_frame)
        self.right_notebook.pack(fill='both', expand=True)
        details_frame = ttk.Frame(self.right_notebook)
        self.details_text = scrolledtext.ScrolledText(details_frame, height=10)
        self.details_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.right_notebook.add(details_frame, text='Packet Details')
        payload_frame = ttk.Frame(self.right_notebook)
        self.payload_text = scrolledtext.ScrolledText(payload_frame, height=10)
        self.payload_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.right_notebook.add(payload_frame, text='Payload Analysis')
        protocol_frame = ttk.LabelFrame(self.root, text="Protocol Analysis")
        protocol_frame.pack(fill='x', padx=15, pady=2)
        self.protocol_notebook = ttk.Notebook(protocol_frame)
        self.protocol_notebook.pack(fill='both', expand=True, padx=5, pady=5)
        protocol_tab = ttk.Frame(self.protocol_notebook)
        self.protocol_text = scrolledtext.ScrolledText(protocol_tab, height=8)
        self.protocol_text.pack(fill='both', expand=True)
        self.protocol_notebook.add(protocol_tab, text='Protocol Overview')
        http_tab = ttk.Frame(self.protocol_notebook)
        self.http_text = scrolledtext.ScrolledText(http_tab, height=8)
        self.http_text.pack(fill='both', expand=True)
        self.protocol_notebook.add(http_tab, text='HTTP')
        dns_tab = ttk.Frame(self.protocol_notebook)
        self.dns_text = scrolledtext.ScrolledText(dns_tab, height=8)
        self.dns_text.pack(fill='both', expand=True)
        self.protocol_notebook.add(dns_tab, text='DNS')
        tls_tab = ttk.Frame(self.protocol_notebook)
        self.tls_text = scrolledtext.ScrolledText(tls_tab, height=8)
        self.tls_text.pack(fill='both', expand=True)
        self.protocol_notebook.add(tls_tab, text='TLS/SSL')
        paned_window.add(right_frame, weight=2)
        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side='left', padx=5)
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        self.search_entry.pack(side='left')
        ttk.Checkbutton(search_frame, text="Case Sensitive", variable=self.case_sensitive).pack(side='left')
        ttk.Checkbutton(search_frame, text="Regex", variable=self.regex).pack(side='left')
        ttk.Checkbutton(search_frame, text="Hex", variable=self.hex_search).pack(side='left')
        self.find_button = ttk.Button(search_frame, text="Find", command=self.find_text)
        self.find_button.pack(side='left', padx=2)
        self.find_next_button = ttk.Button(search_frame, text="Find Next", command=self.find_next_text)
        self.find_next_button.pack(side='left', padx=2)
        self.match_count_label = ttk.Label(search_frame, text="Matches: 0")
        self.match_count_label.pack(side='left', padx=2)
        self.copy_button = ttk.Button(search_frame, text="Copy Selected", command=self.copy_selected_text)
        self.copy_button.pack(side='left', padx=2)
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(main_container, textvariable=self.status_var, relief='sunken', anchor='w')
        status_bar.pack(fill='x', pady=2)
        self.filter_var = tk.StringVar()
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        self.root.bind("<Control-f>", lambda event: self.search_entry.focus_set())
        self.root.bind("<F3>", self.find_next_text)

   

   


    def add_protocol_filters(self):
        """
        Adds quick filter buttons for common protocols.

        This method creates a labeled frame titled "Quick Filters" and adds buttons for filtering
        packets by TCP, UDP, HTTP, and DNS. A "Reset Filters" button is also provided to restore
        the full packet list.
        """
        filter_frame = ttk.LabelFrame(self.root, text="Quick Filters")
        filter_frame.pack(fill='x', padx=15, pady=2)
        ttk.Button(filter_frame, text="TCP Only", command=lambda: self.apply_quick_filter("TCP")).pack(side='left', padx=2)
        ttk.Button(filter_frame, text="UDP Only", command=lambda: self.apply_quick_filter("UDP")).pack(side='left', padx=2)
        ttk.Button(filter_frame, text="HTTP", command=lambda: self.apply_quick_filter("HTTP")).pack(side='left', padx=2)
        ttk.Button(filter_frame, text="DNS", command=lambda: self.apply_quick_filter("DNS")).pack(side='left', padx=2)
        ttk.Button(filter_frame, text="Reset Filters", command=self.reset_filters).pack(side='left', padx=2)

    def add_export_options(self):
        """
        Adds export options to the top menu.

        This method creates a file menu with options to open a PCAP file, save analysis, export data to JSON,
        and exit the application.
        """
        export_menu = tk.Menu(self.root)
        self.root.config(menu=export_menu)
        file_menu = tk.Menu(export_menu, tearoff=0)
        export_menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open PCAP", command=self.open_pcap)
        file_menu.add_command(label="Save Analysis", command=self.save_analysis)
        file_menu.add_command(label="Export to JSON", command=self.export_to_json)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

    def setup_protocol_analysis_frame(self):
        """
        Sets up the protocol analysis frame.

        This method is already handled in the create_gui method, so no additional setup is performed here.
        """
        pass

    def setup_location_tracking_frame(self):
        """
        Sets up the location tracking frame.

        This method creates a labeled frame titled "Location Tracking" which includes:
          - A button to start/stop location logging.
          - A label to display the current location.
          - A scrolled text widget to display location history.
        """
        location_frame = ttk.LabelFrame(self.root, text="Location Tracking")
        location_frame.pack(fill='x', padx=15, pady=2)
        control_frame = ttk.Frame(location_frame)
        control_frame.pack(fill='x', padx=5, pady=2)
        self.log_button = ttk.Button(control_frame, text="Start Location Logging", command=self.toggle_location_logging)
        self.log_button.pack(side='left', padx=2)
        self.location_var = tk.StringVar(value="Location: Not detected")
        ttk.Label(control_frame, textvariable=self.location_var).pack(side='left', padx=10)
        self.location_text = scrolledtext.ScrolledText(location_frame, height=6)
        self.location_text.pack(fill='x', padx=5, pady=5)

    def toggle_location_logging(self):
        """
        Toggles location logging on or off.

        If logging is not active, this method attempts to start logging using the location_tracker.
        If logging is already active, it stops the logging. The log button text and status message are updated accordingly.
        """
        if not self.location_tracker.logging_active:
            if self.location_tracker.start_logging():
                self.log_button.configure(text="Stop Location Logging")
                self.status_var.set("Location logging started")
            else:
                self.status_var.set("Failed to start location logging")
        else:
            self.location_tracker.stop_logging()
            self.log_button.configure(text="Start Location Logging")
            self.status_var.set("Location logging stopped")

    def update_location_display(self, location):
        """
        Updates the location display and history.

        If a valid location is provided, this method updates the location label with formatted X, Y, and Z coordinates.
        It also clears and repopulates the location history text widget with a timestamp and coordinates for each recorded location.

        Parameters:
            location (dict): A dictionary containing 'x', 'y', 'z', and 'timestamp' keys.
        """
        if location:
            self.location_var.set(f"Location: X: {location['x']:.2f}, Y: {location['y']:.2f}, Z: {location['z']:.2f}")
            self.location_text.delete(1.0, tk.END)
            history = self.location_tracker.locations
            for loc in history:
                timestamp = datetime.fromtimestamp(loc['timestamp']).strftime('%H:%M:%S.%f')[:-3]
                self.location_text.insert(tk.END, f"[{timestamp}] X: {loc['x']:.2f}, Y: {loc['y']:.2f}, Z: {loc['z']:.2f}\n")

    def format_dict_output(self, text_widget, data, indent=0):
        """
        Recursively formats and inserts dictionary or list data into a text widget.

        This method is used to display nested dictionary or list data in a readable, indented format.
        
        Parameters:
            text_widget: The Tkinter text widget where the output will be inserted.
            data: The dictionary or list to be formatted.
            indent (int): The current indentation level (number of spaces).
        """
        indent_str = " " * indent
        if isinstance(data, dict):
            for key, value in data.items():
                text_widget.insert(tk.END, f"{indent_str}{key}:\n")
                if isinstance(value, (dict, list)):
                    self.format_dict_output(text_widget, value, indent + 2)
                else:
                    text_widget.insert(tk.END, f"{indent_str}  {value}\n")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self.format_dict_output(text_widget, item, indent + 2)
                else:
                    text_widget.insert(tk.END, f"{indent_str}- {item}\n")
        else:
            text_widget.insert(tk.END, f"{indent_str}{data}\n")

    def apply_quick_filter(self, protocol):
        """
        Applies a quick filter to the packets based on the specified protocol.

        Depending on the protocol, this method filters the original packet list and updates the packet display.
        Supported protocols include TCP, UDP, HTTP, and DNS.

        Parameters:
            protocol (str): The protocol to filter by.
        """
        if protocol == "TCP":
            self.packets = [p for p in self.original_packets if scapy.TCP in p]
        elif protocol == "UDP":
            self.packets = [p for p in self.original_packets if scapy.UDP in p]
        elif protocol == "HTTP":
            self.packets = [p for p in self.original_packets if scapy.TCP in p and
                          (p[scapy.TCP].sport == 80 or p[scapy.TCP].dport == 80 or
                           p[scapy.TCP].sport == 443 or p[scapy.TCP].dport == 443)]
        elif protocol == "DNS":
            self.packets = [p for p in self.original_packets if scapy.UDP in p and
                          (p[scapy.UDP].sport == 53 or p[scapy.UDP].dport == 53)]
        self.update_packet_list()
        self.status_var.set(f"Filtered: showing {len(self.packets)} {protocol} packets")

    def reset_filters(self):
        """
        Resets any applied packet filters.

        This method restores the packet list to the original unfiltered set and updates the packet display and status message.
        """
        self.packets = self.original_packets.copy()
        self.update_packet_list()
        self.status_var.set(f"Filters reset: showing all {len(self.packets)} packets")

    def apply_filter(self):
        """
        Applies a custom filter to the packets based on user input.

        This method reads a filter expression from the filter_var entry, evaluates it against each packet's attributes,
        and updates the packet list to show only those packets that match the filter.
        If the filter expression is empty, it resets to the original packet list.
        Any errors during filtering are reported via a messagebox.
        """
        filter_text = self.filter_var.get().strip()
        if not filter_text:
            self.reset_filters()
            return
        try:
            filtered_packets = []
            for packet in self.original_packets:
                filter_map = {
                    'TCP': scapy.TCP in packet,
                    'UDP': scapy.UDP in packet,
                    'IP': scapy.IP in packet,
                    'src_ip': packet[scapy.IP].src if scapy.IP in packet else None,
                    'dst_ip': packet[scapy.IP].dst if scapy.IP in packet else None,
                    'src_port': packet[scapy.TCP].sport if scapy.TCP in packet else None,
                    'dst_port': packet[scapy.TCP].dport if scapy.TCP in packet else None,
                }
                try:
                    if eval(filter_text, {}, filter_map):
                        filtered_packets.append(packet)
                except:
                    continue
            self.packets = filtered_packets
            self.update_packet_list()
            self.status_var.set(f"Showing {len(filtered_packets)} filtered packets")
        except Exception as e:
            messagebox.showerror("Filter Error", f"Invalid filter: {str(e)}")

    def open_pcap(self):
        """
        Opens a file dialog to select a PCAP file and initiates its loading.

        This method updates the status message, and spawns a new thread to load the selected PCAP file.
        """
        filename = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap;*.pcapng"), ("All files", "*.*")]
        )
        if filename:
            self.status_var.set("Loading PCAP file.")
            self.root.update()
            thread = threading.Thread(target=self.load_pcap, args=(filename,))
            thread.daemon = True
            thread.start()

    def load_pcap(self, filename):
        """
        Loads packets from a PCAP file and updates the packet display.

        This method uses scapy to read packets from the given filename. It decodes each packet and updates the packet list
        asynchronously. Any errors during loading are reported via a messagebox.
        
        Parameters:
            filename (str): The path to the PCAP file.
        """
        try:
            self.packets = scapy.rdpcap(filename)
            self.original_packets = self.packets.copy()
            decoded_packets = []
            for packet in self.packets:
                try:
                    decoded = self.packet_decoder.decode_packet(packet)
                    decoded_packets.append(decoded)
                except Exception as e:
                    print(f"Error decoding packet: {e}")
                    decoded_packets.append(None)
            self.root.after(0, lambda: self.update_packet_list_with_decoded(decoded_packets))
            self.root.after(0, lambda: self.status_var.set(f"Loaded {len(self.packets)} packets"))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to load PCAP: {str(e)}"))
            self.root.after(0, lambda: self.status_var.set("Error loading PCAP"))

    def export_to_json(self):
        """
        Exports the current packet analysis data to a JSON file.

        This method opens a save file dialog, converts each packet's decoded data to JSON, and writes the data to the selected file.
        If there are no packets or an error occurs, an appropriate message is displayed.
        """
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to export")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                packet_data = []
                for packet in self.packets:
                    decoded = self.packet_decoder.decode_packet(packet)
                    packet_data.append(decoded)
                with open(filename, 'w') as f:
                    json.dump(packet_data, f, indent=2, default=str)
                messagebox.showinfo("Success", "Data exported successfully")
                self.status_var.set("Data exported to JSON")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export data: {str(e)}")

    def save_analysis(self):
        """
        Saves a detailed network packet analysis report to a text file.

        This method opens a save file dialog and writes a report containing summary statistics and details for each packet,
        including timestamp, layer data, and payload analysis. If there are no packets or an error occurs, an appropriate
        message is displayed.
        """
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to save")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("Network Packet Analysis Report\n")
                    f.write("=" * 50 + "\n\n")
                    f.write("Summary Statistics:\n")
                    f.write("-" * 20 + "\n")
                    f.write(f"Total Packets: {len(self.packets)}\n")
                    protocol_counts = {
                        'TCP': sum(1 for p in self.packets if scapy.TCP in p),
                        'UDP': sum(1 for p in self.packets if scapy.UDP in p),
                        'HTTP': sum(1 for p in self.packets if scapy.TCP in p and 
                                  (p[scapy.TCP].sport in (80, 443) or p[scapy.TCP].dport in (80, 443))),
                        'DNS': sum(1 for p in self.packets if scapy.UDP in p and 
                                 (p[scapy.UDP].sport == 53 or p[scapy.UDP].dport == 53))
                    }
                    for proto, count in protocol_counts.items():
                        f.write(f"{proto} Packets: {count}\n")
                    f.write("\n")
                    for i, packet in enumerate(self.packets, 1):
                        f.write(f"\nPacket {i}\n")
                        f.write("-" * 50 + "\n")
                        decoded = self.packet_decoder.decode_packet(packet)
                        f.write(f"Timestamp: {decoded['timestamp']['formatted']}\n")
                        for layer in ['layer2', 'layer3', 'layer4', 'layer7']:
                            if layer in decoded:
                                f.write(f"\n{layer.upper()}:\n")
                                self.write_dict_to_file(f, decoded[layer], indent=2)
                        if 'payload' in decoded and decoded['payload']:
                            f.write("\nPayload Analysis:\n")
                            self.write_dict_to_file(f, decoded['payload'], indent=2)
                        f.write("\n" + "=" * 50 + "\n")
                messagebox.showinfo("Success", "Analysis saved successfully")
                self.status_var.set("Analysis saved to file")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save analysis: {str(e)}")

    def write_dict_to_file(self, file, data, indent=0):
        """
        Recursively writes dictionary or list data to a file with indentation.

        This method is used by the save_analysis method to output structured data in a human-readable format.
        
        Parameters:
            file: The file object to write the data to.
            data: The dictionary or list data to be written.
            indent (int): The current level of indentation.
        """
        indent_str = " " * indent
        if isinstance(data, dict):
            for key, value in data.items():
                file.write(f"{indent_str}{key}:\n")
                if isinstance(value, (dict, list)):
                    self.write_dict_to_file(file, value, indent + 2)
                else:
                    file.write(f"{indent_str}  {value}\n")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self.write_dict_to_file(file, item, indent + 2)
                else:
                    file.write(f"{indent_str}- {item}\n")
        else:
            file.write(f"{indent_str}{data}\n")

    def load_coordinate_csv(self):
        """
        Loads a CSV file containing coordinate data for analysis.

        This method opens a file dialog to select a CSV file and attempts to load it using the coordinate analyzer.
        If successful, it updates the status message; otherwise, it displays an error.
        """
        filename = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if filename:
            try:
                self.coordinate_analyzer.load_csv(filename)
                self.status_var.set("Loaded coordinate CSV file")
            except Exception as e:
                messagebox.showerror("Error", str(e))
    def follow_selected_conversation(self):
        """
        Retrieves the conversation for the selected packet and displays its details.
        """
        # Get the selected packet from the packet list
        selection = self.packet_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No packet selected")
            return
        item = self.packet_tree.selection()[0]
        packet_num = int(self.packet_tree.item(item)['values'][0]) - 1
        decoded_packet = self.packet_decoder.decode_packet(self.packets[packet_num])
    
        # Construct the conversation key from the selected packet.
        conv_key = self.conversation_tracker._get_conversation_key(decoded_packet)
        if conv_key is None:
            messagebox.showerror("Error", "Could not determine conversation key")
            return
    
        # Retrieve the conversation details.
        conv_text = self.conversation_tracker.follow_conversation(conv_key)
    
        # Display the conversation in a new window.
        conv_window = tk.Toplevel(self.root)
        conv_window.title("Conversation Details")
        text_widget = tk.Text(conv_window, wrap='word')
        text_widget.insert('1.0', conv_text)
        text_widget.config(state='disabled')
        text_widget.pack(fill='both', expand=True)

    def analyze_coordinates(self):
        """
        Performs coordinate analysis on the loaded packets using a CSV file of coordinates.

        This method checks if packets and coordinate CSV data are available, then creates a new window to display
        analysis results. It iterates through each packet, decodes payloads, finds matching coordinates, and displays
        the matches with packet details. The status message is updated with the total matches found.
        """
        if not hasattr(self, 'packets') or not self.packets:
            messagebox.showwarning("Warning", "No packets loaded")
            return
        if self.coordinate_analyzer.csv_data is None:
            messagebox.showwarning("Warning", "Please load coordinate CSV file first")
            return
        results_window = tk.Toplevel(self.root)
        results_window.title("Coordinate Analysis Results")
        results_window.geometry("800x600")
        filter_frame = ttk.Frame(results_window)
        filter_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(filter_frame, text="Filter:").pack(side='left', padx=2)
        filter_entry = ttk.Entry(filter_frame)
        filter_entry.pack(side='left', fill='x', expand=True, padx=2)
        results_text = scrolledtext.ScrolledText(results_window)
        results_text.pack(fill='both', expand=True, padx=5, pady=5)
        total_matches = 0
        try:
            csv_data = self.coordinate_analyzer.csv_data
            csv_data['ID'] = pd.to_numeric(csv_data['ID'], errors='coerce')
            results_text.insert('end', "Analyzing packets for coordinate matches...\n\n")
            results_text.update()
            for packet_index, packet in enumerate(self.packets, 1):
                decoded = self.packet_decoder.decode_packet(packet)
                if 'payload' not in decoded or not decoded['payload']:
                    continue
                payload = bytes.fromhex(decoded['payload']['raw']['hex'])
                coords = self.coordinate_analyzer.find_coordinates(payload, decoded['timestamp']['epoch'])
                if coords:
                    for coord in coords:
                        matches = csv_data[
                            (abs(csv_data['ID'] - coord['timestamp']) < 0.1) &
                            (abs(csv_data['x'] - coord['x']) < 0.001) &
                            (abs(csv_data['y'] - coord['y']) < 0.001) &
                            (abs(csv_data['z'] - coord['z']) < 0.001)
                        ]
                        if not matches.empty:
                            total_matches += 1
                            results_text.insert('end',
                                f"\nMatch #{total_matches}:\n"
                                f"Packet #{packet_index}\n"
                                f"Time: {decoded['timestamp']['formatted']}\n"
                                f"Format: {coord['format']}\n"
                                f"Offset: {coord['offset']}\n"
                                f"Coordinates: ({coord['x']:.3f}, {coord['y']:.3f}, {coord['z']:.3f})\n"
                                f"Matching CSV IDs: {', '.join(map(str, matches['ID'].tolist()))}\n"
                                f"{'='*50}\n"
                            )
                            results_text.see('end')
                            results_text.update()
            if total_matches == 0:
                results_text.insert('end', "No matching coordinates found.\n")
            results_text.insert('1.0', f"Analysis complete: Found {total_matches} matching coordinates.\n{'='*50}\n\n")
            self.status_var.set(f"Coordinate analysis complete: {total_matches} matches found")
        except Exception as e:
            messagebox.showerror("Error", f"Coordinate analysis failed: {str(e)}")

if __name__ == '__main__':
    root = tk.Tk()
    app = PacketAnalyzerGUI(root)
    root.mainloop()
