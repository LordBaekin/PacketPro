# Advanced Network Packet Analyzer

This project is a comprehensive network packet analyzer built with Python and Scapy. It provides live packet capture, payload decoding, protocol analysis, location tracking, coordinate analysis, and an interactive GUI built with Tkinter.

## Project Overview

### 1. live_packet_scanner.py
**Class: LivePacketScanner**  
Captures network packets in real time using Scapy on a specified network interface. The capture runs in a separate daemon thread and includes the following key methods:
- **__init__(packet_callback, interface=None):** Initializes the scanner with a packet callback and optional interface.
- **start_capture():** Starts the capture loop in a daemon thread.
- **stop_capture():** Stops the capture loop.
- **_capture_packets():** Internal loop using Scapy's `sniff` to capture and process packets.
- **get_available_interfaces():** Retrieves a dictionary of available network interfaces.

### 2. location_tracker.py
**Class: LocationTracker**  
Extracts, validates, and logs geographic coordinates (X, Y, Z) from packet payloads. Also filters out duplicate locations.
- **__init__():** Initializes the tracker with default parameters.
- **set_valid_ranges(x_range, y_range, z_range):** (Deprecated) Previously used to set fixed coordinate ranges.
- **start_logging(filename="location_log.csv"):** Opens a CSV file and starts logging.
- **stop_logging():** Stops logging and closes the file.
- **analyze_packet_for_location(packet_data, timestamp):** Extracts and validates coordinates, calculates movement, logs and returns location data.
- **is_valid_location(x, y, z):** Validates the coordinates.
- **calculate_movement(x, y, z):** Computes a basic speed and returns a fixed direction ("N/A").

### 3. packet_decoder.py
**Class: PacketDecoder**  
Performs comprehensive decoding and analysis of network packets, combining protocol-specific decoding with payload analysis.
- **__init__():** Creates instances of `ProtocolDecoder` and `EncodingDetector`.
- **decode_packet(packet):** Aggregates layer-by-layer decoding and, if applicable, performs payload analysis.
- **analyze_payload(payload):** Reports payload length, hex representation, entropy, text decoding attempts, encoding detection, and file signature identification.
- **identify_file_signature(data):** Checks for known file signatures (magic numbers).

### 4. gui_live_capture.py
**Mixin: LiveCaptureMixin**  
Provides the GUI components for live packet capture.
- **setup_live_capture_controls():** Creates a labeled frame with network interface selection, start/stop button, and packet count.
- **toggle_capture():** Starts or stops the live capture based on the current state.
- **process_live_packet(packet):** Processes each packet (decoding and location analysis) and updates the GUI.

### 5. encoding_detector.py
**Class: EncodingDetector**  
Analyzes raw byte data to detect encoding schemes, compression, or encryption. Calculates entropy and applies regular expression patterns.
- **__init__():** Compiles patterns for various encodings and checks for zlib.
- **calculate_entropy(data):** Computes Shannon entropy.
- **detect_encoding(data):** Attempts to detect encodings (Base64, hex, JWT, etc.) and compression.
- **is_printable(data):** Checks if data is printable text.

### 6. coordinate_analyzer.py
**Class: CoordinateAnalyzer**  
Loads coordinate data from a CSV file and extracts (x, y, z) coordinate values from payloads.
- **__init__():** Initializes supported formats (e.g., "float32").
- **load_csv(filename):** Loads CSV data using pandas.
- **find_coordinates(payload, timestamp):** Extracts and validates coordinate triples.
- **is_valid_coordinate(x, y, z):** Validates that coordinates are within a reasonable range.

### 7. gui_payload_analysis.py
**Mixin: PayloadAnalysisMixin**  
Adds payload analysis functionality to the GUI including text search, highlighting, and detailed decoding information.
- **copy_selected_text():** Copies selected text to the clipboard.
- **find_text():** Searches the payload text for a specified term with options for case sensitivity, regex, or hexadecimal search.
- **find_next_text(*args):** Cycles through and highlights the next match.
- **update_payload_analysis(decoded_packet):** Updates the payload analysis view with comprehensive decoding and analysis details.

### 8. payload_decoder.py
**Class: PayloadDecoder**  
Conducts an in-depth analysis of packet payloads including hex dump generation, file type detection, numeric and text decoding, and pattern recognition.
- **__init__():** Initializes known file signatures and numeric data patterns.
- **analyze_payload(data):** Orchestrates overall payload analysis.
- **create_hex_dump(data):** Generates a formatted hex dump with ASCII representations.
- **try_decode_chunk(chunk):** Attempts numeric and text decoding of a data chunk.
- **detect_file_type(data):** Identifies file type via magic numbers and content-based heuristics.
- **analyze_data_patterns(data):** Detects numeric sequences, string sequences, repeating patterns, and structured data.
- **find_number_sequences(data):** Extracts numeric values using various binary formats.
- **find_string_sequences(data):** Finds sequences of printable characters.
- **find_repeating_patterns(data):** Identifies repeating byte sequences.
- **detect_structured_data(data):** Looks for potential structured data patterns.
- **analyze_text(data):** Attempts to decode text in multiple encodings.
- **calculate_entropy(data):** Calculates the Shannon entropy.
- **analyze_encodings(data):** Tries decoding via Base64, hex, and URL encodings.
- **analyze_structure(data):** Searches for alignment and boundary markers.
- **format_hex_ascii_dump(data):** Produces a formatted string version of the hex dump.

### 9. gui_packet_list.py
**Mixin: PacketListMixin**  
Manages the display of captured packets in the GUI and handles user interactions.
- **add_packet_to_list(packet, decoded_packet=None):** Inserts a decoded packet into the packet list.
- **update_packet_list():** Refreshes the entire packet list.
- **update_packet_list_with_decoded(decoded_packets):** Updates the list using pre-decoded packet data.
- **on_packet_select(event):** Handles user selection of a packet to display detailed info.
- **update_packet_details(decoded_packet):** Displays detailed layer-by-layer information.
- **update_protocol_tabs(decoded_packet):** Updates protocol-specific views (HTTP, DNS, TLS).

### 10. protocol_decoder.py
**Class: ProtocolDecoder**  
Decodes the various layers (2 through 7) of a network packet.
- **__init__():** Registers common application protocols.
- **decode_packet(packet):** Aggregates decoding from all layers including timestamp, Ethernet/WiFi (L2), IP/ARP (L3), TCP/UDP/ICMP (L4), and HTTP/DNS/TLS (L7).
- **get_timestamp(packet):** Formats the packet timestamp.
- **decode_layer2(packet):** Extracts data link layer information.
- **decode_layer3(packet):** Extracts network layer details.
- **decode_layer4(packet):** Extracts transport layer details.
- **decode_layer7(packet):** Attempts application layer decoding.
- **decode_http(packet):** Extracts HTTP-specific details.
- **decode_dns(packet):** Extracts DNS-specific details.
- **decode_tls(packet):** Extracts TLS/SSL details.
- **decode_payload(packet):** Tries multiple decoding methods on the payload.
- **identify_protocols(packet):** Identifies all protocols present.
- **get_raw_data(packet):** Returns a summary of the raw packet.
- **Helper methods:** Additional functions for decoding TCP/IP flags, TCP options, DNS record types, etc.

### 11. gui_main.py
**Class: PacketAnalyzerGUI**  
The main GUI class that integrates all modules, providing the user interface for live capture, packet listing, payload analysis, protocol analysis, coordinate analysis, and location tracking.
- **__init__(root):** Initializes the GUI, analyzers, trackers, packet storage, and live scanner.
- **create_gui():** Constructs the main layout including menus, toolbar, packet list, details view, search bar, and status bar.
- **add_protocol_filters():** Adds quick filter buttons.
- **add_export_options():** Adds file export options.
- **setup_protocol_analysis_frame() & setup_location_tracking_frame():** Set up dedicated frames for protocol analysis and location tracking.
- **toggle_location_logging():** Starts or stops location logging.
- **update_location_display(location):** Updates the location view with current and historical coordinates.
- **format_dict_output(text_widget, data, indent=0):** Recursively formats and outputs dictionary data.
- **apply_quick_filter(protocol):** Applies protocol-specific filters.
- **reset_filters():** Resets any applied filters.
- **apply_filter():** Applies custom filters based on user input.
- **open_pcap() & load_pcap(filename):** Loads a PCAP file and updates the packet list.
- **export_to_json():** Exports decoded packet data to JSON.
- **save_analysis():** Saves a detailed analysis report to a text file.
- **load_coordinate_csv():** Loads coordinate CSV data.
- **analyze_coordinates():** Performs coordinate analysis against loaded packets and CSV data.

