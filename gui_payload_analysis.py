# gui_payload_analysis.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import re
from datetime import datetime
import pyperclip
from payload_decoder import PayloadDecoder

class PayloadAnalysisMixin:
    def copy_selected_text(self):
        """
        Copies the currently selected text from the payload analysis text widget to the clipboard.
        
        If no text is selected, it prints an informational message.
        """
        try:
            selected_text = self.payload_text.get(tk.SEL_FIRST, tk.SEL_LAST)
            pyperclip.copy(selected_text)
            print("Selected text copied to clipboard")
        except tk.TclError:
            print("No text selected")

    def find_text(self):
        """
        Searches for a given string (or hex string/regex pattern) in the payload analysis text widget.

        The method retrieves the search string from 'self.search_var' and clears any previous search results.
        It supports case-sensitive, regular expression, and hexadecimal searches based on the state of the
        'self.case_sensitive', 'self.regex', and 'self.hex_search' BooleanVars.

        On a successful search, it updates the match count label and calls 'find_next_text' to highlight the first occurrence.
        If no matches are found, a messagebox is displayed.
        """
        search_text = self.search_var.get()
        if not search_text:
            return

        self.search_results = []
        self.current_match_index = -1
        content = self.payload_text.get("1.0", tk.END)

        if self.hex_search.get():
            # Perform a hexadecimal search
            try:
                search_bytes = bytes.fromhex(search_text.replace(' ', ''))
                content_bytes = bytes.fromhex(content.replace(' ', '').replace('\n', ''))
                pos = -1
                while True:
                    pos = content_bytes.find(search_bytes, pos + 1)
                    if pos == -1:
                        break
                    # Calculate corresponding text position (each byte represented as hex is 3 characters: two digits and a space)
                    text_pos = pos * 3
                    self.search_results.append(f"1.{text_pos}")
            except ValueError:
                messagebox.showerror("Error", "Invalid hex string")
                return
        else:
            # Regular text search
            flags = 0 if self.case_sensitive.get() else re.IGNORECASE
            if self.regex.get():
                # Use regular expressions for search
                try:
                    pattern = re.compile(search_text, flags)
                    for match in pattern.finditer(content):
                        start_pos = f"1.{match.start()}"
                        self.search_results.append(start_pos)
                except re.error:
                    messagebox.showerror("Error", "Invalid regular expression")
                    return
            else:
                # Simple substring search
                pos = "1.0"
                while True:
                    pos = self.payload_text.search(search_text, pos, tk.END, nocase=not self.case_sensitive.get())
                    if not pos:
                        break
                    self.search_results.append(pos)
                    pos = f"{pos}+1c"

        self.match_count_label.config(text=f"Matches: {len(self.search_results)}")
        if self.search_results:
            self.find_next_text()
        else:
            messagebox.showinfo("Search", "No matches found")

    def find_next_text(self, *args):
        """
        Highlights the next occurrence of the search term in the payload analysis text widget.

        If no search results exist, it will call 'find_text' to perform a new search.
        This method cycles through all found matches, removes any previous highlighting, and applies a yellow background
        to the current match.
        """
        if not self.search_results:
            self.find_text()
            return

        # Remove previous highlight
        self.payload_text.tag_remove("search", "1.0", tk.END)
        # Cycle to the next match index
        self.current_match_index = (self.current_match_index + 1) % len(self.search_results)
        match_pos = self.search_results[self.current_match_index]
        search_text = self.search_var.get()
        # Calculate length of match
        if self.hex_search.get():
            length = len(bytes.fromhex(search_text.replace(' ', ''))) * 3
        else:
            length = len(search_text)
        end_pos = f"{match_pos}+{length}c"
        # Apply highlight tag to the match
        self.payload_text.tag_add("search", match_pos, end_pos)
        self.payload_text.tag_config("search", background="yellow")
        self.payload_text.see(match_pos)

    def update_payload_analysis(self, decoded_packet):
        """
        Updates the payload analysis text widget with detailed decoding information.

        This method clears the current content and, if a valid payload exists in the decoded_packet,
        it retrieves the raw payload data (as hex), decodes it using the PayloadDecoder, and then displays:
          - Basic information (length, entropy, detected file type if available)
          - Hex dump along with ASCII interpretation
          - Numeric sequences, string sequences, text encoding analysis, repeating patterns,
            structural boundary markers, and additional encoding analysis.

        If an error occurs during analysis, an error message is displayed in the text widget.
        If no payload data is available, it notifies the user accordingly.
        
        Parameters:
            decoded_packet (dict): The dictionary containing decoded packet information, including a 'payload' key.
        """
        self.payload_text.config(state='normal')
        self.payload_text.delete(1.0, tk.END)
        if 'payload' in decoded_packet and decoded_packet['payload']:
            payload_info = decoded_packet['payload']
            if 'raw' in payload_info:
                decoder = PayloadDecoder()
                try:
                    raw_data = bytes.fromhex(payload_info['raw']['hex'])
                    analysis = decoder.analyze_payload(raw_data)
                    
                    # Basic Information
                    self.payload_text.insert(tk.END, "BASIC INFORMATION\n")
                    self.payload_text.insert(tk.END, "=" * 70 + "\n")
                    self.payload_text.insert(tk.END, f"Length: {len(raw_data)} bytes\n")
                    self.payload_text.insert(tk.END, f"Entropy: {analysis['entropy']:.2f}\n")
                    if analysis.get('file_type', 'UNKNOWN') != 'UNKNOWN':
                        self.payload_text.insert(tk.END, f"Detected File Type: {analysis['file_type']}\n")
                    self.payload_text.insert(tk.END, "\n")
                    
                    # Hex Dump and Interpretations
                    self.payload_text.insert(tk.END, "HEX DUMP AND INTERPRETATIONS\n")
                    self.payload_text.insert(tk.END, "=" * 70 + "\n")
                    self.payload_text.insert(tk.END, "Offset  Hexadecimal                                              ASCII\n")
                    self.payload_text.insert(tk.END, "-" * 70 + "\n")
                    for line in analysis['hex_dump']:
                        offset = f"{line['offset']:04x}"
                        hex_dump = line['hex'].ljust(48)
                        ascii_dump = line['ascii']
                        self.payload_text.insert(tk.END, f"{offset}  {hex_dump}  {ascii_dump}\n")
                        if line['decoded']:
                            self.payload_text.insert(tk.END, " " * 8 + "Interpreted values:\n")
                            for dtype, value in line['decoded'].items():
                                if isinstance(value, float):
                                    self.payload_text.insert(tk.END, " " * 10 + f"{dtype}: {value:.6f}\n")
                                else:
                                    self.payload_text.insert(tk.END, " " * 10 + f"{dtype}: {value}\n")
                    
                    # Numeric Sequences
                    if analysis['data_analysis']['numbers']:
                        self.payload_text.insert(tk.END, "\nNUMERIC SEQUENCES FOUND\n")
                        self.payload_text.insert(tk.END, "=" * 70 + "\n")
                        for seq in analysis['data_analysis']['numbers']:
                            self.payload_text.insert(tk.END, f"Offset 0x{seq['offset']:04x}: {seq['type']} = {seq['value']}\n")
                    
                    # String Sequences
                    if analysis['data_analysis']['strings']:
                        self.payload_text.insert(tk.END, "\nSTRING SEQUENCES FOUND\n")
                        self.payload_text.insert(tk.END, "=" * 70 + "\n")
                        for string_item in analysis['data_analysis']['strings']:
                            self.payload_text.insert(tk.END, f"Offset 0x{string_item['offset']:04x}: {string_item['string']} (length: {string_item['length']})\n")
                    
                    # Text Encoding Analysis
                    if analysis['text_analysis']:
                        self.payload_text.insert(tk.END, "\nTEXT ENCODING ANALYSIS\n")
                        self.payload_text.insert(tk.END, "=" * 70 + "\n")
                        for encoding, result in analysis['text_analysis'].items():
                            if result['printable_ratio'] > 0.5:
                                self.payload_text.insert(tk.END, f"{encoding} ({result['printable_ratio']:.2%} printable):\n")
                                self.payload_text.insert(tk.END, f"{result['text']}\n\n")
                    
                    # Repeating Patterns
                    if analysis['data_analysis']['repeating']:
                        self.payload_text.insert(tk.END, "\nREPEATING PATTERNS\n")
                        self.payload_text.insert(tk.END, "=" * 70 + "\n")
                        for pattern in analysis['data_analysis']['repeating']:
                            self.payload_text.insert(tk.END, f"Offset 0x{pattern['offset']:04x}: Pattern {pattern['pattern']} repeats {pattern['repeats']} times\n")
                    
                    # Structure Analysis - Boundary Markers
                    if analysis['structure_analysis']['boundaries']:
                        self.payload_text.insert(tk.END, "\nSTRUCTURE ANALYSIS\n")
                        self.payload_text.insert(tk.END, "=" * 70 + "\n")
                        for boundary in analysis['structure_analysis']['boundaries']:
                            positions = ', '.join(f'0x{pos:04x}' for pos in boundary['positions'])
                            self.payload_text.insert(tk.END, f"Boundary marker {boundary['marker']} found at offsets: {positions}\n")
                    
                    # Additional Encoding Analysis
                    if analysis['encoding_analysis']:
                        self.payload_text.insert(tk.END, "\nADDITIONAL ENCODING ANALYSIS\n")
                        self.payload_text.insert(tk.END, "=" * 70 + "\n")
                        for encoding, result in analysis['encoding_analysis'].items():
                            self.payload_text.insert(tk.END, f"{encoding} decoding:\n")
                            for key, value in result.items():
                                self.payload_text.insert(tk.END, f"  {key}: {value}\n")
                            self.payload_text.insert(tk.END, "\n")
                except Exception as e:
                    self.payload_text.insert(tk.END, f"Error analyzing payload: {str(e)}")
            else:
                self.payload_text.insert(tk.END, "No raw payload data available")
        else:
            self.payload_text.insert(tk.END, "No payload data available")
