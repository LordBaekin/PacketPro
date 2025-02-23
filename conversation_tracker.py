# conversation_tracker.py
import difflib
import datetime

class ConversationTracker:
    """
    Tracks conversations (i.e. sequences of related packets) and highlights changes
    in the payload analysis. Packets are grouped by a conversation key (e.g., a tuple of
    source/destination IP and ports).
    """

    def __init__(self):
        # Dictionary mapping conversation keys to lists of packet records.
        # Each record is a dict with keys: 'timestamp', 'payload', and optionally 'numeric_values'.
        self.conversations = {}

    def _get_conversation_key(self, packet):
        """
        Constructs a conversation key from a decoded packet.
        Assumes packet has 'layer3' for IP and 'layer4' for TCP/UDP.
        The key is a sorted tuple so that traffic in both directions is grouped together.
        """
        try:
            src = packet.get('layer3', {}).get('src_ip', None)
            dst = packet.get('layer3', {}).get('dst_ip', None)
            if 'layer4' in packet:
                if packet['layer4'].get('type') in ['TCP', 'UDP']:
                    src_port = packet['layer4'].get('src_port', None)
                    dst_port = packet['layer4'].get('dst_port', None)
                else:
                    src_port = dst_port = None
            else:
                src_port = dst_port = None

            endpoints = sorted([(src, src_port), (dst, dst_port)])
            return (endpoints[0], endpoints[1])
        except Exception as e:
            print("Error constructing conversation key:", e)
            return None

    def add_packet(self, packet, payload_hex_dump, timestamp):
        """
        Adds a packet's payload (in hex dump form) and its interpreted numeric values to the conversation tracker.
    
        Parameters:
            packet (dict): The decoded packet dictionary.
            payload_hex_dump (str): The formatted hex dump string of the packet payload.
            timestamp (float): The packet's epoch timestamp.
        """
        key = self._get_conversation_key(packet)
        if key is None:
            return

        # Look for numeric values at the top level; if not found, try inside 'payload_analysis'
        numeric_values = packet.get('numeric_values', {})
        if not numeric_values and 'payload_analysis' in packet:
            numeric_values = packet['payload_analysis'].get('numeric_values', {})

        record = {
            'timestamp': timestamp,
            'payload': payload_hex_dump,
            'numeric_values': numeric_values
        }
        if key in self.conversations:
            self.conversations[key].append(record)
        else:
            self.conversations[key] = [record]


    def follow_conversation(self, key):
        """
        Returns a formatted string that shows the conversation for the given key,
        including differences between successive payload hex dumps.
        
        Parameters:
            key: The conversation key (tuple) to follow.
        
        Returns:
            str: A multi-line string showing the timeline and payload differences.
        """
        if key not in self.conversations:
            return "No conversation found for key: {}".format(key)
        
        records = self.conversations[key]
        output_lines = []
        output_lines.append("Conversation for key: {}".format(key))
        output_lines.append("-" * 80)
        
        prev_payload = None
        for record in records:
            ts = datetime.datetime.fromtimestamp(record['timestamp']).strftime('%Y-%m-%d %H:%M:%S.%f')
            output_lines.append(f"Time: {ts}")
            output_lines.append("Payload:")
            output_lines.append(record['payload'])
            
            if prev_payload:
                diff = difflib.unified_diff(
                    prev_payload.splitlines(), record['payload'].splitlines(),
                    lineterm='', fromfile='prev', tofile='curr'
                )
                diff_text = "\n".join(diff)
                if diff_text:
                    output_lines.append("Differences from previous packet:")
                    output_lines.append(diff_text)
                else:
                    output_lines.append("No differences from previous packet.")
            else:
                output_lines.append("First packet in conversation.")
            output_lines.append("-" * 80)
            prev_payload = record['payload']
        
        return "\n".join(output_lines)

    def follow_numeric_differences(self, key):
        """
        Returns a list of tuples (line_text, tag) for numeric differences in the conversation.
    
        For each numeric key that is present in every record of the conversation:
          - If the value remains the same between consecutive packets, the line is tagged "green".
          - If the value changes, the line is tagged "red" (showing the previous value, current value, and the delta).
    
        Keys that are not present in every packet are omitted.
    
        Parameters:
            key: The conversation key (tuple) to follow.
        
        Returns:
            list: A list of tuples (line_text, tag). 'tag' is either "green", "red", or None.
        """
        import datetime

        if key not in self.conversations:
            return [("No conversation found for key: " + str(key), None)]
    
        records = self.conversations[key]
        output = []
        output.append(("Numeric Differences for conversation key: " + str(key), None))
        output.append(("-" * 80, None))
    
        # Only consider keys that appear in every record
        common_keys = None
        for record in records:
            keys = set(record.get('numeric_values', {}).keys())
            if common_keys is None:
                common_keys = keys
            else:
                common_keys = common_keys.intersection(keys)
        common_keys = sorted(common_keys) if common_keys else []
    
        if len(records) < 1 or not common_keys:
            output.append(("No numeric data available for consistent keys.", None))
            return output

        prev_record = None
        for record in records:
            ts = datetime.datetime.fromtimestamp(record['timestamp']).strftime('%Y-%m-%d %H:%M:%S.%f')
            output.append((f"Time: {ts}", None))
            numeric_vals = record.get('numeric_values', {})
            for key_field in common_keys:
                val = numeric_vals.get(key_field)
                if prev_record is not None:
                    prev_val = prev_record.get('numeric_values', {}).get(key_field)
                    if prev_val is not None:
                        if val == prev_val:
                            output.append((f"  {key_field}: {val} (unchanged)", "green"))
                        else:
                            diff = val - prev_val
                            output.append((f"  {key_field}: {prev_val} -> {val} (Δ = {diff})", "red"))
                else:
                    # For the first record, simply display the value (mark as unchanged)
                    output.append((f"  {key_field}: {val}", "green"))
            output.append(("-" * 80, None))
            prev_record = record

        return output


    def get_all_conversations(self):
        """
        Returns all conversation keys currently tracked.
        """
        return list(self.conversations.keys())
