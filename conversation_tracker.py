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
        # Each record is a dict with keys: timestamp, payload, and optionally decoded fields.
        self.conversations = {}

    def _get_conversation_key(self, packet):
        """
        Constructs a conversation key from a packet.
        Assumes packet has 'layer3' for IP and 'layer4' for TCP/UDP.
        The key is a sorted tuple to merge both directions.
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

            # Order the endpoints so that conversation is independent of direction.
            endpoints = sorted([(src, src_port), (dst, dst_port)])
            return (endpoints[0], endpoints[1])
        except Exception as e:
            print("Error constructing conversation key:", e)
            return None

    def add_packet(self, packet, payload_hex_dump, timestamp):
        """
        Adds a packet's payload (in hex dump form) to the conversation tracker.
        
        Parameters:
            packet (dict): The decoded packet dictionary.
            payload_hex_dump (str): The formatted hex dump string of the packet payload.
            timestamp (float): The packet's timestamp.
        """
        key = self._get_conversation_key(packet)
        if key is None:
            return

        record = {
            'timestamp': timestamp,
            'payload': payload_hex_dump
        }
        if key in self.conversations:
            self.conversations[key].append(record)
        else:
            self.conversations[key] = [record]

    def follow_conversation(self, key):
        """
        Returns a formatted string that shows the conversation for the given key,
        including differences between successive payloads.
        
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
                # Compute a diff between previous payload and current payload
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

    def get_all_conversations(self):
        """
        Returns all conversation keys currently tracked.
        """
        return list(self.conversations.keys())
