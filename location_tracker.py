import math
import os
import struct

class LocationTracker:
    """
    The LocationTracker class extracts, validates, and logs geographical coordinate data
    from network packet payloads. It validates a location by ensuring that none of the coordinates
    are near 0.0 (using an epsilon threshold), infinite, or NaN, and that they do not exceed a reasonable
    maximum value. Duplicate locations are filtered out using a hash check.
    Valid location data can be logged to a CSV file and a history of locations is maintained.
    
    Attributes:
        locations (list): List of recorded valid location data.
        current_location (dict or None): The most recent valid location.
        log_file (file object or None): File object for logging location data to CSV.
        logging_active (bool): Indicates whether location logging is active.
        location_hashes (set): Set of hashes for recorded locations, used to filter duplicates.
        MAX_COORDINATE (float): Maximum allowed absolute value for any coordinate.
        EPSILON (float): Minimum absolute value for a coordinate to be considered valid.
    """

    MAX_COORDINATE = 10000.0  # Maximum allowed absolute value (adjust if needed)
    EPSILON = 0.05            # Minimum threshold to consider a coordinate as non-zero

    def __init__(self):
        """
        Initialize a new LocationTracker instance with default settings.
        """
        self.locations = []
        self.current_location = None
        self.log_file = None
        self.logging_active = False
        # Set for duplicate filtering using coordinate hashes.
        self.location_hashes = set()

    def set_valid_ranges(self, x_range=None, y_range=None, z_range=None):
        """
        (Deprecated) Update coordinate validation ranges for x, y, and z axes.
        
        This method is retained for backward compatibility. The new validation approach
        does not enforce fixed range limits.
        
        Parameters:
            x_range (tuple or list, optional): The (min, max) range for the x-axis.
            y_range (tuple or list, optional): The (min, max) range for the y-axis.
            z_range (tuple or list, optional): The (min, max) range for the z-axis.
        """
        pass

    def start_logging(self, filename="location_log.csv"):
        """
        Start logging location data to a CSV file.

        Opens the specified file for writing and writes the CSV header.
        Sets logging_active to True if successful.

        Parameters:
            filename (str): Path to the CSV file.

        Returns:
            bool: True if logging started successfully; False otherwise.
        """
        try:
            if not self.logging_active:
                self.log_file = open(filename, 'w', newline='')
                self.log_file.write("Timestamp,X,Y,Z,Speed,Direction,Raw_Hex\n")
                self.logging_active = True
                return True
        except Exception as e:
            print(f"Failed to start logging: {e}")
            self.logging_active = False
            return False

    def stop_logging(self):
        """
        Stop logging location data and close the CSV file.

        Closes the log file (if open) and sets logging_active to False.
        Any errors encountered while closing are printed.
        """
        try:
            if self.log_file:
                self.log_file.close()
                self.log_file = None
            self.logging_active = False
        except Exception as e:
            print(f"Error closing log file: {e}")

    def analyze_packet_for_location(self, packet_data: bytes, timestamp: float) -> dict:
        """
        Extract and validate location data from a packet payload using new offsets.

        Expected new offsets (in hexadecimal):
          - X coordinate: 4 bytes starting at offset 0x0039 (decimal 57)
          - Y coordinate: 4 bytes starting at offset 0x0043 (decimal 67)
          - Z coordinate: 4 bytes starting at offset 0x003E (decimal 62)

        The method performs the following steps:
          1. Checks that the payload is long enough to contain the required data.
          2. Extracts the x, y, and z coordinates using struct.unpack with little-endian float format.
          3. Validates the extracted coordinates with is_valid_location().
          4. Calculates movement metrics (speed and direction) via calculate_movement().
          5. Computes a hash of the rounded coordinates for duplicate filtering.
          6. Updates the location history:
             - For the first valid location, it appends the result.
             - For subsequent valid locations, it appends the previous current location before updating.
          7. If logging is active, writes a CSV record containing the timestamp, coordinates, movement, and a raw hex representation.

        Parameters:
            packet_data (bytes): The raw payload data from the packet.
            timestamp (float): The timestamp of the packet capture.

        Returns:
            dict: A dictionary with the location data (keys include 'timestamp', 'x', 'y', 'z', 'speed',
                  'direction', 'raw_hex', and 'hash') if the location is valid and unique.
                  Returns None if the payload is too short, the data is invalid, or it is a duplicate.
        """
        try:
            # Ensure the payload is long enough; we need at least 0x0043 + 4 bytes (i.e. 71 bytes).
            if len(packet_data) < 0x0047:
                return None

            # Extract coordinates using the new offsets:
            # X coordinate: bytes 0x0039 to 0x0039+4
            x = struct.unpack('<f', packet_data[0x0039:0x0039+4])[0]
            # Y coordinate: bytes 0x0043 to 0x0043+4
            y = struct.unpack('<f', packet_data[0x0043:0x0043+4])[0]
            # Z coordinate: bytes 0x003E to 0x003E+4
            z = struct.unpack('<f', packet_data[0x003E:0x003E+4])[0]

            # Validate coordinates
            if not self.is_valid_location(x, y, z):
                return None

            # Calculate movement metrics
            speed, direction = self.calculate_movement(x, y, z)

            # Compute a unique hash for duplicate filtering (round coordinates to 5 decimal places)
            location_hash = hash((round(x, 5), round(y, 5), round(z, 5)))
            if location_hash in self.location_hashes:
                return None
            self.location_hashes.add(location_hash)

            # Prepare the result dictionary
            result = {
                'timestamp': timestamp,
                'x': x,
                'y': y,
                'z': z,
                'speed': speed,
                'direction': direction,
                # Optionally, log a relevant portion of the payload as hex (from offset 0x0039 to 0x003E+4)
                'raw_hex': packet_data[0x0039:0x003E+4].hex(),
                'hash': location_hash
            }

            # Update location history:
            # Append the previous current location (if it exists) to the history and update current_location.
            if self.current_location is None:
                self.locations.append(result)
            else:
                self.locations.append(self.current_location)
                self.current_location = result

            # Always update current location
            self.current_location = result

            # If logging is active, write the location data to the CSV file
            if self.logging_active and self.log_file:
                self.log_file.write(
                    f"{timestamp},{x},{y},{z},{speed},{direction},{packet_data[0x0039:0x003E+4].hex()}\n"
                )

            return result

        except Exception as e:
            print(f"Location analysis error: {e}")
            return None



    def is_valid_location(self, x, y, z) -> bool:
        """
        Validate a location based on new criteria.

        A valid location must satisfy the following:
          - None of the coordinates is near 0.0 (i.e. abs(val) < EPSILON).
          - None of the coordinates is infinite or NaN.
          - None of the coordinates exceed MAX_COORDINATE in absolute value.
          - No fixed range limit is enforced beyond these checks.

        Parameters:
            x (float): x-coordinate.
            y (float): y-coordinate.
            z (float): z-coordinate.

        Returns:
            bool: True if the location is valid; False otherwise.
        """
        for val in (x, y, z):
            if abs(val) < self.EPSILON:
                return False
            if math.isinf(val) or math.isnan(val):
                return False
            if abs(val) > self.MAX_COORDINATE:
                return False
        return True

    def calculate_movement(self, x, y, z):
        """
        Dummy implementation for movement calculation.

        Computes speed as the Euclidean norm of the coordinates divided by 1000.0
        and returns a fixed direction ("N/A").

        Parameters:
            x (float): x-coordinate.
            y (float): y-coordinate.
            z (float): z-coordinate.

        Returns:
            tuple: (speed, direction)
        """
        speed = math.sqrt(x * x + y * y + z * z) / 1000.0
        direction = "N/A"
        return speed, direction
