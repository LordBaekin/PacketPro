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
        Extract and validate location data from packet payload, filtering out duplicates.

        Steps:
          - Ensures packet_data is sufficiently long.
          - Extracts x, y, and z coordinates from fixed offsets.
          - Validates the coordinates using is_valid_location.
          - Calculates movement metrics via calculate_movement.
          - Computes a hash from the rounded (x, y, z) coordinates.
          - Checks for duplicates using the location_hashes set.
          - Updates the history and current location.
            (Now, if no previous location exists, the valid location is still added to history.)
          - Logs the data if logging is active.
          - Returns the location dictionary.

        Parameters:
            packet_data (bytes): Raw packet payload data.
            timestamp (float): Packet timestamp.

        Returns:
            dict: Dictionary with location data (including 'hash') if valid and unique; None otherwise.
        """
        try:
            if len(packet_data) < 32:
                return None

            # Extract coordinates from predetermined offsets.
            x = struct.unpack('<f', packet_data[0x000f:0x0013])[0]
            y = struct.unpack('<f', packet_data[0x0014:0x0018])[0]
            z = struct.unpack('<f', packet_data[0x0019:0x001d])[0]

            # Validate coordinates.
            if not self.is_valid_location(x, y, z):
                return None

            speed, direction = self.calculate_movement(x, y, z)

            # Compute hash using rounded coordinates (to 5 decimal places).
            location_hash = hash((round(x, 5), round(y, 5), round(z, 5)))

            # Filter out duplicate locations.
            if location_hash in self.location_hashes:
                return None

            self.location_hashes.add(location_hash)

            result = {
                'timestamp': timestamp,
                'x': x,
                'y': y,
                'z': z,
                'speed': speed,
                'direction': direction,
                'raw_hex': packet_data[0x000f:0x001d].hex(),
                'hash': location_hash
            }

            # Update history: if current_location is None, add this result;
            # otherwise, add the previous current_location to history and update current.
            if self.current_location is None:
                self.locations.append(result)
            else:
                self.locations.append(self.current_location)
                self.current_location = result

            # Always update current_location to the new result.
            self.current_location = result

            if self.logging_active and self.log_file:
                self.log_file.write(f"{timestamp},{x},{y},{z},{speed},{direction},{packet_data[0x000f:0x001d].hex()}\n")

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
