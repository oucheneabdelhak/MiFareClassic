"""
Simple MiFARE Classic 1K Library
=================================

A clean, minimal library for MiFARE Classic 1K operations with Omnikey 5422.
No unnecessary complexity - just basic read/write/authentication.

Author: OUCHENE Abdelhak
Version: 1.0.0
Requirements: python3-smartcard
"""

from smartcard.System import readers
from smartcard.util import toHexString
import struct


class MifareClassic1K:
    def __init__(self, reader_index=0, prefer_cl=True):
        """Initialize connection to card
        
        Args:
            reader_index: Fallback index if no CL reader found
            prefer_cl: Prefer readers with 'CL' in name (Omnikey)
        """
        r = readers()
        if not r:
            raise RuntimeError("No readers found")
        
        # Try to find a reader with "CL" in the name (Omnikey)
        selected_reader = None
        if prefer_cl:
            for reader in r:
                if "CL" in str(reader).upper():
                    selected_reader = reader
                    print(f"Found CL reader: {reader}")
                    break
        
        # If no CL reader found, use the specified index or first available
        if selected_reader is None:
            if reader_index < len(r):
                selected_reader = r[reader_index]
            else:
                selected_reader = r[0]
            print(f"Using reader at index {reader_index}: {selected_reader}")
        
        self.reader = selected_reader
        self.connection = self.reader.createConnection()
        self.connection.connect()
        print(f"Connected to: {self.reader}")
        print(f"ATR: {toHexString(self.connection.getATR())}")
        
        '''ATR (Answer to Reset):
    When you insert a smart card, its chip sends an ATR signal after a reset.
    It's a standardized data sequence (following ISO/IEC 7816 standards) that tells the reader about the card's capabilities (e.g., maximum speed, clock frequency, voltage).
    The reader (like an OMNIKEY) uses the ATR to configure its communication settings to talk to the card correctly. '''
    
    def transmit(self, apdu):
        """Send APDU and return response"""
        return self.connection.transmit(apdu)
    
    def get_uid(self):
        """Get card UID"""
        apdu = [0xFF, 0xCA, 0x00, 0x00, 0x00]
        data, sw1, sw2 = self.transmit(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            return toHexString(data)
        return None
    
    def load_key(self, key_slot, key_bytes):
        """Load 6-byte key into reader memory"""
        if len(key_bytes) != 6:
            raise ValueError("Key must be 6 bytes")
        apdu = [0xFF, 0x82, 0x20, key_slot, 0x06] + key_bytes
        data, sw1, sw2 = self.transmit(apdu)
        return sw1 == 0x90 and sw2 == 0x00
    
    def authenticate(self, block, key_type, key_slot):
        """Authenticate to block (0-63)"""
        # key_type: 0x60 for Key A, 0x61 for Key B
        apdu = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, key_type, key_slot]
        data, sw1, sw2 = self.transmit(apdu)
        return sw1 == 0x90 and sw2 == 0x00
    
    def read_block(self, block):
        """Read 16 bytes from block"""
        apdu = [0xFF, 0xB0, 0x00, block, 0x10]
        data, sw1, sw2 = self.transmit(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            return data
        return None
    
    def write_block(self, block, data):
        """Write 16 bytes to block"""
        if len(data) != 16:
            raise ValueError("Data must be 16 bytes")
        apdu = [0xFF, 0xD6, 0x00, block, 0x10] + data
        data, sw1, sw2 = self.transmit(apdu)
        return sw1 == 0x90 and sw2 == 0x00
    
    def read_sector(self, sector):
        """Read all 4 blocks in a sector"""
        blocks = []
        start_block = sector * 4
        for i in range(4):
            block_data = self.read_block(start_block + i)
            if block_data:
                blocks.append(block_data)
        return blocks
    
    def write_sector(self, sector, blocks):
        """Write all 4 blocks to a sector"""
        if len(blocks) != 4:
            raise ValueError("Must provide 4 blocks")
        success = True
        start_block = sector * 4
        for i, block_data in enumerate(blocks):
            if not self.write_block(start_block + i, block_data):
                success = False
        return success


class MemoryManager:
    def __init__(self, card):
        """Initialize with MifareClassic1K instance"""
        self.card = card
        self.default_key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    
    def string_to_bytes(self, text, length=16):
        """Convert string to byte list with zero padding"""
        bytes_list = list(text.encode('ascii', errors='ignore'))
        bytes_list.extend([0] * (length - len(bytes_list)))
        return bytes_list[:length]
    
    def bytes_to_string(self, byte_list):
        """Convert byte list back to string"""
        clean_bytes = bytearray()
        for byte in byte_list:
            if byte == 0:
                break
            if 32 <= byte <= 126:  # Printable ASCII
                clean_bytes.append(byte)
        return clean_bytes.decode('ascii', errors='ignore')
    
    def dump_memory(self):
        """Dump entire card memory"""
        print("\n=== MiFARE Classic 1K Memory Dump ===")
        print("Sector | Block | Data")
        print("-" * 50)
        
        for sector in range(16):
            for block in range(4):
                block_num = sector * 4 + block
                data = self.card.read_block(block_num)
                if data:
                    hex_str = toHexString(data)
                    ascii_str = self.bytes_to_string(data)
                    print(f"{sector:2d}     | {block_num:3d}   | {hex_str[:32]}... | '{ascii_str[:10]}...'")
     
    
    
class SecurityTools:
    def __init__(self, card):
        """Initialize with MifareClassic1K instance"""
        self.card = card
        self.common_keys = [
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],  # Default
            [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],  # Transport
            [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7],  # MAD
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  # Zero key
        ]
    
    def try_common_keys(self):
        """Try common default keys on all sectors"""
        print("\n=== Trying Common Keys ===")
        accessible_sectors = []
    
        for sector in range(16):
            print(f"\nSector {sector:2d}:")
        
        # First, try to read the actual sector trailer
            trailer_block = sector * 4 + 3
            data = self.card.read_block(trailer_block)
            if data:
                print(f"  Actual trailer: {toHexString(data)}")
                print(f"  Key A (bytes 0-5): {toHexString(data[0:6])}")
                print(f"  Access (bytes 6-9): {toHexString(data[6:10])}")
                print(f"  Key B (bytes 10-15): {toHexString(data[10:16])}")
        
            success = False
        
            for key in self.common_keys:
                # Try Key A (0x60)
                if self.card.load_key(0, key):
                    if self.card.authenticate(trailer_block, 0x60, 0):
                        print(f"  ✓ Authenticated with Key A: {toHexString(key)}")
                        accessible_sectors.append((sector, 'A', key))
                        success = True
                        break
            
            # Try Key B (0x61)
                if self.card.load_key(0, key):
                    if self.card.authenticate(trailer_block, 0x61, 0):
                        print(f"  ✓ Authenticated with Key B: {toHexString(key)}")
                        accessible_sectors.append((sector, 'B', key))
                        success = True
                        break
        
            if not success:
                print("  ✗ No access")
    
        return accessible_sectors
        
    
    def read_access_bits(self, sector_trailer_data):
        """Parse access bits from sector trailer"""
        # Access bits are bytes 6-9
        if len(sector_trailer_data) >= 10:
            access_bytes = sector_trailer_data[6:10]
            print(f"Access bits: {toHexString(access_bytes)}")
            
            # Parse individual bits
            c1 = []
            c2 = []
            c3 = []
            
            for i in range(4):
                c1.append((access_bytes[i] >> 0) & 0x01)
                c2.append((access_bytes[i] >> 1) & 0x01)
                c3.append((access_bytes[i] >> 2) & 0x01)
            
            return c1, c2, c3
        return None, None, None


# Utility functions
def to_hex(byte_list):
    """Convert byte list to hex string"""
    return toHexString(byte_list)

def from_hex(hex_string):
    """Convert hex string to byte list"""
    return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]

def create_test_data():
    """Create test data for demonstration"""
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return {
        'timestamp': timestamp,
        'card_type': 'MiFARE Classic 1K',
        'test_data': 'Hello World!'
    }
