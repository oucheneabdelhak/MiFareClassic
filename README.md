MiFARE Classic 1K Python Library

A clean, minimal Python library for MiFARE Classic 1K RFID card operations with Omnikey 5422 readers. Provides essential read/write/authentication functionality without unnecessary complexity.
Features

    Simple API: Easy-to-use methods for card operations

    PC/SC Compatible: Works with standard PC/SC readers (tested with Omnikey 5422)

    Complete Operations:

        Card connection and UID reading

        Block and sector reading/writing

        Authentication with Key A/Key B

        Memory dumping and analysis

    Security Tools: Default key scanning and vulnerability assessment

    Comprehensive Example: Detailed workflow demonstration included

Quick Start
Installation
bash

# Install required dependencies
pip install pyscard

# Clone the repository
git clone https://github.com/yourusername/mifare-classic-python.git
cd mifare-classic-python

Basic Usage
python

from mifare_classic import MifareClassic1K, MemoryManager, SecurityTools

# Connect to card
card = MifareClassic1K()

# Get card UID
uid = card.get_uid()
print(f"Card UID: {uid}")

# Load default key (FFFFFFFFFFFF)
default_key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
card.load_key(0, default_key)

# Authenticate and read block 4
if card.authenticate(4, 0x60, 0):  # Key A
    data = card.read_block(4)
    print(f"Block 4 data: {data}")

Complete Workflow

Run the example workflow for a comprehensive demonstration:
bash

python example_workflow.py

This will guide you through:

    Card connection and identification

    Basic read/write operations

    Security vulnerability scanning

    Sector analysis with trailer information

    Advanced operations and cleanup

Card Structure

MiFARE Classic 1K cards have:

    1KB memory (1024 bytes)

    64 blocks (0-63)

    16 sectors (0-15)

    4 blocks per sector (3 data blocks + 1 sector trailer)

    16 bytes per block

Sector Trailer Structure

Each sector trailer (block 3, 7, 11, ...) contains:

    Key A: 6 bytes (first authentication key)

    Access Bits: 4 bytes (permission control)

    Key B: 6 bytes (second authentication key)

API Reference
MifareClassic1K Class
python

# Connection
card = MifareClassic1K(reader_index=0, prefer_cl=True)

# Core Operations
card.get_uid()                          # Get card UID
card.load_key(slot, key_bytes)          # Load 6-byte key
card.authenticate(block, key_type, slot) # Authenticate (0x60=Key A, 0x61=Key B)
card.read_block(block)                  # Read 16 bytes
card.write_block(block, data)           # Write 16 bytes
card.read_sector(sector)                # Read all 4 blocks in sector
card.write_sector(sector, blocks)       # Write 4 blocks to sector

MemoryManager Class
python

mem = MemoryManager(card)
mem.dump_memory()                       # Dump entire card memory
mem.string_to_bytes(text, length=16)    # Convert string to bytes
mem.bytes_to_string(byte_list)          # Convert bytes to string

SecurityTools Class
python

sec = SecurityTools(card)
sec.try_common_keys()                   # Test common default keys
sec.read_access_bits(trailer_data)      # Parse access bits

Common Keys

The library includes these common default keys:

    FFFFFFFFFFFF - Factory default

    A0A1A2A3A4A5 - Transport key

    D3F7D3F7D3F7 - MAD key

    000000000000 - Zero key

Requirements

    Python 3.6+

    python-smartcard (pyscard)

    PC/SC compatible card reader (tested with Omnikey 5422)

    MiFARE Classic 1K RFID cards

Installation
Linux (Ubuntu/Debian)
bash

# Install PC/SC libraries
sudo apt-get install pcscd pcsc-tools libpcsclite-dev

# Install Python package
pip install pyscard

Windows

    Install Omnikey Smart Card Reader Drivers

    Install Python package:

bash

pip install pyscard

macOS
bash

# Install PC/SC Lite
brew install pcsc-lite

# Install Python package
pip install pyscard

Examples
1. Read Entire Card
python

card = MifareClassic1K()
mem = MemoryManager(card)
mem.dump_memory()

2. Security Assessment
python

card = MifareClassic1K()
sec = SecurityTools(card)
vulnerable_sectors = sec.try_common_keys()

3. Write Custom Data
python

card = MifareClassic1K()
card.load_key(0, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

# Authenticate to block 4
if card.authenticate(4, 0x60, 0):
    # Write "Hello World!" to block
    data = list(b"Hello World!\x00\x00\x00\x00")
    card.write_block(4, data)

Troubleshooting
Common Issues

    "No readers found"

        Ensure reader is properly connected and powered

        Check if PC/SC service is running (pcscd on Linux)

    Authentication failures

        Verify card uses default keys or load correct keys

        Check access bits aren't restricting operations

    Read/Write errors

        Ensure proper authentication before operations

        Verify block isn't a sector trailer (blocks 3, 7, 11, etc.)

Debug Mode

Add debug output by modifying the transmit method in mifare_classic.py:
python

def transmit(self, apdu):
    """Send APDU and return response"""
    print(f"Sending: {toHexString(apdu)}")
    response = self.connection.transmit(apdu)
    print(f"Response: {response}")
    return response

Security Considerations

⚠️ IMPORTANT: MiFARE Classic cards have known cryptographic weaknesses. Do not use for high-security applications.

    Change default keys in production environments

    Never store sensitive data without proper encryption

    Understand access control before modifying sector trailers

    Always backup card data before writing

File Structure
text
