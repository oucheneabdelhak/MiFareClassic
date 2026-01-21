# MiFARE Classic 1K Python Library

A clean, minimal Python library for MiFARE Classic 1K RFID card operations with Omnikey 5422 readers. Provides essential read/write/authentication functionality without unnecessary complexity.

## Features

- **Simple API**: Easy-to-use methods for card operations
- **PC/SC Compatible**: Works with standard PC/SC readers (tested with Omnikey 5422)
- **Complete Operations**:
  - Card connection and UID reading
  - Block and sector reading/writing
  - Authentication with Key A/Key B
  - Memory dumping and analysis
- **Security Tools**: Default key scanning and vulnerability assessment
- **Comprehensive Example**: Detailed workflow demonstration included

## Quick Start

### Installation

```bash
# Install required dependencies
pip install pyscard

# Clone the repository
git clone https://github.com/yourusername/mifare-classic-python.git
cd mifare-classic-python
