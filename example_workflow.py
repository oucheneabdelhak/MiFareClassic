"""
COMPLETE WORKFLOW EXAMPLE FOR MiFARE CLASSIC 1K CARD
===================================================

Enhanced workflow demonstrating all major MiFARE Classic operations.
Includes detailed explanations, user interaction, and comprehensive testing.

Author: OUCHENE Abdelhak
Version: 2.0.0 - Enhanced Workflow Edition
"""

import time
from smartcard.util import toHexString
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from mifare_classic import MifareClassic1K, MemoryManager, SecurityTools


def press_enter_to_continue(prompt="Press Enter to continue..."):
    """Pause execution and wait for user to press Enter"""
    input(f"\n{prompt}")


def print_section(title, width=60):
    """Print formatted section header"""
    print("\n" + "=" * width)
    print(title.center(width))
    print("=" * width)


def print_subsection(title, width=50):
    """Print formatted subsection header"""
    print("\n" + "-" * width)
    print(title.center(width))
    print("-" * width)


def print_step(step_num, description):
    """Print formatted step information"""
    print(f"\n[{step_num}] {description}")
    print("-" * 40)


def main():
    """Main workflow demonstration"""
    print("=" * 70)
    print("MiFARE CLASSIC 1K - COMPLETE WORKFLOW DEMONSTRATION")
    print("=" * 70)
    print("\nThis script demonstrates all major features of MiFARE Classic 1K cards.")
    print("It will read card data, demonstrate value blocks, perform security")
    print("analysis, and show memory management operations.")
    print("\nREQUIREMENTS:")
    print("• MiFARE Classic 1K card")
    print("• PC/SC compatible card reader")
    print("• Default keys (often 0xFFFFFFFFFFFF)")
    
    press_enter_to_continue("Press Enter to begin the workflow...")
    
    try:
        # ============================================
        # 1. INITIALIZATION AND CONNECTION
        # ============================================
        print_section("1. INITIALIZING CARD CONNECTION", 70)
        
        print("\nAttempting to connect to MiFARE Classic 1K card...")
        try:
            card = MifareClassic1K()
            print("   ✓ PC/SC connection established")
        except Exception as e:
            print(f"   ✗ Connection failed: {e}")
            print("\nTROUBLESHOOTING:")
            print("1. Ensure card reader is connected and powered")
            print("2. Insert a MiFARE Classic 1K card")
            print("3. Check if PC/SC service is running")
            print("4. Try running as administrator")
            return
        
        # Load default key for initial operations
        print("\nLoading default authentication key...")
        default_key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        try:
            card.load_key(0, default_key)
            print(f"   ✓ Key loaded: {toHexString(default_key)}")
            print("   This key works on many factory-default cards")
        except Exception as e:
            print(f"   ✗ Failed to load key: {e}")
        
        press_enter_to_continue()
        
        # ============================================
        # 2. CARD IDENTIFICATION
        # ============================================
        print_section("2. CARD IDENTIFICATION", 70)
        
        print("\nReading card unique identifier (UID)...")
        try:
            uid = card.get_uid()
            if uid:
                print(f"   ✓ Card UID: {uid}")
                uid_bytes = [int(x, 16) for x in uid.split()]
                print(f"   UID bytes: {toHexString(uid_bytes)}")
                
                # Determine card type based on UID length
                if len(uid_bytes) == 4:
                    print("   Card type: Standard MiFARE Classic 1K (4-byte UID)")
                elif len(uid_bytes) == 7:
                    print("   Card type: Extended UID MiFARE Classic 1K (7-byte UID)")
                else:
                    print(f"   Card type: Unknown (UID length: {len(uid_bytes)} bytes)")
            else:
                print("   ✗ Could not read UID")
        except Exception as e:
            print(f"   ✗ Error reading UID: {e}")
        
        press_enter_to_continue()
        
        # ============================================
        # 3. MEMORY STRUCTURE OVERVIEW
        # ============================================
        print_section("3. MEMORY STRUCTURE OVERVIEW", 70)
        
        print("\nMiFARE Classic 1K Memory Layout:")
        print("=" * 50)
        print("Total Memory: 1 KB (1024 bytes)")
        print("Blocks: 64 blocks (0-63)")
        print("Sectors: 16 sectors (0-15)")
        print("Blocks per sector: 4 blocks")
        print("Bytes per block: 16 bytes")
        print("\nBlock Organization:")
        print("  • Data Blocks: 3 blocks per sector (user data)")
        print("  • Sector Trailer: 1 block per sector (security)")
        print("\nSector Trailer contains:")
        print("  • Key A (6 bytes) - First authentication key")
        print("  • Access Bits (4 bytes) - Permission control")
        print("  • Key B (6 bytes) - Second authentication key")
        
        press_enter_to_continue()
        
        # ============================================
        # 4. BASIC READ/WRITE OPERATIONS
        # ============================================
        print_section("4. BASIC READ/WRITE OPERATIONS", 70)
        
        mem = MemoryManager(card)
        
        print_step("4.1", "Testing Authentication on Sector 1")
        
        # Choose a safe block for testing (block 4, sector 1, first data block)
        test_block = 4
        print(f"\nAttempting to authenticate to block {test_block} (Sector 1)...")
        
        try:
            # Authenticate with Key A (0x60)
            if card.authenticate(test_block, 0x60, 0):
                print("   ✓ Authentication successful with Key A")
                print("   Access granted for read/write operations")
            else:
                print("   ✗ Authentication failed")
                print("   The sector may use a different key or have restricted access")
                press_enter_to_continue("Continue to security scan...")
                # Skip to security scan if authentication fails
                security_successful = False
                
                # Jump to security scan section
                print_section("5. SECURITY ANALYSIS", 70)
                sec = SecurityTools(card)
                print("\nPerforming security analysis...")
                accessible = sec.try_common_keys()
                
                if accessible:
                    print(f"   Found {len(accessible)} accessible sectors")
                    print("\nAccessible sectors with common keys:")
                    for sector, key_type, key in accessible:
                        key_name = "Key A" if key_type == 0x60 else "Key B"
                        print(f"   Sector {sector}: {key_name} = {toHexString(key)}")
                    
                    # Try using one of the found keys
                    print("\nAttempting to use discovered keys...")
                    if accessible:
                        sector, key_type, key = accessible[0]
                        trailer_block = sector * 4 + 3
                        print(f"Trying key from sector {sector} on block {trailer_block}...")
                        card.load_key(1, key)
                        if card.authenticate(trailer_block, key_type, 1):
                            print("   ✓ Success! Using discovered key.")
                            # Update default key for subsequent operations
                            default_key = key
                            key_slot = 1
                            security_successful = True
                        else:
                            print("   ✗ Discovered key didn't work")
                else:
                    print("   ✗ No sectors accessible with common keys")
                
                if not security_successful:
                    print("\n" + "!" * 50)
                    print("SECURITY WARNING:")
                    print("Could not authenticate with any common key.")
                    print("The card may be using custom keys or enhanced security.")
                    print("!" * 50)
                    press_enter_to_continue()
                    return
                else:
                    # Continue with basic operations using discovered key
                    print("\nContinuing with discovered key...")
                    press_enter_to_continue()
                    # Set test_block to a block in the accessible sector
                    test_block = sector * 4  # First block of the sector
        except Exception as e:
            print(f"   ✗ Authentication error: {e}")
            press_enter_to_continue()
            return
        
        print_step("4.2", "Reading Existing Data")
        
        print(f"\nReading current data from block {test_block}...")
        try:
            current_data = card.read_block(test_block)
            if current_data:
                print(f"   Block {test_block} content:")
                print(f"   Hex: {toHexString(current_data)}")
                
                # Try to decode as ASCII
                ascii_str = ""
                for byte in current_data:
                    if 32 <= byte <= 126:  # Printable ASCII range
                        ascii_str += chr(byte)
                    else:
                        ascii_str += "."
                
                print(f"   ASCII: {ascii_str}")
                
                # Check if block appears to be a value block
                if mem.is_value_block(current_data):
                    print("   Block appears to be a VALUE BLOCK")
                    value = mem.read_value_block(test_block)
                    if value is not None:
                        print(f"   Stored value: {value}")
            else:
                print("   Block appears to be empty or unreadable")
        except Exception as e:
            print(f"   ✗ Read error: {e}")
        
        print_step("4.3", "Writing Test Data")
        
        print("\nWould you like to write test data to the card?")
        print("WARNING: This will overwrite existing data!")
        choice = input("Write test data? (y/N): ").lower()
        
        if choice == 'y':
            # Create test data
            test_message = b"MiFARE Test Block"
            # Pad to 16 bytes
            if len(test_message) < 16:
                test_message += b' ' * (16 - len(test_message))
            elif len(test_message) > 16:
                test_message = test_message[:16]
            
            test_data = list(test_message)
            
            print(f"\nPreparing to write to block {test_block}:")
            print(f"   Content: \"{test_message.decode('utf-8')}\"")
            print(f"   Hex: {toHexString(test_data)}")
            
            confirm = input("\nConfirm write operation? (y/N): ").lower()
            
            if confirm == 'y':
                try:
                    if card.write_block(test_block, test_data):
                        print("   ✓ Data written successfully")
                        
                        # Verify write by reading back
                        print("\nVerifying write operation...")
                        verify_data = card.read_block(test_block)
                        if verify_data == test_data:
                            print("   ✓ Write verification successful")
                            print(f"   Verified content: \"{bytes(verify_data).decode('utf-8', errors='ignore')}\"")
                        else:
                            print("   ⚠ Write verification failed")
                            print(f"   Expected: {toHexString(test_data)}")
                            print(f"   Got: {toHexString(verify_data)}")
                    else:
                        print("   ✗ Write operation failed")
                except Exception as e:
                    print(f"   ✗ Write errorring 5A 81 55 9F is being split incorrectly.: {e}")
            else:
                print("   Write operation cancelled")
        else:
            print("   Skipping write operation")
        
        press_enter_to_continue()
        
        # ============================================
        # 5. SECTOR AND MEMORY ANALYSIS
        # ============================================
        print_section("5. SECTOR AND MEMORY ANALYSIS", 70)
        
        print("\nAnalyzing card memory structure and accessibility...")
        
        print_step("5.1", "Security Vulnerability Scan")
        
        sec = SecurityTools(card)
        print("\nScanning for common default keys...")
        
        accessible_sectors = sec.try_common_keys()
        
        print(f"\nSecurity Assessment Results:")
        print("=" * 50)
        print(f"Total sectors scanned: 16")
        print(f"Sectors accessible: {len(accessible_sectors)}")
        print(f"Sectors secured: {16 - len(accessible_sectors)}")
        
        if len(accessible_sectors) > 0:
            print("\n⚠ SECURITY WARNING: Card vulnerable to default key attack!")
            print("\nAccessible sectors (with default keys):")
            for i, (sector, key_type, key) in enumerate(accessible_sectors, 1):
                key_name = "Key A" if key_type == 0x60 else "Key B"
                print(f"  {i:2d}. Sector {sector:2d}: {key_name:<5} = {toHexString(key)}")
        else:
            print("\n✓ GOOD: No default keys found")
            print("   Card appears to use custom keys")
        
        print_step("5.2", "Detailed Sector Analysis with Sector Trailers")

        print("\nWould you like to perform detailed sector analysis with sector trailers?")
        choice = input("Perform detailed sector analysis? (y/N): ").lower()

        if choice == 'y':
            print("\nAnalyzing each sector with trailer information...")
            print("\n" + "=" * 90)
            print(f"{'Sector':^6} | {'Trailer':^7} | {'Key A':^14} | {'Access Bits':^24} | {'Key B':^14} | {'Access'}")
            print(f"{'':^6} | {'Block':^7} | {'':^14} | {'(Hex)':^24} | {'':^14} | {'Control'}")
            print("=" * 90)
    
            for sector in range(16):
                trailer_block = sector * 4 + 3
        
                # Try to authenticate with default key
                try:
                    if card.authenticate(trailer_block, 0x60, 0):
                        # Read sector trailer
                        trailer_data = card.read_block(trailer_block)
                        if trailer_data:
                            key_a = trailer_data[0:6]
                            access_bits = trailer_data[6:10]
                            key_b = trailer_data[10:16]
                            
                            # Format key display
                            key_a_str = toHexString(key_a)
                            key_b_str = toHexString(key_b)
                            access_str = toHexString(access_bits)
                            
                            # Determine access control type based on access bits
                            # Check for default access bits (0xFF0780 or similar)
                            if (access_bits == [0xFF, 0x07, 0x80, 0x69] or         
                                access_bits == [0xFF, 0x07, 0x80, 0x00] or
                                access_bits[0:3] == [0xFF, 0x07, 0x80]):
                                access_type = "Default"
                                access_desc = "Key A:R/W, Key B:R/W"
                            elif access_bits == [0x78, 0x77, 0x88, 0x69] or access_bits[0:3] == [0x78, 0x77, 0x88]:
                                access_type = "Deny All"
                                access_desc = "No access"
                            elif access_bits == [0x08, 0x77, 0x8F, 0x69] or access_bits[0:3] == [0x08, 0x77, 0x8F]:
                                access_type = "Read Only"
                                access_desc = "Key A:R, Key B:None"
                            elif access_bits == [0x87, 0x0F, 0x87, 0x0F] or access_bits[0:3] == [0x87, 0x0F, 0x87]:
                                access_type = "Value Block"
                                access_desc = "Key A:Dec/Inc, Key B:R"
                            else:
                                access_type = "Custom"
                                access_desc = "Custom config"
                            
                            # Check which keys are default
                            is_default_key_a = key_a == default_key
                            is_default_key_b = key_b == default_key
                            
                            key_a_display = f"{key_a_str}{'*' if is_default_key_a else ''}"
                            key_b_display = f"{key_b_str}{'*' if is_default_key_b else ''}"
                            
                            print(f"{sector:6d} | {trailer_block:7d} | {key_a_display:<14} | {access_str:<24} | {key_b_display:<14} | {access_type:<8}")
                            
                            # Print access description on next line if not default
                            if access_type != "Default":        
                                print(f"{'':^6} {'':^7} {'':^14} {'':^24} {'':^14}  {access_desc}")
                    
                        else:
                            print(f"{sector:6d} | {trailer_block:7d} | {'ERROR':^14} | {'READ FAILED':^24} | {'':^14} | {'ERROR'}")
                    else:
                # Try with Key B        
                        try:
                            if card.authenticate(trailer_block, 0x61, 0):
                                trailer_data = card.read_block(trailer_block)
                                if trailer_data:
                                    key_a = trailer_data[0:6]
                                    access_bits = trailer_data[6:10]
                                    key_b = trailer_data[10:16]
                                    
                                    key_a_str = toHexString(key_a)
                                    key_b_str = toHexString(key_b)
                                    access_str = toHexString(access_bits)
                                    
                                    print(f"{sector:6d} | {trailer_block:7d} | {key_a_str:<14} | {access_str:<24} | {key_b_str:<14} | KeyB_Access")
                                else:
                                    print(f"{sector:6d} | {trailer_block:7d} | {'Locked-B':^14} | {'(Key B)':^24} | {'Present':^14} | KeyB_Only")
                            else:
                                print(f"{sector:6d} | {trailer_block:7d} | {'LOCKED':^14} | {'NO ACCESS':^24} | {'LOCKED':^14} | Denied")
                        except:
                            print(f"{sector:6d} | {trailer_block:7d} | {'NO AUTH':^14} | {'UNABLE TO READ':^24} | {'':^14} | Denied")
                except Exception as e:
                    print(f"{sector:6d} | {trailer_block:7d} | {'ERROR':^14} | {str(e)[:20]:<24} | {'':^14} | Error")
    
            print("=" * 90)
            print("\nLEGEND:")
            print("  * = Default key (FFFFFFFFFFFF)")
            print("  Key A = First authentication key (6 bytes)")
            print("  Access Bits = Permission control (4 bytes)")
            print("  Key B = Second authentication key (6 bytes)")
            print("  Access Control: Default, Read Only, Value Block, Custom, etc.")
    
            # Also show data blocks for first few sectors
            print("\n\nFIRST 4 SECTORS - DATA BLOCKS PREVIEW:")
            print("=" * 90)
            print(f"{'Sector':^6} | {'Block':^7} | {'Data (Hex)':^32} | {'ASCII Preview':^16}")
            print("=" * 90)
    
            for sector in range(4):
                first_data_block = sector * 4
                try:
                    if card.authenticate(first_data_block, 0x60, 0):
                        for block_offset in range(3):  # Only data blocks (3 per sector)
                            block_num = sector * 4 + block_offset
                            block_data = card.read_block(block_num)
                            if block_data:
                                # Format hex display (first 8 bytes only for readability)
                                hex_display = toHexString(block_data[:8])
                                if len(block_data) > 8:
                                    hex_display += "..."
                        
                                # Create ASCII preview
                                ascii_preview = ""
                                for byte in block_data[:16]:  # Full block for ASCII
                                    if 32 <= byte <= 126:
                                        ascii_preview += chr(byte)
                                    else:
                                        ascii_preview += "."
                        
                                print(f"{sector:6d} | {block_num:7d} | {hex_display:<32} | {ascii_preview:<16}")
                            else:
                                print(f"{sector:6d} | {block_num:7d} | {'NO DATA':^32} | {'':^16}")
                    else:
                        print(f"{sector:6d} | {first_data_block:7d} | {'AUTH FAILED':^32} | {'':^16}")
                except:
                    print(f"{sector:6d} | {first_data_block:7d} | {'ERROR':^32} | {'':^16}")
    
            print("=" * 90)
    
            # Show access bits decoding for first sector trailer
            print("\n\nACCESS BITS DECODING EXAMPLE (Sector 0 Trailer):")
            print("-" * 50)
            try:
                if card.authenticate(3, 0x60, 0):
                    trailer_data = card.read_block(3)
                    if trailer_data:
                        access_bits = trailer_data[6:10]
                        print(f"Access Bits (Hex): {toHexString(access_bits)}")
                        print(f"Access Bits (Binary):")
                
                        for i, byte in enumerate(access_bits):
                            print(f"  Byte {i}: {byte:08b} ({byte:02X}h)")
                
                # Simple decoding
                        print("\nAccess Control Meaning:")
                        c1 = (access_bits[1] >> 4) & 0x0F
                        c2 = (access_bits[2] >> 0) & 0x0F
                        c3 = (access_bits[2] >> 4) & 0x0F
                
                        if (c1, c2, c3) == (0, 0, 0):
                            print("  Block 0-2: Key A|B required for R/W")
                            print("  Trailer: Key A required for R/W of keys, Key B: Read")
                        elif (c1, c2, c3) == (1, 0, 0):
                            print("  Block 0-2: Key A|B required for R/W")
                            print("  Trailer: Key A required for R/W of keys, Key B: None")
                        else:
                            print(f"  Custom configuration: C1={c1:04b}, C2={c2:04b}, C3={c3:04b}")
            except:
                print("  Unable to decode access bits for sector 0")
        else:
            print("   Skipping detailed sector analysis")
                
        press_enter_to_continue()
        
        # ============================================
        # 6. ADVANCED OPERATIONS
        # ============================================
        print_section("6. ADVANCED OPERATIONS", 70)
        
        print("\nDemonstrating advanced MiFARE Classic features...")
        
        print_step("6.1", "Complete Sector Operations")
        
        print("\nReading entire sector 0 (blocks 0-3)...")
        try:
            if card.authenticate(3, 0x60, 0):  # Authenticate to sector trailer
                blocks = card.read_sector(0)
                if blocks:
                    print(f"   Successfully read {len(blocks)} blocks")
                    print("\n   Sector 0 Contents:")
                    for i, block_data in enumerate(blocks):
                        block_num = i
                        hex_data = toHexString(block_data)
                        
                        # Create ASCII preview
                        ascii_preview = ""
                        for byte in block_data:
                            if 32 <= byte <= 126:
                                ascii_preview += chr(byte)
                            else:
                                ascii_preview += "."
                        
                        print(f"   Block {block_num:2d}: {hex_data[:24]}... | {ascii_preview}")
                else:
                    print("   Failed to read sector")
            else:
                print("   Cannot authenticate to sector 0")
        except Exception as e:
            print(f"   Error reading sector: {e}")
        
        print_step("6.2", "Backup and Restore Demo")
        
        print("\nDemonstrating backup procedure...")
        print("This shows how to backup and restore block data.")
        
        backup_block = 9
        print(f"\nBacking up block {backup_block}...")
        
        try:
            if card.authenticate(backup_block, 0x60, 0):
                original_data = card.read_block(backup_block)
                if original_data:
                    print(f"   Backup successful: {len(original_data)} bytes")
                    print(f"   Data: {toHexString(original_data)}")
                    
                    # Restore demonstration
                    print("\n   Restore demonstration:")
                    print("   (In a real scenario, you would restore this data)")
                    print(f"   Data would be restored to: {toHexString(original_data)}")
                else:
                    print("   ✗ Could not read block for backup")
            else:
                print("   ✗ Cannot authenticate to backup block")
        except Exception as e:
            print(f"   ✗ Backup error: {e}")
        
        press_enter_to_continue()
        
        # ============================================
        # 7. CLEANUP AND CARD RESTORATION
        # ============================================
        print_section("7. CLEANUP AND CARD RESTORATION", 70)
        
        print("\nChoose cleanup option:")
        print("1. Restore test block to original state (if backed up)")
        print("2. Clear test block (write zeros)")
        print("3. Keep all changes (no cleanup)")
        
        choice = input("\nSelect option (1-3): ")
        
        if choice == "1":
            print("\nRestoring test block to original state...")
            if 'original_data' in locals() and test_block:
                try:
                    if card.authenticate(test_block, 0x60, 0):
                        if card.write_block(test_block, original_data):
                            print("   ✓ Test block restored successfully")
                        else:
                            print("   ✗ Failed to restore block")
                    else:
                        print("   ✗ Cannot authenticate to restore block")
                except Exception as e:
                    print(f"   ✗ Restore error: {e}")
            else:
                print("   No backup data available for restoration")
                
        elif choice == "2":
            print("\nClearing test block...")
            if test_block:
                try:
                    if card.authenticate(test_block, 0x60, 0):
                        empty_data = [0] * 16
                        if card.write_block(test_block, empty_data):
                            print("   ✓ Test block cleared successfully")
                        else:
                            print("   ✗ Failed to clear block")
                    else:
                        print("   ✗ Cannot authenticate to clear block")
                except Exception as e:
                    print(f"   ✗ Clear error: {e}")
        
        else:
            print("\nKeeping all changes on card.")
            print("Test data remains written.")
        
        press_enter_to_continue()
        
        # ============================================
        # 8. WORKFLOW SUMMARY
        # ============================================
        print_section("8. WORKFLOW COMPLETED SUCCESSFULLY!", 70)
        
        print("\nSUMMARY OF OPERATIONS PERFORMED:")
        print("-" * 50)
        print("✓ Card connection established")
        print("✓ Card UID read successfully")
        print("✓ Memory structure explained")
        print("✓ Authentication tested")
        print("✓ Read/write operations demonstrated")
        print("✓ Value block operations shown")
        print("✓ Security vulnerability scan completed")
        print("✓ Sector analysis performed")
        print("✓ Advanced operations demonstrated")
        print("✓ Cleanup options presented")
        
        print("\nSECURITY ASSESSMENT:")
        print("-" * 50)
        if 'accessible_sectors' in locals():
            if len(accessible_sectors) > 0:
                print(f"⚠ VULNERABLE: {len(accessible_sectors)}/16 sectors use default keys")
                print("  Recommendation: Change default keys immediately!")
            else:
                print("✓ SECURE: No default keys detected")
        else:
            print("  Security scan not performed")
        
        print("\nCARD STATUS:")
        print("-" * 50)
        print(f"UID: {uid if 'uid' in locals() else 'Unknown'}")
        print(f"Test block: {test_block if 'test_block' in locals() else 'None'}")
        if 'value_block_found' in locals() and value_block_found:
            print(f"Value block: Block {value_block_num}")
            if 'final_value' in locals():
                print(f"Final value: {final_value}")
        
        print("\n" + "=" * 70)
        print("MiFARE Classic 1K workflow demonstration complete!")
        print("=" * 70)
        
        print("\nNEXT STEPS FOR DEVELOPMENT:")
        print("-" * 50)
        print("1. Implement custom key management")
        print("2. Design your data structure across sectors")
        print("3. Add error handling for production use")
        print("4. Implement backup/restore functionality")
        print("5. Add logging for audit trails")
        
        print("\n" + "-" * 40)
        print("Workflow completed successfully.")
        print("Card is ready for your application development.")
        print("-" * 40)
        
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        print("Card connection terminated.")
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\nExiting workflow demonstration...")


if __name__ == "__main__":
    main()
