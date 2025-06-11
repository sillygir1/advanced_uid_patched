# Advanced UID Pro v2.0

This repo contains the patched version of original application. Patch removes the license check completely. Read how i did it one paragraph lower!

As the MIT license states, i can do whatever the hell i want with this software. Also, please don't create issues in this fork, i will not be able to fix this mess. The only person who can help you with problems with this app is it's original creator.

Back to the important things. What did i do to save your script kiddie's wallet 10 euros? Actually, there were 2 versions of the patch. First one involved patching the return value of `verify_license_code` function, which worked, but it needed a dummy license file with a dummy key. Imagine if you needed to spend extra half a minute to put that into your flipper? Unthinkable. So i spend like an extra couple of hours (i'm new to this patching stuff) figuring out how to make scriptkiddying easier for y'all. Behold, my second best reverse-engineering project:
- As we start going through the disassembly of the main function (keep in mind, it's not an actual code, just the ghidra's interpretation of the disassembly), there's a piece of code that starts with:
```c
  furi_record_open("storage");
  uVar4 = file_stream_alloc();
  iVar5 = file_stream_open(uVar4,"/ext/apps_data/advanced_uid_pro/license.txt",1);
```
- There are some interesting things after it too, let's check them.
  ```c
      iVar5 = verify_license_code(local_7c,__dest_00);
      if (iVar5 == 0) {
        pcVar3 = "Invalid License - Demo Mode Active";
        __dest[0x8c] = '\0';
        __dest[200] = '\0';
      }
      else {
        pcVar3 = "Pro Mode - All Features Unlocked";
        __dest[0x8c] = '\x01';
        __dest[200] = '\x01';
      }
      strcpy(local_80,pcVar3);
  ```
- What do we see, a piece of code that sets flags if the license code is valid? Well duh, we just need to take these changes and apply them **instead** of the license check. Time to do some instruction patching. **Be careful not to change the total file size, as it can and will break everything.** We will replace the bytes, instead of adding new ones. For that, you need a hex editor. Also, i used ghidra 11.0 for decompilation of the `.fap` file. 
- Returning to the file opening section. Forget it. We're rewrting it. What do we need? Set the flags (2 of them) and jump to the end of the license check section.
- Let's take the first instruction for that function call, the one that puts format string address to the `r2` register. What do we do with it? Replace it with loading `0x1` into the `r0` register. Why `r0`? Idk, seems like a safe bet, as it's usually used for a return value i think? So, we replace `69 4a` right after the label with `01 20`, which stands for `movs r0, #0x1`, putting an immediate value `0x1` in the `r0` register. Wel'll need it later.
- To the next instruction. We replace next 2 16-bit instructions with a 4-byte one. `84 f8 8c 00`, which stands for `strb.w r0,[r4,#0x8c]`. We put that `0x1` value into a memory address, calculated by adding `0x8c` to the struct address, stored in `r4`.
- Now we need to replace next 2 instructions with another long one. `84 f8 c8 00`, which means `strb.w r0,[r4,#0xc8]`, same thing as the previous one, but this time for another field of the struct.
- To finish this off, we need to get the rest of the license section out of our way. How? Branching, of course. We once again rewrite next instruction, but this time with a short one. `68 e0`, meaning `b LAB_00014fdc`. Unconditional branch to the `LAB_00014fdc` label. Why `LAB_00014fdc`? This is the place where the section of the code right after license check is. It's conveniently labeled because there's an `if`/`else` statement right before it.
- That's it! We have successfully made the app completely free to use, enjoy your script kiddy stuff if you're into it, i don't really care. I just wanted to feel like a smartass (i also condemn paid stuff in the open-source community, but that's unimportant).


Original README.md is preserved below:
---
Advanced UID Pro v2.0
The Ultimate NFC/RFID UID Manipulation Tool for Flipper Zero
![Screenshot-20250609-172751](https://github.com/user-attachments/assets/19de737e-cc20-4fff-b462-925ff2fc7671)
![Screenshot-20250609-172821](https://github.com/user-attachments/assets/5edd2483-d11f-4839-ba5b-393cf9158122)
![Screenshot-20250609-172810](https://github.com/user-attachments/assets/4e907a2b-0c99-471b-8330-bc98992eb440)
Professional-grade NFC/RFID UID manipulation suite with support for 20+ technologies, advanced fuzzing capabilities, and enterprise-level features.


✨ Key Features
🆓 Free Version Features

2 NFC Technologies: MIFARE Classic 1K & MIFARE Ultralight
Manual UID Manipulation: Edit UIDs byte by byte
Basic Emulation: Standard NFC card emulation
Demo Mode: Limited to 100 operations
Clean Interface: Professional single-tile navigation

🔥 PRO Version Features

20+ NFC Technologies: Complete industry coverage
Advanced Fuzzing: Smart UID generation with predefined and random modes
Auto-Increment Mode: Automated UID cycling with customizable delays
Reader Detection: Analyze and adapt to any NFC reader
File Import: Load .nfc files directly
Unlimited Operations: No restrictions
Priority Support: Direct access to developer


🏆 Why Upgrade to PRO?
💼 Professional Use Cases

Security Testing: Comprehensive penetration testing toolkit
Access Control Analysis: Test building security systems
Transport Research: Analyze public transport card systems
Academic Research: Complete NFC protocol investigation
Enterprise Deployment: Bulk operations without limitations

💰 Exceptional Value

20+ Premium Technologies worth $500+ if purchased separately
Lifetime Updates with new technologies as they emerge
Professional Support from experienced developers
Custom Feature Requests for enterprise clients

📧 Get Your PRO License
Contact: nocomp@gmail.com

⚡ Instant Activation - Delivered within 24 hours
🔒 Secure License System - Tied to your Flipper's unique ID
🎯 Competitive Pricing - Starting from $29.99


📡 Supported NFC Technologies
🆓 Free Technologies (2)
TechnologyUID SizeMemoryApplicationsMIFARE Classic 1K4 bytes1024 bytesAccess cards, hotel keysMIFARE Ultralight7 bytes96 bytesTransport tickets, loyalty cards
🔥 PRO Technologies (18)
MIFARE Family
TechnologyUID SizeMemoryApplicationsMIFARE Classic 4K4 bytes4096 bytesHigh-security access cardsMIFARE Classic Mini4 bytes320 bytesCompact applicationsMIFARE Plus S/X4 bytes2K/4KNext-gen secure cardsMIFARE DESFire EV17 bytes2K-8KBanking, secure accessMIFARE DESFire EV27 bytes2K-8KAdvanced encryptionMIFARE DESFire EV37 bytes2K-8KLatest generationMIFARE DESFire Light7 bytes640 bytesIoT applications
NTAG Family
TechnologyUID SizeMemoryApplicationsNTAG2107 bytes64 bytesBasic NFC tagsNTAG2137 bytes180 bytesSmartphone interactionsNTAG2157 bytes540 bytesAmiibo compatibleNTAG2167 bytes928 bytesAdvanced NFC applicationsNTAG424 DNA7 bytes416 bytesSecure brand protection
Industry Standards
TechnologyUID SizeProtocolApplicationsFeliCa8 bytesSonyJapanese transport (Suica, Pasmo)ISO156938 bytesLong-rangeIndustrial trackingISO14443-4 Type A4 bytesGenericBanking, governmentISO14443-4 Type B4 bytesGenericEuropean bankingTopaz (Type 1)4 bytesBroadcomLegacy NFC systemsCalypso4 bytesTransportEuropean public transport

🛠️ Advanced Configuration Options
⚙️ UID Manipulation Settings

Increment Step: 1-256 (customize counting speed)
Offset Position: Target specific UID bytes
Increment Length: 2-8 bytes modification range
Format Validation: Automatic UID format checking

⏱️ Timing Controls

Auto Delay: 100ms - 10s (automated cycling speed)
Fuzzer Delay: 100ms - 10s (fuzzing speed)
Detection Timeout: Configurable reader detection time

🎲 Fuzzing Modes

Predefined UIDs: Database of real-world UIDs
Random Generation: Cryptographically secure randomization
Smart Prefixes: Technology-appropriate UID formats
Sequential Scanning: Systematic UID space exploration

📁 File Operations

.nfc Import: Load existing Flipper NFC files
Auto-Detection: Automatic technology identification
Batch Processing: Multiple file operations
Export Capability: Save generated UIDs


📱 User Interface Features
🎨 Modern Design

Single-Tile View: Clean, focused interface
Triangle Navigation: Intuitive left/right browsing
Status Indicators: Clear visual feedback
Bordered Tiles: Professional appearance

🔍 Visual Feedback

Technology Icons: Instant identification
License Status: Clear FREE/PRO/LOCKED indicators
Operation Counter: Track demo usage
Real-time Updates: Live UID changes

🎮 Controls

OK Button: Select/Confirm actions
Long Press: Access license entry
Directional Pad: Navigate and edit
Back Button: Return to previous screen


🚀 Installation Guide
📋 Prerequisites

Flipper Zero with updated firmware
SD card with available space
Git or direct download capability

💻 Installation Methods

FAP Installation
bash# Download pre-compiled FAP
wget https://releases.com/advanced_uid_pro.fap

# Copy to SD card
cp advanced_uid_pro.fap /path/to/sd/apps/NFC/
✅ Verification

Navigate to Apps → NFC → Advanced UID Pro
Launch application
Verify demo mode is active
Test with MIFARE Classic 1K


📖 Usage Guide
🆓 Free Version Workflow

Select Technology: Choose Classic 1K or Ultralight
Edit UID: Modify bytes using directional controls
Configure Settings: Adjust increment parameters
Start Emulation: Begin NFC emulation
Manual Control: Use UP button to increment

🔥 PRO Version Workflow

Purchase License: Contact nocomp@gmail.com
Enter License: Long press OK → Enter 16-character code
Access All Technologies: Browse 20+ options
Advanced Features:

Reader Detection: Analyze target systems
Auto Mode: Automated UID cycling
Fuzzer Mode: Intelligent UID generation
File Import: Load existing .nfc files



🎯 Advanced Operations
Auto-Increment Mode
1. Select technology → Edit UID → Settings
2. Configure: Step=1, Offset=4, Length=4, Delay=1000ms
3. Navigate to Auto Mode
4. Press OK to start automated cycling
Fuzzer Mode
1. Select technology → Settings → Fuzzer Mode
2. Choose: Predefined or Random
3. Set delay (500ms recommended)
4. Press OK to start fuzzing
5. Use UP/DOWN to control manually
Reader Detection
1. Select "Detect" tile (PRO only)
2. Position Flipper near target reader
3. Press OK to start detection
4. System analyzes ATQA/SAK responses
5. Automatic technology recommendation

🔧 Technical Specifications
📊 Performance Metrics

UID Generation Speed: Up to 1000 UIDs/minute
Memory Usage: < 32KB RAM
Storage Requirements: < 1MB flash
Battery Impact: Optimized for long sessions

🔌 Compatibility

Firmware: Compatible with latest official/custom firmware
Hardware: All Flipper Zero revisions
NFC Protocols: ISO14443 A/B, ISO15693, FeliCa
File Formats: Native .nfc, custom exports

🛡️ Security Features

License Validation: Cryptographic verification
Secure Storage: Encrypted license storage
Anti-Piracy: Hardware-tied licensing
Privacy Protection: No telemetry or tracking


💎 Licensing & Pricing
🆓 Free Version

Technologies: 2 basic protocols
Operations: 100 demonstration cycles
Features: Core UID manipulation
Support: Community forums

🔥 PRO License - 10 €
What You Get:

✅ 20+ NFC Technologies - Complete industry coverage
✅ Unlimited Operations - No restrictions or counters
✅ Advanced Fuzzing - Professional security testing
✅ Reader Detection - Adaptive technology analysis
✅ File Import/Export - Complete workflow integration
✅ Priority Support - Direct developer access
✅ Lifetime Updates - New technologies included
✅ Commercial License - Business use permitted

Enterprise Pricing Available - Volume discounts for 10+ licenses
🔒 License Security

Hardware Binding: Tied to your Flipper's unique serial
Instant Activation: Delivered within 24 hours
Secure Validation: Cryptographic verification system
Transfer Protection: Licensed to your device permanently


🔒 Responsible Use
This tool is designed for:

✅ Security Research: Authorized penetration testing
✅ Educational Purposes: Learning NFC protocols
✅ Personal Projects: Legitimate technical exploration
✅ Professional Testing: Authorized security assessments

⚠️ Important Notice

Authorization Required: Only test systems you own or have explicit permission to test
Legal Compliance: Ensure compliance with local laws and regulations
Ethical Use: Use responsibly and respect others' privacy and security
No Warranty: Provided as-is for educational and research purposes

📜 License Terms

Free Version: Personal use only, no commercial applications
PRO Version: Includes commercial use rights with proper licensing
Redistribution: Prohibited without explicit written permission
Reverse Engineering: License validation systems are protected


🌟 Why Choose Advanced UID Pro?
🎯 Industry Leading

Most Comprehensive: 20+ technologies in one tool
Professional Grade: Used by security researchers worldwide
Actively Maintained: Regular updates and new features
Expert Developed: Created by NFC/RFID specialists

💡 Innovation

Smart Fuzzing: Intelligent UID generation algorithms
Adaptive Detection: Learn from any NFC reader
User-Centric Design: Optimized for real-world workflows
Performance Optimized: Fast, efficient, battery-friendly

🤝 Community

Active Development: Continuous improvement based on user feedback
Expert Support: Direct access to knowledgeable developers
Documentation: Comprehensive guides and examples
Future-Proof: Investment in long-term NFC technology support


📈 Roadmap
🚀 Coming Soon

Additional Protocols: New NFC technologies as they emerge
Enhanced UI: Advanced visualization and reporting
Scripting Support: Automation and batch operations
Cloud Integration: Remote management and updates

💭 Feature Requests
Have an idea? Contact us at nocomp@gmail.com or open a GitHub issue.

🙏 Credits
Developed with ❤️ by the Advanced UID Pro Team
Special thanks to:

Flipper Zero community for inspiration and feedback
NFC/RFID researchers for protocol documentation
Security professionals for real-world testing scenarios
Beta testers for quality assurance and validation


📧 Get Started Today!
Ready to unlock the full potential of NFC manipulation?
🔥 Upgrade to PRO: nocomp@gmail.com
Transform your Flipper Zero into the ultimate NFC research and security testing platform. Join hundreds of security professionals, researchers, and enthusiasts who trust Advanced UID Pro for their NFC needs.
