# advanced_uid
Advanced NFC UID Tool for Flipper Zero firmware 
A powerful NFC UID manipulation tool for Flipper Zero that allows you to emulate, increment, and fuzz NFC UIDs with advanced customization options.
🚀 Features
📱 Multiple NFC Technologies Support

Mifare Classic 1K - Industry standard proximity cards
Mifare Ultralight - Lightweight NFC tags
NTAG213/215/216 - NFC Forum Type 2 tags
FeliCa - Japanese contactless smart card system
ISO15693 - Vicinity cards

🔄 Three Operation Modes

Manual Mode - Increment UID manually with button press
Auto Mode - Automatic UID incrementation with configurable delay
Fuzzer Mode - Cycle through predefined UIDs then generate random ones

📁 File Loading Capability

Load NFC Files - Import UIDs from captured .nfc files
Auto-Detection - Automatically detect card type from file content
Seamless Integration - All modes work with loaded UIDs

⚙️ Advanced Configuration

Increment Step - Customize increment value (1-256)
Offset Position - Choose which part of UID to modify
Increment Length - Select how many characters to increment
Auto Delay - Configure automatic mode timing (100-10000ms)
Fuzzer Delay - Set fuzzer mode speed (100-10000ms)

🎯 Smart Features

Real-time Synchronization - Displayed UID always matches emulated UID
Scrollable Menus - Navigate through all options on small screen
Intelligent Truncation - Long filenames displayed elegantly
Vibration Feedback - Haptic feedback for user actions

📋 Requirements

Flipper Zero with updated firmware (only tested on Momentum yet)
Compatible Firmware:

Official Firmware
Unleashed Firmware
RogueMaster Firmware
Momentum Firmware
Other OFW-based firmwares



🛠️ Installation
Method 1: Build from Source

Clone this repository
bash git clone https://github.com/nocomp/advanced_uid.git
cd advanced-uid-tool

Copy to your Flipper firmware directory
bashcp -r advanced_uid /path/to/your/flipper-firmware/applications_user/

Build and flash
bash./fbt launch_app APPSRC=applications_user/advanced_uid


Method 2: FAP Installation

Download the latest .fap file from Releases
Copy the .fap file to your Flipper Zero's apps folder
Navigate to Apps → NFC → Advanced UID Tool

📖 Usage Guide
🎮 Basic Operation

Start the Application

Navigate to Apps → NFC → Advanced UID Tool
Select your desired NFC technology OR load an NFC file


Configure UID

Edit the UID manually character by character
Use ↑/↓ to change hex values (0-9, A-F)
Use ←/→ to move between positions


Adjust Settings

Configure increment parameters
Set timing for auto and fuzzer modes
Fine-tune operation to your needs


Choose Operation Mode

Manual: Press ↑ to increment UID
Auto: Automatic incrementation
Fuzzer: Cycle through predefined then random UIDs



🔧 Advanced Configuration
Increment Settings

Step: How much to add each increment (1, 2, 4, 8, 16...)
Offset: Starting position in UID string (0-based)
Length: Number of hex characters to modify (2, 4, 6, 8)

Example Configuration
UID: 04123456ABCD
Offset: 8 (start at 'A')
Length: 4 (modify 'ABCD')
Step: 1

Result: 04123456ABCD → 04123456ABCE → 04123456ABCF → ...
📁 Loading NFC Files

Select "Load NFC File" from main menu
Browse your saved NFC captures
Select the desired .nfc file
Automatic detection of card type and UID extraction
Continue with normal operation using loaded UID

🎯 Use Cases
🔍 Security Testing

Access Control Testing - Test sequential card ranges
RFID System Analysis - Analyze system responses to different UIDs
Vulnerability Research - Discover security weaknesses

🛠️ Development & Research

NFC Protocol Testing - Test reader compatibility
Range Testing - Find valid UID ranges
System Integration - Test NFC-enabled applications

🎓 Educational

Learning NFC - Understand UID structure
Security Education - Demonstrate RFID vulnerabilities
Hands-on Experience - Practical NFC experimentation

⚠️ Legal Disclaimer
This tool is intended for educational purposes, security research, and testing your own systems only.
🚨 IMPORTANT WARNINGS:

Only use on systems you own or have explicit permission to test
Unauthorized access to RFID/NFC systems may be illegal
Users are responsible for compliance with local laws and regulations
This tool should not be used for malicious purposes

I am not responsible for any misuse of this tool.
📸 Screenshots
