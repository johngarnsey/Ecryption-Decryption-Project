# Folder Encryption and Decryption Application

## Overview
This project is a comprehensive file encryption and decryption application developed as part of a master's program in cybersecurity. The application utilizes the GCM (Galois/Counter Mode) algorithm for secure encryption and decryption of files and folders. The project employs Python and Tkinter for GUI development, providing a user-friendly interface for managing encrypted data.

## Technologies Used
- **Python**: Primary language for encryption/decryption functionalities.
- **Tkinter**: Library for creating GUI applications.
- **GCM**: Authenticated encryption algorithm.

## Features

### Encryption:
- Implemented file encryption using GCM.
- Secure key generation based on user-provided passwords.
- Encrypted files stored in specified output folders.
- User feedback during the encryption process.

### Decryption:
- Developed file decryption to reverse the encryption process.
- Utilized user passwords and encryption levels to generate decryption keys.
- Successfully decrypted files and restored them to their original state.
- Implemented error handling for incorrect passwords or missing encryption nonces.
- Provided informative messages during the decryption process.

### Graphical User Interface (GUI):
- Created a user-friendly GUI using Tkinter.
- Integrated encryption and decryption functionalities into the GUI.
- Allowed users to select files and folders for encryption/decryption.
- Displayed relevant information during the encryption/decryption process.

## Current Challenges
- **Nonce Management**: Difficulties in managing/retrieving encryption nonces during decryption.
- **Error Handling**: Limited error handling causing unexpected exceptions and unclear messages.
- **Interface Improvements**: Need for progress indicators, better visual feedback, and intuitive user experience.

## Future Objectives
- Improve nonce management.
- Refine error handling mechanisms.
- Enhance folder decryption functionality.
- Refine user experience and interface.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Encryption-Decryption-Project.git
   cd Encryption-Decryption-Project
   
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt

3. Run the application
   ```bash
   python GUI.py

## Usage

### Encrypting a Folder
1. Select the folder you want to encrypt.
2. Choose the desired encryption level (AES-128, AES-192, or AES-256).
3. Enter a password.
4. Click the "Encrypt Folder" button.

### Decrypting a Folder
1. Select the encrypted folder (with `.enc` extension).
2. Enter the password used during encryption.
3. Click the "Decrypt Folder" button.

## Context Menu Integration
The application can be integrated into the Windows context menu for easy access. A PowerShell script (`create_shortcut.ps1`) is provided to create a shortcut in the Windows SendTo menu, allowing users to encrypt or decrypt files and folders directly from the right-click menu.

## Contributing
Contributions are welcome! Please fork the repository and create a pull request with your changes. Ensure your code follows the project's coding standards and includes appropriate tests.

