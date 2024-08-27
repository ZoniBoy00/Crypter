# Crypter

Crypter is a versatile encryption tool that offers various cryptographic functions such as encryption, decryption, obfuscation, de-obfuscation, hashing, and password generation.

## Features

- Text encryption and decryption using Fernet encryption
- Text obfuscation and de-obfuscation using Base85 encoding
- Text hashing with different algorithms (MD5, SHA1, SHA256, SHA512)
- Secure password generation
- File loading and processing
- User-friendly graphical interface

## Installation

### Option 1: Executable File (Windows only)

1. Download the latest `Crypter.exe` from the [releases page](https://github.com/ZoniBoy00/Crypter/releases).
2. Double-click the downloaded file to run the application.

### Option 2: Python Source Code

1. Ensure you have Python 3.7 or newer installed.
2. Clone this repository:
git clone https://github.com/ZoniBoy00/Crypter.git cd Crypter

3. (Recommended) Create and activate a virtual environment:
python -m venv venv source venv/bin/activate # On Linux and macOS venv\Scripts\activate # On Windows

4. Install the required libraries:
pip install -r requirements.txt

5. Launch the application:
python crypto_app.py


## Usage Instructions

1. Start the application by either double-clicking the exe file or running the Python script.
2. Choose the desired function from the tabs:
- **Encrypt**: Encrypt text using Fernet encryption
- **Decrypt**: Decrypt Fernet-encrypted text
- **Obfuscate**: Obfuscate text using Base85 encoding
- **Deobfuscate**: De-obfuscate Base85-encoded text
- **Hash**: Create a hash of the text
- **Password**: Generate a secure password
3. Enter the required information and press the action button.
4. Copy the result to the clipboard if needed.

## Security Notes

- Store encryption keys securely. Do not share them with anyone.
- Use strong passwords and unique encryption keys for each encrypted message.
- This application is intended for educational and demonstration purposes. Professional encryption solutions are recommended for critical data.

## Troubleshooting

- If you encounter issues with the exe file, try running the application from the Python source code.
- Ensure you have the necessary permissions to read and write files in the application folder.
- If the application doesn't start, verify that all required libraries are correctly installed.

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/ZoniBoy00/Crypter/blob/main/LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgements

- [cryptography](https://github.com/pyca/cryptography) - For Fernet encryption and hashing algorithms
- [tkinter](https://docs.python.org/3/library/tkinter.html) - For the GUI framework
- [pyperclip](https://github.com/asweigart/pyperclip) - For clipboard operations

To complete the GitHub repository, you should also include the following files:

requirements.txt: This file should list all the Python packages required to run your application. You can create it by running:

pip freeze > requirements.txt
The contents might look something like this:

cryptography

pyperclip
