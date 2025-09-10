# StegCrypto

StegCrypto is a command-line tool that combines **encryption** and **steganography** to securely hide and retrieve data inside image files. It uses the **cryptography** library (Fernet symmetric encryption) and **stepic** (least significant bit steganography) to embed encrypted data into images without visibly altering them.

---

## Features
- Secure Encryption: Data is encrypted using `cryptography.fernet` before being hidden.
- Image Steganography: The encrypted data is embedded inside an image using **LSB (Least Significant Bit)** encoding via the `stepic` library.
- File Output: Saves both the steganographic image and the encryption key for later retrieval.
- Error Handling: Handles missing files and invalid keys gracefully.
- Command-Line Interface: Provides two subcommands — `hide` and `retrieve`.

---

## Requirements
Install Python packages:
```bash
pip install pillow stepic cryptography
```

---

## Installation
1. Clone or download this repository.
2. Navigate to the project folder:
   ```bash
   cd path/to/project
   ```
3. See available commands:
   ```bash
   python StegCrypto.py --help
   ```

---

## Usage

### Hide data in an Image
Encrypts the data and hides it inside the image.
```bash
python StegCrypto.py hide input.png "MyPassword" --output-path output.png --key-path secret.key
```
- `input.png` → original image file (container).
- `"MyPassword"` → data to hide.
- `--output-path output.png` → path for the stego image.
- `--key-path secret.key` → path to save the generated encryption key.

After running this, you will have:
- `output.png` → image with the hidden (encrypted) data.
- `secret.key` → key file needed for decryption.

### Retrieve data from an Image
Extracts and decrypts the hidden data.
```bash
python StegCrypto.py retrieve output.png --key-path secret.key
```
- `output.png` → image with the hidden (encrypted) data.
- `--key-path secret.key` → key file needed for decryption.

Example output:
```
Retrieved data: MyPassword
```

---

## Error Handling
- If the input image or key file does not exist, the script prints a clear error message.
- If decryption fails (wrong key or no hidden data), you will see:
  ```
  Error: Invalid key or no data found. Decryption failed.
  ```
- **Important (lossy formats):** Always use **lossless** formats (e.g., **PNG** or **BMP**) for both input and output images.
  - **Do not use** JPEG/JPG/WEBP for the stego image. These formats are typically lossy and will compress away the LSB changes, destroying the hidden data and causing decryption to fail.
- Avoid re-saving, resizing, or re-compressing the stego image (messengers and editors can recompress automatically).

---

## License
MIT
