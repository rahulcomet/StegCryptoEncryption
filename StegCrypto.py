import argparse
from pathlib import Path
from PIL import Image
import stepic
from cryptography.fernet import Fernet, InvalidToken

# Function to load the encryption key from a file
def load_key(key_path: Path) -> bytes:
    """
    Load the encryption key from a file.

    Args:
    key_path (Path): Path to the key file.
    """
    return key_path.read_bytes()

def hide_password(image_path: Path, password: str, output_path: Path, key_path: Path):
    """
    Hide an encrypted password in an image.

    Args:
    image_path (Path): Path to the input image.
    password (str): The password to hide.
    output_path (Path): Path to save the output image with the hidden password.
    key_path (Path): Path to save the new encryption key.
    """
    # Ensure output format is approprite (lossless)
    if output_path.suffix.lower() in [".jpg", ".jpeg", ".webp"]:
        raise ValueError(
            f"Unsupported format {output_path.suffix}. "
            "Use a lossless format like PNG or BMP to preserve hidden data."
        )
    
    try:
        # Generate a key for encryption
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)

        # Encrypt the password
        encrypted_password = cipher_suite.encrypt(password.encode('utf-8'))
        
        # Open the image
        image = Image.open(image_path)

        # Hide the encrypted password in the image
        encoded_image = stepic.encode(image, encrypted_password)
        
        # Save the new image with the hidden password
        encoded_image.save(output_path)

        # Save the key to a file
        key_path.write_bytes(key)

        print(f"Password hidden in image and saved as {output_path}")
        print(f"Encryption key saved to {key_path}")
    except FileNotFoundError:
        print(f"Error: Input image not found at {image_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

def retrieve_password(image_path: Path, key_path: Path):
    """
    Retrieve and decrypt a hidden password from an image.

    Args:
    image_path (Path): Path to the image containing the hidden password.
    key_path (Path): Path to the encryption key file.

    Returns:
    str: The retrieved and decrypted password, or None on failure.
    """
    try:
        # Load the key
        key = load_key(key_path)
        cipher_suite = Fernet(key)

        # Extract the hidden data
        image = Image.open(image_path)
        hidden_data = stepic.decode(image)
        
        # Decrypt the password
        decrypted_password = cipher_suite.decrypt(hidden_data).decode('utf-8')
        return decrypted_password
    except FileNotFoundError as e:
        print(f"Error: File not found - {e.filename}")
        return None
    except InvalidToken:
        print("Error: Invalid key or no data found. Decryption failed.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

if __name__ == "__main__":
    USAGE_EXAMPLES = """
Examples:
  Hide a password in an image:
    python StegCrypto.py hide input.png "myS3cret!" --output-path out.png --key-path secret.key

  Retrieve a password from an image:
    python StegCrypto.py retrieve out.png --key-path secret.key
"""
    # Create an ArgumentParser object with a description of the script
    parser = argparse.ArgumentParser(
        description="Hide or retrieve a password in an image using steganography and encryption.",
        epilog=USAGE_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Available modes")

    # Create the parser for the "hide" command
    parser_hide = subparsers.add_parser("hide", help="Hide a password in an image")
    parser_hide.add_argument("image_path", type=Path, help="Path to the input image")
    parser_hide.add_argument("password", help="Password to hide")
    parser_hide.add_argument("--output-path", type=Path, required=True, help="Path to save the output image")
    parser_hide.add_argument("--key-path", type=Path, required=True, help="Path to save the new encryption key")

    # Create the parser for the "retrieve" command
    parser_retrieve = subparsers.add_parser("retrieve", help="Retrieve a password from an image")
    parser_retrieve.add_argument("image_path", type=Path, help="Path to the image containing the hidden password")
    parser_retrieve.add_argument("--key-path", type=Path, required=True, help="Path to the encryption key file")

    # Parse the command-line arguments
    args = parser.parse_args()

    # Perform the appropriate action based on the mode
    if args.mode == "hide":
        hide_password(args.image_path, args.password, args.output_path, args.key_path)
    elif args.mode == "retrieve":
        password = retrieve_password(args.image_path, args.key_path)
        if password:
            print(f"Retrieved password: {password}")
        else:
            print("Failed to retrieve the password.")
