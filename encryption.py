# encryption.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from base64 import b64encode, b64decode

def generate_keypair():
    """
    Generate RSA key pair for encryption and decryption.
    Returns private key and public key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(message, public_key):
    """
    Encrypt a message using RSA public key.
    Returns encrypted message bytes.
    """
    try:
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return b64encode(encrypted_message).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_message(encrypted_message, private_key):
    """
    Decrypt an encrypted message using RSA private key.
    Returns decrypted message string.
    """
    try:
        decrypted_message = private_key.decrypt(
            b64decode(encrypted_message.encode()),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def load_public_key_from_pem(pem_data):
    """
    Load RSA public key from PEM-encoded data.
    Returns loaded public key object.
    """
    try:
        public_key = load_pem_public_key(pem_data, backend=default_backend())
        return public_key
    except Exception as e:
        print(f"Error loading public key: {e}")
        return None

def load_private_key_from_pem(pem_data, password=None):
    """
    Load RSA private key from PEM-encoded data.
    Returns loaded private key object.
    """
    try:
        if password:
            private_key = load_pem_private_key(pem_data, password=password.encode(), backend=default_backend())
        else:
            private_key = load_pem_private_key(pem_data, backend=default_backend())
        return private_key
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None
