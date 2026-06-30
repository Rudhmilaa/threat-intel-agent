import base64
import datetime
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def json_converter(o):
    """
    Format datetime objects in dictionaries to ISO format strings for JSON strings.

    :param o: object
    :return: ISO formatted datetime string
    :rtype: str
    """
    if isinstance(o, datetime.datetime):
        return o.isoformat()


def generate_keypair():
    """
    Generates an RSA SSH authentication keypair for use with AuthKey records.
    :return: (SSH public key, SSH private key)
    :rtype: tuple
    """
    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption())
    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )
    return public_key, private_key


def encrypt_data(passphrase, salt, data):
    """
    Encrypt data with Fernet symmetric encryption using passphrase and salt.
    Used for encrypting SSH authentication keys.

    :param passphrase: Fernet encryption passphrase
    :type passphrase: str
    :param salt: Fernet encryption salt
    :type salt: str
    :param data: data to encrypt
    :type data: str
    :return: encrypted data
    :rtype: str
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase))
    f = Fernet(key)
    token = f.encrypt(data)
    return token


def decrypt_data(passphrase, salt, data):
    """
    Decrypt data encrypted with Fernet symmetric encryption using passphrase and salt.
    Used for decrypting SSH authentication keys.

    :param passphrase: Fernet decryption passphrase
    :type passphrase: str
    :param salt: Fernet decryption salt
    :type salt: str
    :param data: data to decrypt
    :type data: str
    :return: decrypted data
    :rtype: str
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase))
    f = Fernet(key)
    token = f.decrypt(data)
    return token
