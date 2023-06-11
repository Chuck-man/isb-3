import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import logging

logger = logging.getLogger()
logger.setLevel('INFO')

def gen_asymmetric_key() -> tuple:

    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()
    logging.info(' Сгенерированы ключи асимметричного шифрования')
    return private_key, public_key

def encrypt_asymmetric(public_key: bytes, text: bytes) -> bytes:

    encrypted_text = public_key.encrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                           algorithm=hashes.SHA256(), label=None))
    logging.info(' Текст зашифрован алгоритмом асимметричного шифрования')
    return encrypted_text

def decrypt_asymmetric(private_key, text: bytes) -> bytes:

    decrypted_text = private_key.decrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                            algorithm=hashes.SHA256(), label=None))
    logging.info(' Текст, зашифрованный алгоритмом асимметричного шифрования, расшифрован')
    return decrypted_text
    
    
    

