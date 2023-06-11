import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
import random

logger = logging.getLogger()
logger.setLevel('INFO')


def gen_symmetric_key() -> str:

    keys = [i for i in range(5, 17, 1)]
    iv = os.urandom(8)
    len_key = random.randint(0, len(keys) - 1)
    key = os.urandom(keys[len_key])

    logging.info(
        ' Сгенерирован ключ для симметричного шифрования')
    return key

def encrypt_symmetric(key: bytes, text: bytes) -> bytes:

    padder = padding.ANSIX923(32).padder()
    padded_text = padder.update(text) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.CAST5(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_text) + encryptor.finalize()
    logging.info(
        ' Текст зашифрован алгоритмом симметричного шифрования CAST5')
    return iv + cipher_text

def dencrypt_symmetric(key: bytes, cipher_text: bytes):
    
    iv = os.urandom(8)
    cipher = Cipher(algorithms.CAST5(key), modes.CBC(iv))

    decryptor = cipher.decryptor()
    dc_text = decryptor.update(cipher_text) + decryptor.finalize()

    unpadder = padding.ANSIX923(32).unpadder()
    unpadded_text = unpadder.update(dc_text) + unpadder.finalize()

    logging.info(' Текст, зашифрованный алгоритмом симметричного шифрования CAST5, расшифрован')
    return unpadded_text


