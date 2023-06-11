import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging

logger = logging.getLogger()
logger.setLevel('INFO')


def gen_symmetric_key() -> str:
    """
    Функция генерирует ключ для симметричного шифрования
    :return: ключ 
    """
    key = os.urandom(16)
    logging.info(
        ' Сгенерирован ключ для симметричного шифрования')
    return key

def encrypt_symmetric(key: bytes, text: bytes) -> bytes:

    """
    Функция шифрует текст алгоритмом симметричного шифрования SEED
    :param text: текст, который шифруем
    :param key: ключ
    :return: зашифрованный текст
    """
    padder = padding.ANSIX923(128).padder()
    padded_text = padder.update(text) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_text) + encryptor.finalize()
    logging.info(
        ' Текст зашифрован алгоритмом симметричного шифрования SEED')
    return iv + cipher_text

def decrypt_symmetric(key: bytes, cipher_text: bytes):
    
    """
    Функция расшифровывает симметрично зашифрованный текст
    :param cipher_text: зашифрованный текст
    :param key: ключ
    :return: возвращает расшифрованный текст
    """
    cipher_text, iv = cipher_text[16:], cipher_text[:16]
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    text = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.ANSIX923(128).unpadder()
    unpadded_text = unpadder.update(text) + unpadder.finalize()
    logging.info(' Текст, зашифрованный алгоритмом симметричного шифрования SEED, расшифрован')
    return unpadded_text


