import logging
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger()
logger.setLevel("INFO")


"""
def symmetric_key_generation() -> bytes:
    
    Функция генерирует ключ для симметричного шифрования
    :return: ключ 
    
    key = os.urandom(16)
    logging.info("Symmetric key successfully generated!")
    return key


def symmetric_encryption(key: bytes, text: bytes) -> bytes:
    
    Функция шифрует текст алгоритмом симметричного шифрования SEED
    :param text: текст, который шифруем
    :param key: ключ
    :return: зашифрованный текст
    
    padder = padding.ANSIX923(128).padder()
    padded_text = padder.update(text) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_text) + encryptor.finalize()
    logging.info("Symmetric encryption was successful!")
    return iv + cipher_text


def symmetric_decryption(key: bytes, cipher_text: bytes) -> bytes:
    
    Функция расшифровывает симметрично зашифрованный текст
    :param cipher_text: зашифрованный текст
    :param key: ключ
    :return: возвращает расшифрованный текст
    
    iv = cipher_text[:16]
    cipher_text = cipher_text[16:]
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    text = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.ANSIX923(128).unpadder()
    result = unpadder.update(text) + unpadder.finalize()
    logging.info("Symmetric decryption was successful!")
    return result
"""

class SymmetricAlgorithm:
    def __init__(self, settings: dict) -> None:
        """
        Инициализация симметричного шифрования
        settings (dict): настройки, содержащие пути к файлам
        """
        self.settings = settings
        logging.info('Настройки по умолчанию загружены')
    
    def symmetric_key_generation(self) -> bytes:
        """
        Функция генерирует ключ для симметричного шифрования
        :return: ключ 
        """
        key = os.urandom(16)
        logging.info("Symmetric key successfully generated!")
        return key
    
    def symmetric_encryption(self, key: bytes, text: str, encrypt_text: str) -> bytes:
        """
        Функция шифрует текст алгоритмом симметричного шифрования SEED
        :param text: текст, который шифруем
        :param key: ключ
        :return: зашифрованный текст
        """
        try:
            with open(text, 'rb') as text_file:
                text = text_file.read()
            logging.info(
                f' Encrypted message write to file: {text}')
        except OSError as err:
            logging.warning(f' Encrypted message was not write\nError:{err}')

        padder = padding.ANSIX923(128).padder()
        padded_text = padder.update(text) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_text) + encryptor.finalize()
        logging.info("Symmetric encryption was successful!")
        cipher_data = iv + cipher_text

        try:
            with open(encrypt_text, 'wb') as f:
                f.write(cipher_data)
            logging.info(
                f' Encrypted message write to file: {encrypt_text}')
        except OSError as err:
            logging.warning(f' Encrypted message was not write\nError:{err}')
    
    def symmetric_decryption(self, key: bytes, cipher_text: str, decrypt_text: str) -> bytes:
        """
        Функция расшифровывает симметрично зашифрованный текст
        :param cipher_text: зашифрованный текст
        :param key: ключ
        :return: возвращает расшифрованный текст
        """
        try:
            with open(cipher_text, "rb") as text_file:
                message = text_file.read()
            logging.info(f"Key was successfully written to file {cipher_text}!")
        except OSError as err:
            logging.warning(f"Key was not written to file {cipher_text}\n{err}!")

        iv = message[:16]
        message = message[16:]
        cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        text = decryptor.update(message) + decryptor.finalize()
        unpadder = padding.ANSIX923(128).unpadder()
        result = unpadder.update(text) + unpadder.finalize()
        logging.info("Symmetric decryption was successful!")
        
        try:
            with open(decrypt_text, "wb") as text_file:
                text_file.write(result)
            logging.info(f"Key was successfully written to file {decrypt_text}!")
        except OSError as err:
            logging.warning(f"Key was not written to file {decrypt_text}\n{err}!")
    
    def writing_symmetric_key(self, key: bytes, file_name: str) -> None:
        """
        Функция, которая записывает ключ в виде байтов
        :key (bytes): симметричный ключ
        :file_name (str): название .txt файла
        """
        try:
            with open(file_name, "wb") as text_file:
                text_file.write(key)
            logging.info(f"Key was successfully written to file {file_name}!")
        except OSError as err:
            logging.warning(f"Key was not written to file {file_name}\n{err}!")

    def reading_symmetric_key(self, file_name: str) -> None:
        """
        Функция, которая считывает ключ в режиме "rb"
        :file_name (str): путь .txt файлу.
        returns: bytes: текст в виде байтов
        """
        try:
            with open(file_name, "rb") as text_file:
                key = text_file.read()
            logging.info(f"Key was successfully read from file {file_name}!")
        except OSError as err:
            logging.warning(f"Key was not read from file {file_name}\n{err}!")
        return key